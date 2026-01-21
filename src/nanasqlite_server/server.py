import asyncio
import logging
import secrets
import time
import functools
import signal
import sys
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict
from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived
from nanasqlite import NanaSQLite
from nanasqlite.exceptions import NanaSQLiteError
from . import protocol
from .accounts import AccountManager
import argparse
import os

# 設定
PUBLIC_KEY_PATH = "nana_public.pub"
MAX_FAILED_ATTEMPTS = 3
BAN_DURATION = 900  # 15分 (秒)
MAX_BAN_LIST_SIZE = 10000 # メモリ枯渇攻撃対策

# DoS対策設定
MAX_STREAM_BUFFER_SIZE = 10 * 1024 * 1024  # 10MB (単一ストリーム)
MAX_TOTAL_BUFFER_SIZE = 50 * 1024 * 1024   # 50MB (1接続あたり合計)
MAX_CONCURRENT_STREAMS = 50                 # 1接続あたりの最大同時ストリーム数

# BAN・失敗回数管理
failed_attempts: dict[str, int] = {}  # {ip: count} (defaultdictから変更してサイズ管理を容易に)
ban_list: dict[str, float] = {}  # {ip: unban_time}

# スレッドプールエグゼキューター (書き込み用) - プロセス終了時に適切に片付けられるように
_executor = None
# GC対策: 強参照を保持するためのグローバルセット
_active_tasks = set()
_server = None

def get_executor():
    """共有スレッドプールエグゼキューターを取得 (遅延初期化)"""
    global _executor
    if _executor is None:
        # SQLiteのブロッキングを防ぐため、スレッド数を少し多めに確保
        _executor = ThreadPoolExecutor(
            max_workers=10,
            thread_name_prefix="nanasqlite_worker"
        )
    return _executor

# 禁止メソッド一覧 (ブラックリスト)
# NanaSQLiteの更新に自動対応しつつ、危険なメソッドを制限する
FORBIDDEN_METHODS = {
    "__init__", "close", "vacuum", "pragma", "execute", "execute_many",
    "query", "sql_insert", "sql_update", "sql_delete", "transaction",
    "begin_transaction", "commit", "rollback", "open", "connect",
    "get_model", "set_model", "load_all", "refresh"
}

# ホワイトリスト形式ではなく、全DB操作をexecutorで実行するように変更するため
# 旧来のWRITE_METHODSは削除

def is_banned(ip):
    """IPがBANされているか確認し、期限切れのBANを掃除する"""
    # テスト時など、BAN機能を無効化する場合
    if os.environ.get("NANASQLITE_DISABLE_BAN"):
        return False

    now = time.time()

    # BANリストのクリーンアップ (期限切れのものを削除)
    expired_bans = [addr for addr, expire in ban_list.items() if now >= expire]
    for addr in expired_bans:
        del ban_list[addr]
        if addr in failed_attempts:
            del failed_attempts[addr]

    if ip in ban_list:
        return True

    return False

def record_failed_attempt(ip):
    """失敗回数を記録し、必要に応じてBANする"""
    # テスト時など、BAN機能を無効化する場合
    if os.environ.get("NANASQLITE_DISABLE_BAN"):
        # ログには残すがBANはしない
        print(f"[DEBUG] Failed attempt from {ip} (BAN disabled)")
        return False

    # メモリ枯渇対策: 辞書が大きくなりすぎたら古いエントリーを削除するか制限する
    if len(failed_attempts) > MAX_BAN_LIST_SIZE:
        # 簡易的なクリーンアップ: 全てクリアして再開 (DoS対策としての最低限の防衛)
        failed_attempts.clear()

    failed_attempts[ip] = failed_attempts.get(ip, 0) + 1

    if failed_attempts[ip] >= MAX_FAILED_ATTEMPTS:
        if len(ban_list) < MAX_BAN_LIST_SIZE:
            ban_list[ip] = time.time() + BAN_DURATION
            print(f"IP {ip} has been BANNED for {BAN_DURATION}s")
        return True
    return False


# 共有DBインスタンス (bulk_load=True でメモリに全データをロード)
_db_path = "server_db.sqlite"
_shared_db = None

def get_shared_db():
    """共有DBインスタンスを取得 (遅延初期化)"""
    global _shared_db
    if _shared_db is None:
        _shared_db = NanaSQLite(_db_path, bulk_load=True)
    return _shared_db


class NanaRpcProtocol(QuicConnectionProtocol):
    def __init__(self, account_manager, allowed_methods=None, forbidden_methods=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.db = None
        self.authenticated = False
        self.account = None
        self.challenge = None
        self.client_ip = None
        self.stream_buffers = defaultdict(bytearray)
        self.total_buffer_size = 0
        self.account_manager = account_manager
        # グローバルなデフォルト制限 (アカウント個別の設定がない場合に使用)
        self.default_allowed_methods = allowed_methods
        self.default_forbidden_methods = forbidden_methods
        # Store task references to prevent premature GC in Python 3.13+
        self._background_tasks = set()

    def connection_made(self, transport):
        super().connection_made(transport)
        # aioquicではプラットフォームや環境によりpeernameが取得しにくい場合がある
        # 複数の方法でクライアントIPの取得を試みる (Cross-platform robustness)
        addr = None
        try:
            # 1. 標準的なpeername
            peername = transport.get_extra_info("peername")
            if peername:
                addr = peername[0]

            # 2. ソケットから直接 (一部のプラットフォーム/状況で有効)
            if not addr:
                sock = transport.get_extra_info("socket")
                if sock:
                    addr = sock.getpeername()[0]

            # 3. aioquicの内部情報 (QUIC固有)
            if not addr and hasattr(self._quic, '_peer_cid'):
                addr = self._quic._peer_cid.host_addr
        except Exception:
            # 取得に失敗しても処理は継続する。詳細はデバッグログに残す。
            logging.debug("Failed to resolve client IP from transport.", exc_info=True)

        self.client_ip = addr or "unknown"
        print(f"New connection from: {self.client_ip}", flush=True)

    def connection_lost(self, exc):
        """Clean up background tasks when connection is lost
        
        Clear task references when connection terminates. Running tasks
        will complete or be cancelled depending on their current state.
        """
        self._background_tasks.clear()
        super().connection_lost(exc)

    def quic_event_received(self, event):
        if is_banned(self.client_ip):
            print(f"Blocked connection from banned IP: {self.client_ip}")
            self.close()
            return

        if isinstance(event, StreamDataReceived):
            # 同時ストリーム数制限 (未認証時は厳格に適用)
            if not self.authenticated and len(self.stream_buffers) >= MAX_CONCURRENT_STREAMS:
                print(f"Too many concurrent streams for unauthenticated connection: {self.client_ip}")
                self._quic.reset_stream(event.stream_id, 0)
                return

            # 合計バッファサイズ制限
            new_data_len = len(event.data)
            if self.total_buffer_size + new_data_len > MAX_TOTAL_BUFFER_SIZE:
                print(f"Total buffer overflow for connection from: {self.client_ip}")
                self.close()
                return

            # ストリーム個別のサイズ制限
            if len(self.stream_buffers[event.stream_id]) + new_data_len > MAX_STREAM_BUFFER_SIZE:
                print(f"Stream buffer overflow for stream {event.stream_id}")
                # このストリームの分を合計から引く
                self.total_buffer_size -= len(self.stream_buffers[event.stream_id])
                self.stream_buffers.pop(event.stream_id)
                self._quic.reset_stream(event.stream_id, 0)
                return

            # バッファリング
            self.stream_buffers[event.stream_id].extend(event.data)
            self.total_buffer_size += new_data_len

            if event.end_stream:
                data = bytes(self.stream_buffers.pop(event.stream_id))
                self.total_buffer_size -= len(data)

                # Store task reference to prevent garbage collection in Python 3.13+
                task = asyncio.create_task(self.handle_request(event.stream_id, data))
                self._background_tasks.add(task)
                _active_tasks.add(task) # Global reference
                task.add_done_callback(self._background_tasks.discard)
                task.add_done_callback(_active_tasks.discard)

    async def handle_request(self, stream_id, data):
        try:
            # 即時反映のため、リクエストごとにBAN状態を再チェック
            if is_banned(self.client_ip):
                self.close()
                return

            message, _ = protocol.decode_message(data)
            if message is None:
                return

            # 1. チャレンジ・レスポンス認証 (パスキー方式)
            if not self.authenticated:
                # 認証フェーズ1: クライアントからの認証開始要求
                if message == "AUTH_START":
                    self.challenge = secrets.token_bytes(32)
                    self._send_response(stream_id, {"type": "challenge", "data": self.challenge})
                    return

                # 認証フェーズ2: 署名の検証
                if isinstance(message, dict) and message.get("type") == "response":
                    # チャレンジが未生成の場合は明示的に拒否
                    if self.challenge is None:
                        self._send_response(stream_id, "AUTH_FAILED")
                        return

                    signature = message.get("data")
                    account_name_hint = message.get("account")

                    # AccountManagerを使用してアカウントを検索 (ヒントがあれば活用)
                    account = self.account_manager.find_account_by_signature(signature, self.challenge, account_name_hint)

                    if account:
                        self.authenticated = True
                        self.account = account
                        self.db = get_shared_db()  # 共有DBを使用
                        if self.client_ip in failed_attempts:
                            del failed_attempts[self.client_ip]
                        response = "AUTH_OK"
                        print(f"Authentication successful for {self.client_ip} (Account: {account.name})")
                    else:
                        is_now_banned = record_failed_attempt(self.client_ip)
                        print(f"Auth failed for {self.client_ip}. Attempt: {failed_attempts.get(self.client_ip, 0)}")

                        if is_now_banned:
                            response = "AUTH_BANNED"
                        else:
                            response = "AUTH_FAILED"

                    self._send_response(stream_id, response)
                    return

                # [FIX 3] 未認証状態で不正なメッセージを受信した場合
                self._send_response(stream_id, {"status": "error", "message": "Unauthorized: Please start with AUTH_START"})
                return

            # 2. RPC実行 (認証済みの場合)
            if self.authenticated:
                # [FIX 3] 認証済み状態でAUTH_STARTを再送された場合は無視
                if message == "AUTH_START":
                    self._send_response(stream_id, {"status": "error", "message": "Already authenticated"})
                    return

                result = await self.execute_rpc(message)
                self._send_response(stream_id, result)
            else:
                self._send_response(stream_id, {"status": "error", "message": "Unauthorized"})

        except (PermissionError, ValueError, AttributeError, RuntimeError, NanaSQLiteError) as e:
            # クライアントに返しても安全なエラー (NanaSQLiteErrorを追加)
            self._send_response(stream_id, {
                "status": "error",
                "error_type": type(e).__name__,
                "message": str(e)
            })
        except Exception as e:
            # 予期しないエラーは詳細を隠す (情報漏洩対策)
            print(f"Unexpected error handling request: {e}")
            self._send_response(stream_id, {
                "status": "error",
                "error_type": "InternalServerError",
                "message": "An unexpected error occurred"
            })

    async def execute_rpc(self, message):
        if not isinstance(message, dict):
            raise ValueError("RPC message must be a dictionary")

        method_name = str(message.get("method"))
        args = message.get("args", [])
        kwargs = message.get("kwargs", {})

        # 動的な権限剥奪の反映: watchfilesがバックグラウンドで最新に保っている
        current_account = next((a for a in self.account_manager.accounts if a.name == self.account.name), None)
        if not current_account:
            raise PermissionError(f"Account '{self.account.name}' has been disabled")

        # 権限情報を最新に更新
        allowed_methods = current_account.allowed_methods
        forbidden_methods = current_account.forbidden_methods

        # 動的保護:
        # 1. カスタム許可リストがあれば優先的にチェック
        # 2. カスタム禁止リストがあればチェック
        # 3. デフォルトの動的保護メカニズム

        # 優先順位 1: カスタム許可リスト (ホワイトリスト)
        # allowed_methods が指定されている場合、そこにないメソッドは全て拒否する
        if allowed_methods is not None:
            if method_name not in allowed_methods:
                raise PermissionError(f"Method '{method_name}' is not in the allowed list for account '{current_account.name}'")
        else:
            # 優先順位 2: カスタム禁止リスト (ブラックリスト)
            if forbidden_methods and method_name in forbidden_methods:
                raise PermissionError(f"Method '{method_name}' is forbidden for account '{current_account.name}'")

            # 優先順位 3: デフォルトの安全制限 (ブラックリストがない、またはリストに含まれない場合)
            is_special = method_name.startswith("__") and method_name.endswith("__")
            allowed_special = {"__getitem__", "__setitem__", "__delitem__", "__contains__", "__len__"}

            # 安全性のための厳格なチェック
            is_nana_method = method_name in dir(NanaSQLite)

            if (method_name.startswith("_") and not is_special) or \
               (is_special and method_name not in allowed_special) or \
               (not is_nana_method and not is_special) or \
               (method_name in FORBIDDEN_METHODS):
                raise PermissionError(f"Method '{method_name}' is forbidden or invalid")

        if hasattr(self.db, method_name):
            method = getattr(self.db, method_name)

            # 全てのDB操作をexecutorで実行 (OSを問わずイベントループをブロッキングから守る)
            loop = asyncio.get_running_loop()
            try:
                # DB操作にタイムアウトを設定 (デッドロックや長時間ロックの対策)
                result = await asyncio.wait_for(
                    loop.run_in_executor(
                        get_executor(),
                        functools.partial(method, *args, **kwargs)
                    ),
                    timeout=15.0 # 十分に長いが無限ではない
                )
                return {"status": "success", "result": result}
            except asyncio.TimeoutError:
                logging.error(f"Database operation timeout: {method_name}")
                raise RuntimeError("Database operation timed out")
        else:
            raise AttributeError(f"NanaSQLite object has no attribute '{method_name}'")

    def _send_response(self, stream_id, data):
        payload = protocol.encode_message(data)
        self._quic.send_stream_data(stream_id, payload, end_stream=True)
        self.transmit()

def main_sync():
    """Entry point for console_scripts"""
    parser = argparse.ArgumentParser(description="NanaSQLite QUIC Server")
    parser.add_argument("--port", type=int, default=4433, help="Port to listen on")
    parser.add_argument("--accounts", type=str, default="accounts.json", help="Path to accounts configuration file")
    parser.add_argument("--db", type=str, default="server_db.sqlite", help="Path to SQLite database file")
    args = parser.parse_args()

    # Python 3.13+ では、シグナルハンドラの登録タイミングが重要な場合があるため
    # asyncio.run() に全て任せる
    try:
        asyncio.run(main(port=args.port, account_config=args.accounts, db_path=args.db))
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass

async def main(allowed_methods=None, forbidden_methods=None, port=4433, account_config="accounts.json", db_path="server_db.sqlite"):
    global _executor, _server, _db_path
    _db_path = db_path

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()

    # シグナルハンドラの設定
    if sys.platform != "win32":
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, lambda: stop_event.set())
    else:
        # Windows では signal.signal を使用 (スレッドセーフに Event をセット)
        def handle_signal(sig, frame):
            loop.call_soon_threadsafe(stop_event.set)

        signal.signal(signal.SIGINT, handle_signal)
        signal.signal(signal.SIGTERM, handle_signal)
        if hasattr(signal, "SIGBREAK"):
            signal.signal(signal.SIGBREAK, handle_signal)

    configuration = QuicConfiguration(is_client=False)
    configuration.load_cert_chain("cert.pem", "key.pem")

    # 公開鍵を事前にロード (互換性のためのデフォルト)
    default_public_key = None
    try:
        if os.path.exists(PUBLIC_KEY_PATH):
            with open(PUBLIC_KEY_PATH, "rb") as f:
                default_public_key = f.read().decode()
    except Exception:
        # Ignore if public key is not readable or missing
        pass

    # AccountManagerの初期化
    account_manager = AccountManager(account_config, default_public_key)

    print(f"NanaSQLite QUIC Server starting on 127.0.0.1:{port}")
    print("Auth mode: Ed25519 Passkey (Challenge-Response)")
    print("Security: All DB operations run in executor (non-blocking)")

    # アカウント情報の監視を開始
    account_manager.start_watching()
    # GC対策: account_manager のタスクをグローバルセットでも管理
    if account_manager._watcher_task:
        _active_tasks.add(account_manager._watcher_task)
        account_manager._watcher_task.add_done_callback(_active_tasks.discard)

    try:
        print(f"NanaSQLite Server ready and listening on {port}")
        _server = await serve(
            "127.0.0.1",
            port,
            configuration=configuration,
            create_protocol=lambda *args, **kwargs: NanaRpcProtocol(
                account_manager,
                allowed_methods,
                forbidden_methods,
                *args,
                **kwargs
            ),
        )

        # stop_event がセットされるまで待機
        try:
            await stop_event.wait()
        except (asyncio.CancelledError, KeyboardInterrupt):
            pass

    except Exception as e:
        logging.error(f"Error starting server: {e}")
    finally:
        logging.info("Server shutting down...")

        # サーバーを停止
        if _server is not None:
            _server.close()
            _server = None

        # 監視を停止
        await account_manager.stop_watching()

        # サーバー終了時にエグゼキューターをシャットダウン
        if _executor is not None:
            try:
                # wait=False to prevent hanging if threads are stuck
                _executor.shutdown(wait=False, cancel_futures=True)
            except Exception as e:
                # Intentional ignore of errors during shutdown
                logging.debug(f"Error during executor shutdown: {e}")
            _executor = None

        # stdout/stderr をフラッシュ
        sys.stdout.flush()
        sys.stderr.flush()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NanaSQLite QUIC Server")
    parser.add_argument("--port", type=int, default=4433, help="Port to listen on")
    parser.add_argument("--accounts", type=str, default="accounts.json", help="Path to accounts configuration file")
    parser.add_argument("--db", type=str, default="server_db.sqlite", help="Path to SQLite database file")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    try:
        asyncio.run(main(port=args.port, account_config=args.accounts, db_path=args.db))
    except (KeyboardInterrupt, asyncio.CancelledError):
        # Intentional ignore of KeyboardInterrupt to avoid crash log
        logging.info("Server interrupted by user (KeyboardInterrupt). Shutting down.")
