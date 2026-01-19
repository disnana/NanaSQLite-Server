import asyncio
import logging
import secrets
import time
import functools
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict
from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived
from cryptography.hazmat.primitives import serialization
from nanasqlite import NanaSQLite
from nanasqlite.exceptions import NanaSQLiteError
from . import protocol
import argparse
import os

# 設定
PUBLIC_KEY_PATH = "nana_public.pub"
MAX_FAILED_ATTEMPTS = 3
BAN_DURATION = 900  # 15分 (秒)
MAX_BAN_LIST_SIZE = 10000 # メモリ枯渇攻撃対策

# BAN・失敗回数管理
failed_attempts: dict[str, int] = {}  # {ip: count} (defaultdictから変更してサイズ管理を容易に)
ban_list: dict[str, float] = {}  # {ip: unban_time}

# スレッドプールエグゼキューター (書き込み用)
_executor = ThreadPoolExecutor(max_workers=4)

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
_shared_db = None

def get_shared_db():
    """共有DBインスタンスを取得 (遅延初期化)"""
    global _shared_db
    if _shared_db is None:
        _shared_db = NanaSQLite("server_db.sqlite", bulk_load=True)
    return _shared_db


class NanaRpcProtocol(QuicConnectionProtocol):
    def __init__(self, public_key, allowed_methods=None, forbidden_methods=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.db = None
        self.authenticated = False
        self.challenge = None
        self.client_ip = None
        self.stream_buffers = defaultdict(bytearray)
        self.public_key = public_key
        self.allowed_methods = allowed_methods
        self.forbidden_methods = forbidden_methods
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
            # ストリームデータをバッファリング (フラグメンテーション対策)
            self.stream_buffers[event.stream_id].extend(event.data)

            # 最大バッファサイズ制限 (10MB) - リソース枯渇攻撃対策
            if len(self.stream_buffers[event.stream_id]) > 10 * 1024 * 1024:
                print(f"Buffer overflow for stream {event.stream_id}")
                self.stream_buffers.pop(event.stream_id)
                self._quic.reset_stream(event.stream_id, 0)
                return

            if event.end_stream:
                data = bytes(self.stream_buffers.pop(event.stream_id))
                # Store task reference to prevent garbage collection in Python 3.13+
                task = asyncio.create_task(self.handle_request(event.stream_id, data))
                self._background_tasks.add(task)
                task.add_done_callback(self._background_tasks.discard)

    async def handle_request(self, stream_id, data):
        try:
            if not self.public_key:
                raise RuntimeError("Server public key not loaded")

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
                    try:
                        self.public_key.verify(signature, self.challenge)
                        self.authenticated = True
                        self.db = get_shared_db()  # 共有DBを使用
                        if self.client_ip in failed_attempts:
                            del failed_attempts[self.client_ip]
                        response = "AUTH_OK"
                        print(f"Authentication successful for {self.client_ip}")
                    except Exception:
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

        # 動的保護:
        # 1. カスタム許可リストがあれば優先的にチェック
        # 2. カスタム禁止リストがあればチェック
        # 3. デフォルトの動的保護メカニズム

        # 優先順位 1: カスタム許可リスト (明示的に許可されている場合は他をスキップ)
        if self.allowed_methods and method_name in self.allowed_methods:
            pass
        else:
            # 優先順位 2: カスタム禁止リスト (明示的に禁止されている場合は拒否)
            if self.forbidden_methods and method_name in self.forbidden_methods:
                raise PermissionError(f"Method '{method_name}' is forbidden by custom policy")

            # 優先順位 3: デフォルトの安全制限
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
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                _executor,
                functools.partial(method, *args, **kwargs)
            )

            return {"status": "success", "result": result}
        else:
            raise AttributeError(f"NanaSQLite object has no attribute '{method_name}'")

    def _send_response(self, stream_id, data):
        payload = protocol.encode_message(data)
        self._quic.send_stream_data(stream_id, payload, end_stream=True)
        self.transmit()

def main_sync():
    """Entry point for console_scripts"""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Server interrupted by user (KeyboardInterrupt). Shutting down.")

async def main(allowed_methods=None, forbidden_methods=None, port=4433):
    configuration = QuicConfiguration(is_client=False)
    configuration.load_cert_chain("cert.pem", "key.pem")

    # 公開鍵を事前にロード
    try:
        with open(PUBLIC_KEY_PATH, "rb") as f:
            public_key = serialization.load_ssh_public_key(f.read())
    except Exception as e:
        print(f"CRITICAL: Failed to load public key from {PUBLIC_KEY_PATH}: {e}")
        return

    print(f"NanaSQLite QUIC Server starting on 127.0.0.1:{port}")
    print("Auth mode: Ed25519 Passkey (Challenge-Response)")
    print("Security: All DB operations run in executor (non-blocking)")

    await serve(
        "127.0.0.1",
        port,
        configuration=configuration,
        create_protocol=lambda *args, **kwargs: NanaRpcProtocol(
            public_key,
            allowed_methods,
            forbidden_methods,
            *args,
            **kwargs
        ),
    )
    await asyncio.Future()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NanaSQLite QUIC Server")
    parser.add_argument("--port", type=int, default=4433, help="Port to listen on")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    try:
        asyncio.run(main(port=args.port))
    except KeyboardInterrupt:
        logging.info("Server interrupted by user (KeyboardInterrupt). Shutting down.")
