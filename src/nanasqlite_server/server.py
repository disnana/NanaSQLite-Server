import asyncio
import inspect
import ipaddress
import logging
import secrets
import time
import functools
import signal
import sys
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict
from typing import List, Union
from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived
from nanasqlite import NanaSQLite
from nanasqlite.exceptions import NanaSQLiteError
from . import protocol
from .accounts import AccountManager
import argparse
import os

# AsyncNanaSQLite サポート (nanasqlite v1.5.0dev1 以降で利用可能)
try:
    from nanasqlite import AsyncNanaSQLite
    HAS_ASYNC_NANASQLITE = True
except ImportError:  # pragma: no cover
    AsyncNanaSQLite = None  # type: ignore[assignment,misc]
    HAS_ASYNC_NANASQLITE = False

# Windows: etc/oqs.dll を DLL 検索パスに追加して liboqs の自動インストールをバイパス
if sys.platform == "win32" and hasattr(os, "add_dll_directory"):
    _etc_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "etc",
    )
    if os.path.isfile(os.path.join(_etc_dir, "oqs.dll")):
        os.add_dll_directory(_etc_dir)

# liboqs-python サポート (オプション: pip install liboqs-python)
# PQC KEM セッション鍵交換による通信保護を有効にする
try:
    import oqs  # type: ignore[import]

    HAS_OQS = True
except (ImportError, PermissionError, SystemExit):
    oqs = None  # type: ignore[assignment]
    HAS_OQS = False

# 設定
PUBLIC_KEY_PATH = "nana_public.pub"
MAX_FAILED_ATTEMPTS = 3
BAN_DURATION = 900  # 15分 (秒)
MAX_BAN_LIST_SIZE = 10000  # メモリ枯渇攻撃対策

# DoS対策設定
MAX_STREAM_BUFFER_SIZE = 10 * 1024 * 1024  # 10MB (単一ストリーム)
MAX_TOTAL_BUFFER_SIZE = 50 * 1024 * 1024  # 50MB (1接続あたり合計)
MAX_CONCURRENT_STREAMS = 50  # 1接続あたりの最大同時ストリーム数

# BAN・失敗回数管理
failed_attempts: dict[
    str, int
] = {}  # {ip: count} (defaultdictから変更してサイズ管理を容易に)
ban_list: dict[str, float] = {}  # {ip: unban_time}

# IPフィルター (サーバー起動時に main() から設定される)
# 各エントリは IPv4Network または IPv6Network
_ip_allow_list: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []  # 空=全て許可
_ip_block_list: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []  # 空=ブロックなし

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
            max_workers=10, thread_name_prefix="nanasqlite_worker"
        )
    return _executor


# 禁止メソッド一覧 (ブラックリスト)
# NanaSQLiteの更新に自動対応しつつ、危険なメソッドを制限する
FORBIDDEN_METHODS = {
    "__init__",
    "close",
    "vacuum",
    "pragma",
    "execute",
    "execute_many",
    "query",
    "sql_insert",
    "sql_update",
    "sql_delete",
    "transaction",
    "begin_transaction",
    "commit",
    "rollback",
    "open",
    "connect",
    "get_model",
    "set_model",
    "load_all",
    "refresh",
    # --- v1.4.0 新規追加: セキュリティ上危険なメソッド ---
    # backup/restore: クライアントから任意のファイルパスを指定できるため
    # ディレクトリトラバーサルや任意ファイル読み書きの脆弱性になる
    "backup",
    "restore",
    # fetch_all/fetch_one: 内部でexecute()を呼び出す生SQL実行メソッド
    # executeが既に禁止されているため、これらも禁止する
    "fetch_all",
    "fetch_one",
    # DDL操作: テーブル・インデックスの破壊的な変更を防ぐ
    "create_table",
    "alter_table_add_column",
    "drop_table",
    "drop_index",
    # create_index: 巨大インデックスの作成によるDoSや意図しないスキーマ変更を防ぐ
    "create_index",
    # --- v1.5.0 新規追加: セキュリティ上危険なメソッド ---
    # add_hook: 任意のPythonオブジェクト（フック）を注入できるため
    # RPC経由では安全に検証できず、サーバー側で任意のコードが実行される可能性がある
    "add_hook",
}

# read_only アカウントで禁止するメソッド (データを変更・削除するメソッド)
WRITE_METHODS = {
    "__setitem__",
    "__delitem__",
    "set",
    "delete",
    "batch_update",
    "batch_update_partial",
    "batch_delete",
    "clear",
    "import_from_dict_list",
    "upsert",
    "flush",
    "retry_dlq",
    "clear_dlq",
}

# AsyncNanaSQLite の特殊メソッドマッピング (--async-mode 用)
# NanaSQLite の __dunder__ メソッドを AsyncNanaSQLite の対応する非同期メソッドに変換する
ASYNC_SPECIAL_METHOD_MAP: dict[str, str] = {
    "__getitem__": "aget",
    "__setitem__": "aset",
    "__delitem__": "adelete",
    "__contains__": "acontains",
    "__len__": "alen",
}


def parse_ip_networks(
    entries: List[str],
) -> List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]:
    """IP アドレス・CIDR 表記の文字列リストを Network オブジェクトに変換する。

    個々のIPアドレス ("192.168.1.1") はホスト CIDR として扱う。
    不正な値はスキップし、警告ログを出力する。
    """
    networks = []
    for entry in entries:
        entry = entry.strip()
        if not entry:
            continue
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            logging.warning("Invalid IP/CIDR entry, skipping: %r", entry)
    return networks


def is_ip_allowed(ip_str: str) -> bool:
    """接続元 IP がアクセス許可されているか確認する。

    判定ルール:
    1. IP が不明 ("unknown") の場合: フィルタをスキップして認証に委ねる。
       QUIC/UDP トランスポートでは peername が取得できないケースがあるため。
    2. block リストに含まれる場合は常に拒否。
    3. allow リストが空でない場合: IP が allow リストの **いずれか** に含まれる場合のみ許可。
    4. 上記いずれにも該当しない場合は許可。

    Args:
        ip_str: 接続元 IP アドレス文字列 (例: "192.168.1.10") または "unknown"

    Returns:
        True = 接続を許可 / False = 接続を拒否
    """
    if ip_str == "unknown":
        # IP を取得できなかった接続: QUIC/UDP では peername が None になる環境がある。
        # IP フィルタの適用をスキップし、チャレンジ・レスポンス認証に委ねる。
        if _ip_allow_list or _ip_block_list:
            logging.warning(
                "IP filter is configured but client IP could not be determined. "
                "Skipping IP filter; authentication will proceed normally."
            )
        return True

    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        logging.warning("Could not parse client IP address: %r", ip_str)
        return True

    # block リストチェック
    for net in _ip_block_list:
        if addr in net:
            return False

    # allow リストチェック (空 = 制限なし)
    if _ip_allow_list:
        for net in _ip_allow_list:
            if addr in net:
                return True
        return False  # allow リストに含まれない

    return True


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


# 共有DBインスタンス管理
_db_instances: dict[str, NanaSQLite] = {}
_db_instances_lock = asyncio.Lock()

# v2エンジン設定 (main()で設定される)
_db_config: dict = {}


async def get_db_instance(db_path, bulk_load=True):
    """DBインスタンスを取得（遅延初期化、スレッドセーフ）"""
    async with _db_instances_lock:
        if db_path not in _db_instances:
            logging.info(f"Initializing new database instance: {db_path}")
            # _db_config から async_mode を除いた設定をコンストラクタに渡す
            init_kwargs: dict[str, object] = {"bulk_load": bulk_load}
            init_kwargs.update({k: v for k, v in _db_config.items() if k != "async_mode"})

            if _db_config.get("async_mode") and HAS_ASYNC_NANASQLITE:
                # AsyncNanaSQLite: __init__ は同期処理のみで DB 接続は遅延初期化
                _db_instances[db_path] = AsyncNanaSQLite(db_path, **init_kwargs)
            else:
                # NanaSQLite: スレッドプールで初期化（IOが発生するため）
                loop = asyncio.get_running_loop()
                _db_instances[db_path] = await loop.run_in_executor(
                    get_executor(), lambda: NanaSQLite(db_path, **init_kwargs)
                )
        return _db_instances[db_path]


def validate_db_path(base_dir, db_name):
    """
    DBパスを検証し、ベースディレクトリ配下にあることを保証する。
    ディレクトリトラバーサル攻撃を防ぐ。
    """
    if not db_name:
        return None

    # 正規化
    safe_name = os.path.normpath(db_name)

    # 絶対パスや '..' を含むパスの拒否（追加の安全策）
    if os.path.isabs(safe_name) or ".." in safe_name.split(os.sep):
        raise PermissionError(f"Invalid characters in DB name: {db_name}")

    # パス結合
    full_path = os.path.abspath(os.path.join(base_dir, safe_name))
    base_abs = os.path.abspath(base_dir)

    # ベースディレクトリ配下であることを確認
    if not full_path.startswith(base_abs):
        raise PermissionError(f"DB path traversal detected: {db_name}")

    return full_path


class NanaRpcProtocol(QuicConnectionProtocol):
    def __init__(
        self,
        account_manager,
        allowed_methods=None,
        forbidden_methods=None,
        pqc_kem_algorithm=None,
        *args,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.db = None
        self.authenticated = False
        self.account = None
        self.challenge = None
        self.client_ip = None
        self._ip_allowed = True  # connection_made で更新される
        self.stream_buffers = defaultdict(bytearray)
        self.total_buffer_size = 0
        self.account_manager = account_manager
        # グローバルなデフォルト制限 (アカウント個別の設定がない場合に使用)
        self.default_allowed_methods = allowed_methods
        self.default_forbidden_methods = forbidden_methods
        # マルチDB用: セッション中最後に使ったDBを記録（デフォルト用）
        self.last_db_name = None
        # Store task references to prevent premature GC in Python 3.13+
        self._background_tasks = set()
        # PQC KEM セッション鍵交換
        self._pqc_kem_algorithm = pqc_kem_algorithm  # サーバー設定から渡されるKEMアルゴリズム名
        self._kem_instance = None  # 接続ごとのエフェメラルKEMインスタンス
        self.pqc_session_key = None  # KEM後に導出されたAES-256セッション鍵

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
            if not addr and hasattr(self._quic, "_peer_cid"):
                addr = self._quic._peer_cid.host_addr
        except Exception:
            # 取得に失敗しても処理は継続する。詳細はデバッグログに残す。
            logging.debug("Failed to resolve client IP from transport.", exc_info=True)

        self.client_ip = addr or "unknown"
        logging.info(f"New connection from: {self.client_ip}")
        # IP フィルタは接続確立時に一度だけ評価する
        self._ip_allowed = is_ip_allowed(self.client_ip)

    def connection_lost(self, exc):
        """Clean up background tasks and KEM resources when connection is lost

        Clear task references when connection terminates. Running tasks
        will complete or be cancelled depending on their current state.
        """
        self._background_tasks.clear()
        if self._kem_instance is not None:
            try:
                self._kem_instance.free()
            except Exception:  # noqa: BLE001 - free() may fail if already freed; ignore cleanup errors
                pass
            self._kem_instance = None
        super().connection_lost(exc)

    def quic_event_received(self, event):
        if not self._ip_allowed:
            logging.warning(f"Connection rejected by IP filter: {self.client_ip}")
            self.close()
            return

        if is_banned(self.client_ip):
            logging.warning(f"Blocked connection from banned IP: {self.client_ip}")
            self.close()
            return

        if isinstance(event, StreamDataReceived):
            # 同時ストリーム数制限 (未認証時は厳格に適用)
            if (
                not self.authenticated
                and len(self.stream_buffers) >= MAX_CONCURRENT_STREAMS
            ):
                logging.warning(
                    f"Too many concurrent streams for unauthenticated connection: {self.client_ip}"
                )
                self._quic.reset_stream(event.stream_id, 0)
                return

            # 合計バッファサイズ制限
            new_data_len = len(event.data)
            if self.total_buffer_size + new_data_len > MAX_TOTAL_BUFFER_SIZE:
                logging.warning(f"Total buffer overflow for connection from: {self.client_ip}")
                self.close()
                return

            # ストリーム個別のサイズ制限
            if (
                len(self.stream_buffers[event.stream_id]) + new_data_len
                > MAX_STREAM_BUFFER_SIZE
            ):
                logging.warning(f"Stream buffer overflow for stream {event.stream_id}")
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
                _active_tasks.add(task)  # Global reference
                task.add_done_callback(self._background_tasks.discard)
                task.add_done_callback(_active_tasks.discard)

    async def handle_request(self, stream_id, data):
        try:
            # 即時反映のため、リクエストごとにBAN状態を再チェック
            if is_banned(self.client_ip):
                self.close()
                return

            # セッション鍵が確立している場合はAES-256-GCMで復号、そうでなければ通常デコード
            used_pqc_session_key = bool(self.pqc_session_key)
            if used_pqc_session_key:
                message, _ = protocol.decrypt_message(data, self.pqc_session_key)
            else:
                message, _ = protocol.decode_message(data)
            if message is None:
                # リクエストのデコード/復号に失敗した場合はエラーを返す
                # (レスポンスを返さないとクライアントが None を受け取って
                # "Authentication failed: None" のような誤解を招くエラーになる)
                if used_pqc_session_key:
                    # 暗号化セッションでの復号失敗はデータ改ざんの可能性がある
                    self._send_response(
                        stream_id,
                        {"status": "error", "message": "Invalid encrypted request"},
                    )
                    self.close()
                else:
                    # 非暗号化セッションでのデコード失敗 (不完全なデータや破損など)
                    self._send_response(
                        stream_id,
                        {"status": "error", "message": "Invalid request format"},
                    )
                return

            # 1. チャレンジ・レスポンス認証 (パスキー方式)
            if not self.authenticated:
                # 認証フェーズ1: クライアントからの認証開始要求
                if message == "AUTH_START":
                    self.challenge = secrets.token_bytes(32)
                    self._send_response(
                        stream_id, {"type": "challenge", "data": self.challenge}
                    )
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
                    account = self.account_manager.find_account_by_signature(
                        signature, self.challenge, account_name_hint
                    )

                    if account:
                        # アカウントレベルの IP 制限チェック
                        if not account.is_ip_allowed(self.client_ip):
                            logging.warning(
                                f"Authentication rejected by account-level IP filter: "
                                f"{self.client_ip} (Account: {account.name})"
                            )
                            self._send_response(stream_id, "AUTH_FAILED")
                            return

                        self.authenticated = True
                        self.account = account
                        # 認証時にデフォルトDBを設定（あれば）
                        if account.allowed_dbs:
                            self.last_db_name = sorted(account.allowed_dbs.keys())[0]
                        else:
                            # アカウントごとの制限がない場合は、サーバー全体のデフォルトDBを使用
                            global _db_path
                            self.last_db_name = os.path.basename(_db_path)
                        if self.client_ip in failed_attempts:
                            del failed_attempts[self.client_ip]

                        # PQC KEM が有効な場合、AUTH_OK にKEM情報を含める
                        if self._pqc_kem_algorithm and HAS_OQS:
                            kem = None
                            try:
                                kem = oqs.KeyEncapsulation(self._pqc_kem_algorithm)
                                kem_pubkey = kem.generate_keypair()
                                self._kem_instance = kem
                                kem = None  # ownership transferred
                                response = {
                                    "type": "auth_ok",
                                    "kem": {
                                        "algorithm": self._pqc_kem_algorithm,
                                        "public_key": kem_pubkey,
                                    },
                                }
                                logging.info(
                                    f"Authentication successful for {self.client_ip} "
                                    f"(Account: {account.name}), KEM offer sent ({self._pqc_kem_algorithm})"
                                )
                            except Exception:
                                if kem is not None:
                                    try:
                                        kem.free()
                                    except Exception:  # noqa: BLE001 - free() may fail; ignore cleanup errors
                                        pass
                                logging.exception(
                                    "Failed to create KEM offer for algorithm %s; "
                                    "falling back to AUTH_OK without KEM",
                                    self._pqc_kem_algorithm,
                                )
                                response = "AUTH_OK"
                                logging.info(
                                    f"Authentication successful for {self.client_ip} (Account: {account.name})"
                                )
                        else:
                            response = "AUTH_OK"
                            logging.info(
                                f"Authentication successful for {self.client_ip} (Account: {account.name})"
                            )
                    else:
                        is_now_banned = record_failed_attempt(self.client_ip)
                        logging.warning(
                            f"Auth failed for {self.client_ip}. Attempt: {failed_attempts.get(self.client_ip, 0)}"
                        )

                        if is_now_banned:
                            response = "AUTH_BANNED"
                        else:
                            response = "AUTH_FAILED"

                    self._send_response(stream_id, response)
                    return

                # [FIX 3] 未認証状態で不正なメッセージを受信した場合
                self._send_response(
                    stream_id,
                    {
                        "status": "error",
                        "message": "Unauthorized: Please start with AUTH_START",
                    },
                )
                return

            # 2. PQC KEM レスポンス処理 (認証済み、KEM交換待ち)
            if self.authenticated and self._kem_instance is not None:
                if isinstance(message, dict) and message.get("type") == "kem_response":
                    ciphertext = message.get("ciphertext")
                    shared_secret = None
                    try:
                        shared_secret = self._kem_instance.decap_secret(ciphertext)
                    except Exception as e:
                        logging.warning(f"KEM decapsulation failed for {self.client_ip}: {e}")
                        self._send_response(
                            stream_id,
                            {"status": "error", "message": "KEM exchange failed"},
                        )
                    finally:
                        try:
                            self._kem_instance.free()
                        except Exception:  # noqa: BLE001 - free() may fail if already freed; ignore cleanup errors
                            pass
                        self._kem_instance = None
                    # shared_secret が None の場合はエラー応答送信済みなので接続を終了する。
                    # _kem_instance は already freed なので後続リクエストが KEM チェックを
                    # 迂回して RPC へ進むのを防ぐため、接続を切断する。
                    if shared_secret is None:
                        self.close()
                        return
                    # KEM_OK はセッション鍵を有効化する前に平文で送信する
                    # (クライアントも同時にセッション鍵を確立するため)
                    self._send_response(stream_id, "KEM_OK")
                    # KEM_OK 送信後にセッション鍵を有効化 (以後の通信はAES-256-GCMで暗号化される)
                    self.pqc_session_key = protocol.derive_session_key(shared_secret)
                    logging.info(
                        f"PQC KEM session established for {self.client_ip} "
                        f"({self._pqc_kem_algorithm})"
                    )
                    return
                # KEM が提示されたのに kem_response 以外が来た場合は拒否
                self._send_response(
                    stream_id,
                    {
                        "status": "error",
                        "message": "KEM exchange required before RPC",
                    },
                )
                return

            # 3. RPC実行 (認証済み、KEM完了または不要)
            if self.authenticated:
                # [FIX 3] 認証済み状態でAUTH_STARTを再送された場合は無視
                if message == "AUTH_START":
                    self._send_response(
                        stream_id,
                        {"status": "error", "message": "Already authenticated"},
                    )
                    return

                result = await self.execute_rpc(message)
                self._send_response(stream_id, result)
            else:
                self._send_response(
                    stream_id, {"status": "error", "message": "Unauthorized"}
                )

        except (
            PermissionError,
            ValueError,
            RuntimeError,
            KeyError,
            NanaSQLiteError,
        ) as e:
            # クライアントに返しても安全なエラー
            self._send_response(
                stream_id,
                {"status": "error", "error_type": type(e).__name__, "message": str(e)},
            )
        except (AttributeError, TypeError) as e:
            # サーバー内部エラー (不正なメソッド呼び出し等): 詳細を隠蔽してログに記録
            logging.error(f"Internal error ({type(e).__name__}) handling request: {e}")
            self._send_response(
                stream_id,
                {
                    "status": "error",
                    "error_type": "InternalServerError",
                    "message": "Internal Server Error",
                },
            )
        except Exception as e:
            # 予期しないエラーは詳細を隠す (情報漏洩対策)
            logging.error(f"Unexpected error ({type(e).__name__}) handling request: {e}")
            self._send_response(
                stream_id,
                {
                    "status": "error",
                    "error_type": "InternalServerError",
                    "message": "Internal Server Error",
                },
            )

    async def execute_rpc(self, message):
        if not isinstance(message, dict):
            raise ValueError("RPC message must be a dictionary")

        method_name = str(message.get("method"))
        args = message.get("args", [])
        kwargs = message.get("kwargs", {})
        db_name = message.get("db")  # 要求されたDB名

        # 動的な権限剥奪の反映
        current_account = next(
            (a for a in self.account_manager.accounts if a.name == self.account.name),
            None,
        )
        if not current_account:
            raise PermissionError(f"Account '{self.account.name}' has been disabled")

        # 1. DBの決定と検証
        target_db_name = db_name or self.last_db_name
        if not target_db_name:
            raise ValueError("No database specified and no default available")

        # アカウントごとの許可リストをチェック
        if current_account.allowed_dbs is not None:
            if target_db_name not in current_account.allowed_dbs:
                raise PermissionError(
                    f"Access to database '{target_db_name}' is not allowed for account '{current_account.name}'"
                )
            # テーブルレベルの制限チェック
            allowed_tables = current_account.allowed_dbs[target_db_name]
            if allowed_tables is not None:
                # kwargs からテーブル名を取得する (明示的に指定された場合のみ検査)
                table_name = kwargs.get("table_name") if isinstance(kwargs, dict) else None
                if table_name is not None and table_name not in allowed_tables:
                    raise PermissionError(
                        f"Access to table '{table_name}' in database '{target_db_name}' "
                        f"is not allowed for account '{current_account.name}'"
                    )

        # パスの安全性を検証し、絶対パスを取得
        full_db_path = validate_db_path(self.account_manager.db_dir, target_db_name)
        self.last_db_name = target_db_name  # 最後に成功したDBを記憶

        # 2. メソッド実行権限の更新・確認
        allowed_methods = current_account.allowed_methods
        forbidden_methods = current_account.forbidden_methods

        # read_only アカウントは書き込み系メソッドを呼び出せない
        if current_account.read_only and method_name in WRITE_METHODS:
            raise PermissionError(
                f"Method '{method_name}' is not allowed for read-only account '{current_account.name}'"
            )

        if allowed_methods is not None:
            if method_name not in allowed_methods:
                raise PermissionError(
                    f"Method '{method_name}' is not in the allowed list for account '{current_account.name}'"
                )
        else:
            if forbidden_methods and method_name in forbidden_methods:
                raise PermissionError(
                    f"Method '{method_name}' is forbidden for account '{current_account.name}'"
                )

            is_special = method_name.startswith("__") and method_name.endswith("__")
            allowed_special = {
                "__getitem__",
                "__setitem__",
                "__delitem__",
                "__contains__",
                "__len__",
            }
            is_nana_method = method_name in dir(NanaSQLite)

            if (
                (method_name.startswith("_") and not is_special)
                or (is_special and method_name not in allowed_special)
                or (not is_nana_method and not is_special)
                or (method_name in FORBIDDEN_METHODS)
            ):
                raise PermissionError(f"Method '{method_name}' is forbidden or invalid")

        # 3. DBインスタンスの取得と実行
        db_instance = await get_db_instance(full_db_path)

        # AsyncNanaSQLite の場合: メソッド名を非同期対応にマッピング
        # 特殊メソッド (__getitem__ 等) → a プレフィックス版 (aget 等)
        # 同名メソッドが存在しない場合 (batch_get 等) → a プレフィックス版を試みる
        actual_method_name = method_name
        if HAS_ASYNC_NANASQLITE and isinstance(db_instance, AsyncNanaSQLite):
            actual_method_name = ASYNC_SPECIAL_METHOD_MAP.get(method_name, method_name)
            if not hasattr(db_instance, actual_method_name):
                a_prefixed = f"a{actual_method_name}"
                if hasattr(db_instance, a_prefixed):
                    actual_method_name = a_prefixed

        if hasattr(db_instance, actual_method_name):
            method = getattr(db_instance, actual_method_name)

            try:
                if inspect.iscoroutinefunction(method):
                    # AsyncNanaSQLite: ネイティブな非同期メソッドを直接 await する
                    result = await asyncio.wait_for(
                        method(*args, **kwargs),
                        timeout=15.0,
                    )
                else:
                    # NanaSQLite: 同期メソッドをスレッドプールで実行する
                    loop = asyncio.get_running_loop()
                    result = await asyncio.wait_for(
                        loop.run_in_executor(
                            get_executor(), functools.partial(method, *args, **kwargs)
                        ),
                        timeout=15.0,
                    )
                return {"status": "success", "result": result}
            except asyncio.TimeoutError:
                logging.error(f"Database operation timeout: {method_name} on {target_db_name}")
                raise RuntimeError("Database operation timed out")
        else:
            raise AttributeError(f"NanaSQLite object has no attribute '{method_name}'")

    def _send_response(self, stream_id, data):
        if self.pqc_session_key:
            payload = protocol.encrypt_message(data, self.pqc_session_key)
        else:
            payload = protocol.encode_message(data)
        self._quic.send_stream_data(stream_id, payload, end_stream=True)
        self.transmit()


def main_sync():
    """Entry point for console_scripts"""
    parser = argparse.ArgumentParser(description="NanaSQLite QUIC Server")
    parser.add_argument("--port", type=int, default=4433, help="Port to listen on")
    parser.add_argument(
        "--accounts",
        type=str,
        default="accounts.json",
        help="Path to accounts configuration file",
    )
    parser.add_argument(
        "--db",
        type=str,
        default="server_db.sqlite",
        help="Path to SQLite database file",
    )
    # v2エンジン設定
    parser.add_argument(
        "--v2",
        action="store_true",
        default=False,
        help="Enable NanaSQLite v2 engine (background async writes)",
    )
    parser.add_argument(
        "--flush-mode",
        type=str,
        default="immediate",
        choices=["immediate", "count", "time", "manual"],
        help="v2 flush mode (default: immediate)",
    )
    parser.add_argument(
        "--flush-interval",
        type=float,
        default=3.0,
        help="v2 flush interval in seconds for 'time' mode (default: 3.0)",
    )
    parser.add_argument(
        "--flush-count",
        type=int,
        default=100,
        help="v2 write count threshold for 'count' mode (default: 100)",
    )
    parser.add_argument(
        "--v2-chunk-size",
        type=int,
        default=1000,
        help="v2 maximum writes per flush transaction (default: 1000)",
    )
    parser.add_argument(
        "--enable-metrics",
        action="store_true",
        default=False,
        help="Enable v2 engine metrics collection (v1.5.0+, requires --v2)",
    )
    # Asyncモード設定
    parser.add_argument(
        "--async-mode",
        action="store_true",
        default=False,
        help="Use AsyncNanaSQLite for non-blocking database operations (recommended: nanasqlite v1.5.0dev1+; see docs/async-mode.md)",
    )
    # PQC KEM セッション暗号化設定
    parser.add_argument(
        "--pqc-kem",
        type=str,
        default=None,
        metavar="ALGORITHM",
        help=(
            "Enable post-quantum KEM session key exchange after authentication and encrypt "
            "all subsequent communication with AES-256-GCM. Requires liboqs-python. "
            "Example algorithms: Kyber768, Kyber1024, ML-KEM-768. "
            "See docs/pqc.md for details."
        ),
    )
    # IPフィルター設定
    parser.add_argument(
        "--allow-ips",
        type=str,
        default=None,
        metavar="IP_LIST",
        help=(
            "Comma-separated list of allowed IP addresses or CIDR ranges. "
            "When set, only connections from these IPs are accepted. "
            "Examples: '192.168.1.0/24,10.0.0.1' or '127.0.0.1'. "
            "See docs/ip-filter.md for details."
        ),
    )
    parser.add_argument(
        "--block-ips",
        type=str,
        default=None,
        metavar="IP_LIST",
        help=(
            "Comma-separated list of blocked IP addresses or CIDR ranges. "
            "Connections from these IPs are always rejected regardless of allow list. "
            "Examples: '10.0.0.0/8,172.16.0.5'. "
            "See docs/ip-filter.md for details."
        ),
    )
    args = parser.parse_args()

    # Python 3.13+ では、シグナルハンドラの登録タイミングが重要な場合があるため
    # asyncio.run() に全て任せる
    try:
        asyncio.run(
            main(
                port=args.port,
                account_config=args.accounts,
                db_path=args.db,
                v2_mode=args.v2,
                flush_mode=args.flush_mode,
                flush_interval=args.flush_interval,
                flush_count=args.flush_count,
                v2_chunk_size=args.v2_chunk_size,
                v2_enable_metrics=args.enable_metrics,
                async_mode=args.async_mode,
                pqc_kem_algorithm=args.pqc_kem,
                allow_ips=args.allow_ips,
                block_ips=args.block_ips,
            )
        )
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass


async def main(
    allowed_methods=None,
    forbidden_methods=None,
    port=4433,
    account_config="accounts.json",
    db_path="server_db.sqlite",
    v2_mode=False,
    flush_mode="immediate",
    flush_interval=3.0,
    flush_count=100,
    v2_chunk_size=1000,
    v2_enable_metrics=False,
    async_mode=False,
    pqc_kem_algorithm=None,
    allow_ips=None,
    block_ips=None,
):
    global _executor, _server, _db_path, _db_config, _ip_allow_list, _ip_block_list
    _db_path = db_path

    # IPフィルターの初期化
    _ip_allow_list = parse_ip_networks(
        [e.strip() for e in allow_ips.split(",") if e.strip()] if allow_ips else []
    )
    _ip_block_list = parse_ip_networks(
        [e.strip() for e in block_ips.split(",") if e.strip()] if block_ips else []
    )
    if _ip_allow_list:
        logging.info("IP allow list: %s", [str(n) for n in _ip_allow_list])
    if _ip_block_list:
        logging.info("IP block list: %s", [str(n) for n in _ip_block_list])

    # v2エンジン設定をグローバルに保存 (get_db_instanceで参照される)
    _db_config = {}
    if v2_mode:
        _db_config["v2_mode"] = True
        _db_config["flush_mode"] = flush_mode
        _db_config["flush_interval"] = flush_interval
        _db_config["flush_count"] = flush_count
        _db_config["v2_chunk_size"] = v2_chunk_size
        _db_config["v2_enable_metrics"] = v2_enable_metrics
        logging.info(
            f"v2 engine enabled: flush_mode={flush_mode}, flush_interval={flush_interval}, "
            f"flush_count={flush_count}, v2_chunk_size={v2_chunk_size}, "
            f"enable_metrics={v2_enable_metrics}"
        )

    # Asyncモード設定
    if async_mode:
        if not HAS_ASYNC_NANASQLITE:
            raise RuntimeError(
                "--async-mode requires AsyncNanaSQLite, which is not available in the "
                "currently installed version of nanasqlite. "
                "Recommended: nanasqlite v1.5.0dev1 or later. "
                "See docs/async-mode.md for details."
            )
        _db_config["async_mode"] = True
        logging.info("Async mode enabled: using AsyncNanaSQLite")

    # PQC KEM セッション暗号化設定
    if pqc_kem_algorithm:
        if not HAS_OQS:
            raise RuntimeError(
                "--pqc-kem requires liboqs-python, which is not installed. "
                "Install with: pip install liboqs-python  "
                "(or: pip install 'nanasqlite-server[pqc]'). "
                "See docs/pqc.md for details."
            )
        # アルゴリズム名の有効性を起動時に確認
        try:
            _kem_check = oqs.KeyEncapsulation(pqc_kem_algorithm)
            _kem_check.free()
        except Exception as e:
            raise RuntimeError(
                f"Invalid or unsupported PQC KEM algorithm: {pqc_kem_algorithm!r}. "
                f"Error: {e}. "
                "Run 'python -c \"import oqs; print(oqs.get_enabled_kem_mechanisms())\"' "
                "to list supported algorithms."
            ) from e
        logging.info(
            f"PQC KEM session encryption enabled: algorithm={pqc_kem_algorithm}"
        )

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

    logging.info(f"NanaSQLite QUIC Server starting on 127.0.0.1:{port}")
    logging.info("Auth mode: Ed25519 Passkey / OQS PQC Signature (Challenge-Response)")
    logging.info("Security: All DB operations run in executor (non-blocking)")
    if pqc_kem_algorithm:
        logging.info(f"Session encryption: PQC KEM ({pqc_kem_algorithm}) + AES-256-GCM")

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
                pqc_kem_algorithm,
                *args,
                **kwargs,
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

        # AsyncNanaSQLiteインスタンスを適切に閉じる
        async with _db_instances_lock:
            for db_path_key, db_inst in list(_db_instances.items()):
                if hasattr(db_inst, "close"):
                    try:
                        if inspect.iscoroutinefunction(db_inst.close):
                            await db_inst.close()
                        else:
                            db_inst.close()
                    except Exception as e:
                        logging.debug(f"Error closing DB instance {db_path_key}: {e}")
            _db_instances.clear()

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
    main_sync()
