import asyncio
import logging
import secrets
import time
import functools
import json
import os
import argparse
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict
from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived
from cryptography.hazmat.primitives import serialization
from nanasqlite import NanaSQLite
from nanasqlite.exceptions import NanaSQLiteError
from . import protocol

# --- デフォルト設定 ---
DEFAULT_CONFIG = {
    "host": "127.0.0.1",
    "port": 4433,
    "cert_file": "cert.pem",
    "key_file": "key.pem",
    "db_path": "server_db.sqlite",
    "max_failed_attempts": 3,
    "ban_duration": 900,
    "max_ban_list_size": 1000,
    "max_buffer_size": 10 * 1024 * 1024, # 10MB
    "max_active_streams": 100,
    "accounts_file": "accounts.json"
}

# 禁止メソッド一覧 (デフォルト)
DEFAULT_FORBIDDEN_METHODS = {
    "__init__", "close", "vacuum", "pragma", "execute", "execute_many",
    "query", "sql_insert", "sql_update", "sql_delete", "transaction",
    "begin_transaction", "commit", "rollback", "open", "connect",
    "get_model", "set_model", "load_all", "refresh"
}

# BAN・失敗回数管理
failed_attempts: dict[str, int] = {}
ban_list: dict[str, float] = {}

_executor = ThreadPoolExecutor(max_workers=4)
_shared_db = None

def get_shared_db(db_path):
    global _shared_db
    if _shared_db is None:
        _shared_db = NanaSQLite(db_path, bulk_load=True)
    return _shared_db

def is_banned(ip, config):
    if os.environ.get("NANASQLITE_DISABLE_BAN"):
        return False
    now = time.time()
    expired_bans = [addr for addr, expire in ban_list.items() if now >= expire]
    for addr in expired_bans:
        del ban_list[addr]
        if addr in failed_attempts:
            del failed_attempts[addr]
    return ip in ban_list

def record_failed_attempt(ip, config):
    if os.environ.get("NANASQLITE_DISABLE_BAN"):
        return False
    if len(failed_attempts) > config["max_ban_list_size"]:
        failed_attempts.clear()
    failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
    if failed_attempts[ip] >= config["max_failed_attempts"]:
        if len(ban_list) < config["max_ban_list_size"]:
            ban_list[ip] = time.time() + config["ban_duration"]
            logging.warning(f"IP {ip} has been BANNED")
        return True
    return False

class AccountManager:
    """アカウントと権限の管理"""
    def __init__(self, accounts_file):
        self.accounts = {} # {public_key_bytes: {"name": str, "allowed": set, "forbidden": set, "key_obj": object}}
        self.load_accounts(accounts_file)

    def load_accounts(self, filepath):
        """アカウント設定をロードする。パストラバーサル防止のため、鍵パスはベースディレクトリ内で解決する。"""
        # アカウントファイルのパスを正規化
        filepath = os.path.abspath(filepath)
        base_dir = os.path.dirname(filepath)

        if not os.path.exists(filepath):
            logging.warning("Accounts file not found. Using default admin key if available.")
            # デフォルトアカウント
            default_key = "nana_public.pub"
            if os.path.exists(default_key):
                try:
                    with open(default_key, "rb") as f:
                        pk_bytes = f.read()
                        pk_obj = serialization.load_ssh_public_key(pk_bytes)
                        self.accounts[pk_bytes] = {
                            "name": "default_admin",
                            "allowed": ["*"],
                            "forbidden": list(DEFAULT_FORBIDDEN_METHODS),
                            "key_obj": pk_obj
                        }
                except Exception:
                    logging.error("Failed to load default admin key")
            return

        try:
            with open(filepath, "r") as f:
                data = json.load(f)
                for acc in data:
                    pk_path = acc.get("public_key_path")
                    if not pk_path:
                        continue

                    # パストラバーサル防止: ベースディレクトリ外のパスを拒否
                    # os.path.join 後の絶対パスが base_dir で始まっていることを確認
                    raw_joined = os.path.join(base_dir, pk_path)
                    safe_pk_path = os.path.abspath(raw_joined)

                    if not safe_pk_path.startswith(base_dir + os.sep) and \
                       os.path.dirname(safe_pk_path) != base_dir:
                        logging.error("Security: Path injection attempt blocked")
                        continue

                    if os.path.exists(safe_pk_path):
                        with open(safe_pk_path, "rb") as key_f:
                            pk_content = key_f.read()
                            try:
                                pk_obj = serialization.load_ssh_public_key(pk_content)
                                self.accounts[pk_content] = {
                                    "name": acc.get("name"),
                                    "allowed": set(acc.get("allowed", [])),
                                    "forbidden": set(acc.get("forbidden", list(DEFAULT_FORBIDDEN_METHODS))),
                                    "key_obj": pk_obj
                                }
                            except Exception:
                                logging.error(f"Failed to load key for account {acc.get('name')}")
        except Exception as e:
            logging.error("Failed to load accounts")

    def get_account(self, public_key_bytes):
        return self.accounts.get(public_key_bytes)

class NanaRpcProtocol(QuicConnectionProtocol):
    def __init__(self, account_manager, config, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config = config
        self.account_manager = account_manager
        self.db = None
        self.authenticated = False
        self.account_info = None # {"name": ..., "allowed": ..., "forbidden": ...}
        self.challenge = None
        self.client_ip = None
        self.stream_buffers = defaultdict(bytearray)
        self._background_tasks = set()

    def connection_made(self, transport):
        super().connection_made(transport)
        # 堅牢なIP取得ロジック (Cross-platform robustness)
        addr = None
        try:
            # 1. 標準的なpeername
            peername = transport.get_extra_info("peername")
            if peername:
                addr = peername[0]

            # 2. ソケットから直接
            if not addr:
                sock = transport.get_extra_info("socket")
                if sock:
                    addr = sock.getpeername()[0]

            # 3. aioquicの内部情報
            if not addr and hasattr(self._quic, '_peer_cid'):
                addr = self._quic._peer_cid.host_addr
        except Exception:
            logging.debug("Failed to resolve client IP from transport.", exc_info=True)

        self.client_ip = addr or "unknown"
        logging.info(f"New connection from: {self.client_ip}")

    def connection_lost(self, exc):
        self._background_tasks.clear()
        super().connection_lost(exc)

    def quic_event_received(self, event):
        if is_banned(self.client_ip, self.config):
            self.close()
            return

        if isinstance(event, StreamDataReceived):
            # 新規ストリームの場合、同時ストリーム数制限をチェック
            if event.stream_id not in self.stream_buffers and \
               len(self.stream_buffers) >= self.config.get("max_active_streams", 100):
                logging.warning(f"Closing stream {event.stream_id} due to stream limit")
                self._quic.reset_stream(event.stream_id, 0)
                return

            self.stream_buffers[event.stream_id].extend(event.data)
            if len(self.stream_buffers[event.stream_id]) > self.config["max_buffer_size"]:
                self.stream_buffers.pop(event.stream_id)
                self._quic.reset_stream(event.stream_id, 0)
                return

            if event.end_stream:
                data = bytes(self.stream_buffers.pop(event.stream_id))
                task = asyncio.create_task(self.handle_request(event.stream_id, data))
                self._background_tasks.add(task)
                task.add_done_callback(self._background_tasks.discard)

    async def handle_request(self, stream_id, data):
        try:
            try:
                message, _ = protocol.decode_message(data)
            except Exception as e:
                logging.warning(f"Failed to decode message: {e}")
                return

            if message is None: return

            if not self.authenticated:
                if message == "AUTH_START":
                    self.challenge = secrets.token_bytes(32)
                    self._send_response(stream_id, {"type": "challenge", "data": self.challenge})
                    return

                if isinstance(message, dict) and message.get("type") == "response":
                    if self.challenge is None:
                        self._send_response(stream_id, "AUTH_FAILED")
                        return

                    signature = message.get("data")
                    # すべての登録済みアカウントの鍵で検証を試みる
                    found_account = None
                    for info in self.account_manager.accounts.values():
                        try:
                            pk = info.get("key_obj")
                            if pk:
                                pk.verify(signature, self.challenge)
                                found_account = info
                                break
                        except Exception: # nosec B112
                            continue

                    if found_account:
                        self.authenticated = True
                        self.account_info = found_account
                        self.db = get_shared_db(self.config["db_path"])
                        if self.client_ip in failed_attempts:
                            del failed_attempts[self.client_ip]
                        response = "AUTH_OK"
                        logging.info(f"Auth successful: {found_account['name']} from {self.client_ip}")
                    else:
                        is_now_banned = record_failed_attempt(self.client_ip, self.config)
                        response = "AUTH_BANNED" if is_now_banned else "AUTH_FAILED"

                    self._send_response(stream_id, response)
                    return

                self._send_response(stream_id, {"status": "error", "message": "Unauthorized"})
                return

            if self.authenticated:
                if message == "AUTH_START":
                    self._send_response(stream_id, {"status": "error", "message": "Already authenticated"})
                    return
                result = await self.execute_rpc(message)
                self._send_response(stream_id, result)

        except (PermissionError, ValueError, AttributeError, RuntimeError, NanaSQLiteError) as e:
            # クライアントに返しても比較的安全なエラーだが、内容はサニタイズする
            safe_message = str(e)
            # パス情報が含まれやすい文字列を置換
            for forbidden_word in [os.getcwd(), os.sep, "/"]:
                if forbidden_word and len(forbidden_word) > 1:
                    safe_message = safe_message.replace(forbidden_word, "[PATH]")

            self._send_response(stream_id, {
                "status": "error",
                "error_type": type(e).__name__,
                "message": safe_message
            })
        except Exception as e:
            # 予期しないエラーは詳細を隠す (情報漏洩対策)
            logging.error(f"Unexpected error handling request: {e}", exc_info=True)
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

        # 権限チェック (RBAC)
        allowed = self.account_info["allowed"]
        forbidden = self.account_info["forbidden"]

        # 1. 禁止リストチェック (最優先)
        if method_name in forbidden:
            raise PermissionError(f"Method '{method_name}' is forbidden for your account")

        # 2. 許可リストチェック
        if "*" not in allowed and method_name not in allowed:
            # 特殊メソッドの例外処理 (デフォルトでは厳格に制限)
            # 管理者以外はマジックメソッドによる書き込み等を禁止する方向
            allowed_special = {"__getitem__", "__contains__", "__len__"}
            if method_name not in allowed_special:
                raise PermissionError(f"Method '{method_name}' is not allowed for your account")

        # 3. NanaSQLiteに存在するか確認
        if not hasattr(self.db, method_name):
            raise AttributeError(f"NanaSQLite object has no attribute '{method_name}'")

        method = getattr(self.db, method_name)
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            _executor,
            functools.partial(method, *args, **kwargs)
        )
        return {"status": "success", "result": result}

    def _send_response(self, stream_id, data):
        payload = protocol.encode_message(data)
        self._quic.send_stream_data(stream_id, payload, end_stream=True)
        self.transmit()

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default=".env", help="Path to config file")
    args = parser.parse_args()

    # パスインジェクション防止: 設定ファイルのパスを正規化
    config_path = os.path.abspath(args.config)

    # シンプルな設定ロード
    config = DEFAULT_CONFIG.copy()
    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                for line in f:
                    if "=" in line and not line.startswith("#"):
                        parts = line.strip().split("=", 1)
                        if len(parts) == 2:
                            k, v = parts
                            if k in config:
                                if isinstance(config[k], int): config[k] = int(v)
                                else: config[k] = v
        except Exception as e:
            logging.error("Failed to load config file")

    logging.basicConfig(level=logging.INFO)
    account_manager = AccountManager(config["accounts_file"])

    quic_config = QuicConfiguration(is_client=False)
    quic_config.load_cert_chain(config["cert_file"], config["key_file"])

    logging.info(f"Starting NanaSQLite Server on {config['host']}:{config['port']}")
    await serve(
        config["host"], config["port"],
        configuration=quic_config,
        create_protocol=lambda *args, **kwargs: NanaRpcProtocol(account_manager, config, *args, **kwargs)
    )
    await asyncio.Future()

def main_sync():
    try: asyncio.run(main())
    except KeyboardInterrupt: pass

if __name__ == "__main__":
    main_sync()
