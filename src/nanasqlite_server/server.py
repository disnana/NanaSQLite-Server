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
    "max_ban_list_size": 10000,
    "max_buffer_size": 10 * 1024 * 1024, # 10MB
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
        self.accounts = {} # {public_key_bytes: {"name": str, "allowed": set, "forbidden": set}}
        self.load_accounts(accounts_file)

    def load_accounts(self, filepath):
        """アカウント設定をロードする。パストラバーサル防止のため、鍵パスはベースディレクトリ内で解決する。"""
        base_dir = os.path.dirname(os.path.abspath(filepath))

        if not os.path.exists(filepath):
            logging.warning(f"Accounts file {filepath} not found. Using default admin key if available.")
            # デフォルトアカウント（nana_public.pubがあれば）
            if os.path.exists("nana_public.pub"):
                try:
                    with open("nana_public.pub", "rb") as f:
                        pk_bytes = f.read()
                        serialization.load_ssh_public_key(pk_bytes) # 有効性確認
                        self.accounts[pk_bytes] = {
                            "name": "default_admin",
                            "allowed": ["*"],
                            "forbidden": list(DEFAULT_FORBIDDEN_METHODS)
                        }
                except Exception as e:
                    logging.error(f"Failed to load default admin key: {e}")
            return

        try:
            with open(filepath, "r") as f:
                data = json.load(f)
                for acc in data:
                    pk_path = acc.get("public_key_path")
                    if not pk_path: continue

                    # パストラバーサル防止: ベース名のみを使用するか、絶対パスへの正規化とチェックを行う
                    # ここでは、設定ファイルのディレクトリを基準とした安全なパス解決を行う
                    safe_pk_path = os.path.abspath(os.path.join(base_dir, pk_path))
                    if not safe_pk_path.startswith(base_dir) and not os.path.exists(pk_path):
                        # カレントディレクトリにある場合も許容（後方互換性のため）
                        safe_pk_path = os.path.abspath(pk_path)

                    if os.path.exists(safe_pk_path):
                        with open(safe_pk_path, "rb") as key_f:
                            pk_content = key_f.read()
                            self.accounts[pk_content] = {
                                "name": acc.get("name"),
                                "allowed": set(acc.get("allowed", [])),
                                "forbidden": set(acc.get("forbidden", list(DEFAULT_FORBIDDEN_METHODS)))
                            }
        except Exception as e:
            logging.error(f"Failed to load accounts from {filepath}: {e}")

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
                    for pk_bytes, info in self.account_manager.accounts.items():
                        try:
                            pk = serialization.load_ssh_public_key(pk_bytes)
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
            # クライアントに返しても安全なエラー
            self._send_response(stream_id, {
                "status": "error",
                "error_type": type(e).__name__,
                "message": str(e)
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
            # 特殊メソッドの例外処理 (必要に応じて)
            allowed_special = {"__getitem__", "__setitem__", "__delitem__", "__contains__", "__len__"}
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

    # シンプルな設定ロード (本来はpython-dotenv等を使うのが望ましいが、標準ライブラリ+αで実装)
    config = DEFAULT_CONFIG.copy()
    if os.path.exists(args.config):
        with open(args.config, "r") as f:
            for line in f:
                if "=" in line and not line.startswith("#"):
                    k, v = line.strip().split("=", 1)
                    if k in config:
                        if isinstance(config[k], int): config[k] = int(v)
                        else: config[k] = v

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
