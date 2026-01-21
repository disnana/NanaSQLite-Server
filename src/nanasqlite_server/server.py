import asyncio
import logging
import secrets
import time
import functools
import json
import os
import argparse
import re
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict
from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived
from cryptography.hazmat.primitives import serialization
from nanasqlite import NanaSQLite
from nanasqlite.exceptions import NanaSQLiteError
from . import protocol

# --- Security & Logging ---

def safe_log(msg: str):
    """
    Prevents Log Injection by neutralizing CRLF characters.
    """
    sanitized = msg.replace('\n', '\\n').replace('\r', '\\r')
    logging.info(sanitized)

# --- Configuration ---

class ServerConfig:
    def __init__(self):
        self.port = 4433
        self.host = "127.0.0.1"
        self.public_key_path = "nana_public.pub"
        self.cert_path = "cert.pem"
        self.key_path = "key.pem"
        self.db_dir = "./data"
        self.accounts_path = "accounts.json"
        self.ban_duration = 900
        self.max_failed_attempts = 3
        self.max_buffer_size = 10 * 1024 * 1024
        self.max_ban_list_size = 10000

    @classmethod
    def load(cls, path):
        config = cls()
        if os.path.exists(path):
            with open(path, "r") as f:
                data = json.load(f)
                for k, v in data.items():
                    if hasattr(config, k):
                        setattr(config, k, v)
        return config

# --- RBAC & Account Management ---

class AccountManager:
    def __init__(self, accounts_path):
        self.accounts_path = accounts_path
        self.accounts = {}
        self.load_accounts()

    def load_accounts(self):
        if os.path.exists(self.accounts_path):
            try:
                with open(self.accounts_path, "r") as f:
                    self.accounts = json.load(f)
            except Exception as e:
                safe_log(f"Failed to load accounts: {e}")
                self.accounts = {}
        else:
            # Default fallback for testing if no account file exists
            self.accounts = {
                "admin": {"role": "admin", "public_key": "nana_public.pub"}
            }

    def get_account(self, username):
        return self.accounts.get(username)

    def verify_permission(self, role, method_name):
        if role == "admin":
            return True
        if role == "readonly":
            # Allow basic read operations. load_all is allowed here.
            return method_name in {"load_all", "get", "__getitem__", "__contains__", "__len__"}
        return False

# --- Global State ---

_executor = ThreadPoolExecutor(max_workers=4)
failed_attempts = {}
ban_list = {}
_db_instances = {}

# Absolute No List (Methods that should NEVER be called via RPC)
FORBIDDEN_METHODS = {
    "__init__", "close", "vacuum", "pragma", "execute", "execute_many",
    "query", "sql_insert", "sql_update", "sql_delete", "transaction",
    "begin_transaction", "commit", "rollback", "open", "connect",
    "get_model", "set_model", "refresh"
}

def is_banned(ip, config):
    now = time.time()
    expired_bans = [addr for addr, expire in ban_list.items() if now >= expire]
    for addr in expired_bans:
        del ban_list[addr]
        if addr in failed_attempts:
            del failed_attempts[addr]
    return ip in ban_list

def record_failed_attempt(ip, config):
    if len(failed_attempts) > config.max_ban_list_size:
        failed_attempts.clear()
    failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
    if failed_attempts[ip] >= config.max_failed_attempts:
        if len(ban_list) < config.max_ban_list_size:
            ban_list[ip] = time.time() + config.ban_duration
            safe_log(f"IP {ip} BANNED")
        return True
    return False

def get_db(db_name, db_dir):
    if not re.match(r"^[a-zA-Z0-9_\-\.]+$", db_name) or ".." in db_name:
        raise ValueError("Invalid database name")
    if db_name not in _db_instances:
        if not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
        db_path = os.path.join(db_dir, f"{db_name}.sqlite")
        _db_instances[db_name] = NanaSQLite(db_path, bulk_load=True)
    return _db_instances[db_name]

# --- Protocol ---

class NanaRpcProtocol(QuicConnectionProtocol):
    def __init__(self, config, account_manager, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config = config
        self.account_manager = account_manager
        self.db = None
        self.authenticated = False
        self.user_role = None
        self.challenge = None
        self.client_ip = None
        self.stream_buffers = defaultdict(bytearray)
        # Store task references to prevent premature GC in Python 3.13+
        self._background_tasks = set()

    def connection_made(self, transport):
        super().connection_made(transport)
        addr = None
        try:
            peername = transport.get_extra_info("peername")
            if peername:
                addr = peername[0]
            if not addr:
                sock = transport.get_extra_info("socket")
                if sock:
                    addr = sock.getpeername()[0]
            if not addr and hasattr(self._quic, '_peer_cid'):
                addr = self._quic._peer_cid.host_addr
        except Exception as e:
            logging.debug("Could not resolve client IP: %s", e)
        self.client_ip = addr or "unknown"
        safe_log(f"Connection from: {self.client_ip}")

    def connection_lost(self, exc):
        """Clean up background tasks when connection is lost
        
        Clear task references when connection terminates. Tasks that are
        still running will continue to completion naturally.
        """
        self._background_tasks.clear()
        super().connection_lost(exc)

    def quic_event_received(self, event):
        if is_banned(self.client_ip, self.config):
            self.close()
            return
        if isinstance(event, StreamDataReceived):
            self.stream_buffers[event.stream_id].extend(event.data)
            if len(self.stream_buffers[event.stream_id]) > self.config.max_buffer_size:
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
            message, _ = protocol.decode_message(data)
            if message is None:
                return
            if not self.authenticated:
                # Auth Phase 1: Challenge request
                if message == "AUTH_START" or (isinstance(message, dict) and message.get("type") == "AUTH_START"):
                    username = "admin"
                    if isinstance(message, dict):
                        username = message.get("username", "admin")

                    account = self.account_manager.get_account(username)
                    if not account:
                        self._send_response(stream_id, "AUTH_FAILED")
                        return
                    self.current_user = username
                    self.challenge = secrets.token_bytes(32)
                    self._send_response(stream_id, {"type": "challenge", "data": self.challenge})
                    return
                # Auth Phase 2: Signature verification
                if isinstance(message, dict) and message.get("type") == "response":
                    if self.challenge is None or not hasattr(self, 'current_user'):
                        self._send_response(stream_id, "AUTH_FAILED")
                        return
                    account = self.account_manager.get_account(self.current_user)
                    pub_key_path = account.get("public_key")
                    try:
                        with open(pub_key_path, "rb") as f:
                            public_key = serialization.load_ssh_public_key(f.read())
                        public_key.verify(message.get("data"), self.challenge)
                        self.authenticated = True
                        self.user_role = account.get("role", "readonly")
                        db_name = message.get("db", "default")
                        self.db = get_db(db_name, self.config.db_dir)
                        if self.client_ip in failed_attempts:
                            del failed_attempts[self.client_ip]
                        self._send_response(stream_id, "AUTH_OK")
                        safe_log(f"Auth Success: {self.current_user} ({self.user_role}) from {self.client_ip}")
                    except Exception as e:
                        safe_log(f"Auth Failed: {self.client_ip} - {e}")
                        if record_failed_attempt(self.client_ip, self.config):
                            self._send_response(stream_id, "AUTH_BANNED")
                        else:
                            self._send_response(stream_id, "AUTH_FAILED")
                    return
                self._send_response(stream_id, {"status": "error", "message": "Unauthorized"})
                return

            # RPC Execution
            # [FIX] Handle legacy "AUTH_START" message in authenticated state
            if message == "AUTH_START" or (isinstance(message, dict) and message.get("type") == "AUTH_START"):
                self._send_response(stream_id, {"status": "error", "message": "Already authenticated"})
                return

            result = await self.execute_rpc(message)
            self._send_response(stream_id, result)
        except (PermissionError, ValueError, AttributeError, NanaSQLiteError) as e:
            self._send_response(stream_id, {
                "status": "error",
                "error_type": type(e).__name__,
                "message": str(e)
            })
        except Exception as e:
            safe_log(f"Internal Error: {e}")
            self._send_response(stream_id, {
                "status": "error",
                "error_type": "InternalServerError",
                "message": "An unexpected error occurred"
            })

    async def execute_rpc(self, message):
        if not isinstance(message, dict):
            raise ValueError("Invalid RPC format")
        method_name = str(message.get("method"))
        args = message.get("args", [])
        kwargs = message.get("kwargs", {})

        # Absolute Blacklist Check FIRST
        if method_name in FORBIDDEN_METHODS:
            raise PermissionError(f"Method '{method_name}' is globally forbidden")

        # RBAC Check SECOND
        if not self.account_manager.verify_permission(self.user_role, method_name):
            raise PermissionError(f"Role '{self.user_role}' lacks permission for '{method_name}'")

        if hasattr(self.db, method_name):
            method = getattr(self.db, method_name)
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                _executor,
                functools.partial(method, *args, **kwargs)
            )
            return {"status": "success", "result": result}
        else:
            raise AttributeError(f"Method '{method_name}' not found")

    def _send_response(self, stream_id, data):
        payload = protocol.encode_message(data)
        self._quic.send_stream_data(stream_id, payload, end_stream=True)
        self.transmit()

def main_sync():
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass

async def main():
    parser = argparse.ArgumentParser(description="NanaSQLite Next-Gen Server")
    parser.add_argument("--config", type=str, default="config.json", help="Path to config file")
    parser.add_argument("--port", type=int, help="Override port")
    args = parser.parse_args()

    config = ServerConfig.load(args.config)
    if args.port:
        config.port = args.port

    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    account_manager = AccountManager(config.accounts_path)

    quic_config = QuicConfiguration(is_client=False)
    quic_config.load_cert_chain(config.cert_path, config.key_path)

    safe_log(f"Starting server on {config.host}:{config.port}")

    await serve(
        config.host,
        config.port,
        configuration=quic_config,
        create_protocol=lambda *args, **kwargs: NanaRpcProtocol(
            config, account_manager, *args, **kwargs
        ),
    )
    await asyncio.Future()

if __name__ == "__main__":
    main_sync()
