import asyncio
import builtins
import ssl
from typing import TYPE_CHECKING

import nanasqlite.exceptions as nana_exc
from aioquic.asyncio import QuicConnectionProtocol, connect
from aioquic.quic.configuration import QuicConfiguration
from colorama import Fore, Style, init
from cryptography.hazmat.primitives import serialization

from . import protocol

# Initialize colorama for cross-platform support
init(autoreset=True)

# IDE completion support
if TYPE_CHECKING:
    from nanasqlite import NanaSQLite
    class Base(NanaSQLite): ...
else:
    Base = object

# Exception mapping
EXCEPTION_MAP = {
    name: obj for name, obj in vars(nana_exc).items()
    if isinstance(obj, type) and issubclass(obj, BaseException)
}
for _name in ["AttributeError", "TypeError", "ValueError", "KeyError", "RuntimeError", "PermissionError"]:
    EXCEPTION_MAP[_name] = getattr(builtins, _name)

class NanaRpcClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._responses = asyncio.Queue()

    def quic_event_received(self, event):
        from aioquic.quic.events import StreamDataReceived
        if isinstance(event, StreamDataReceived):
            message, _ = protocol.decode_message(event.data)
            self._responses.put_nowait(message)

    async def call_rpc(self, data):
        stream_id = self._quic.get_next_available_stream_id()
        payload = protocol.encode_message(data)
        self._quic.send_stream_data(stream_id, payload, end_stream=True)
        self.transmit()
        return await self._responses.get()

class RemoteNanaSQLite(Base):
    def __init__(self, host="127.0.0.1", port=4433, ca_cert_path="cert.pem",
                 private_key_path="nana_private.pem", verify_ssl=True):
        """
        RemoteNanaSQLite Client (RBAC-compatible)
        
        Args:
            host: Server host
            port: Server port
            ca_cert_path: Path to CA certificate
            private_key_path: Path to client private key (PEM format)
            verify_ssl: Whether to verify SSL certificate
        """
        self.host = host
        self.port = port
        self.private_key_path = private_key_path
        
        if verify_ssl:
            self.configuration = QuicConfiguration(
                is_client=True,
                verify_mode=ssl.CERT_REQUIRED,
                server_name="localhost",
            )
            try:
                self.configuration.load_verify_locations(ca_cert_path)
            except Exception as e:
                print(f"{Fore.YELLOW}Warning: Could not load CA cert: {e}. Insecure fallback.{Style.RESET_ALL}")
                self.configuration.verify_mode = ssl.CERT_NONE
        else:
            self.configuration = QuicConfiguration(
                is_client=True,
                verify_mode=ssl.CERT_NONE,
                server_name="localhost",
            )
        
        self.connection = None
        self.private_key = None

    def _load_private_key(self):
        try:
            with open(self.private_key_path, "rb") as f:
                return serialization.load_pem_private_key(f.read(), password=None)
        except Exception as e:
            raise RuntimeError(f"Failed to load private key from {self.private_key_path}: {e}")

    async def connect(self, username="admin", db="default"):
        """
        Connect to server and authenticate using RBAC flow.
        """
        if not self.private_key:
            self.private_key = self._load_private_key()

        self._ctx = connect(
            self.host,
            self.port,
            configuration=self.configuration,
            create_protocol=NanaRpcClientProtocol,
        )
        self.connection = await self._ctx.__aenter__()

        # Auth Phase 1: Request Challenge
        auth_start = {"type": "AUTH_START", "username": username}
        challenge_msg = await self.connection.call_rpc(auth_start)
        
        if not isinstance(challenge_msg, dict) or challenge_msg.get("type") != "challenge":
            raise PermissionError(f"Auth failed (Phase 1): {challenge_msg}")
        
        challenge_data = challenge_msg.get("data")
        
        # Auth Phase 2: Sign Challenge
        signature = self.private_key.sign(challenge_data)
        result = await self.connection.call_rpc({
            "type": "response",
            "data": signature,
            "db": db
        })
        
        if result == "AUTH_OK":
            print(f"{Fore.GREEN}Authenticated as '{username}' on DB '{db}'{Style.RESET_ALL}")
        else:
            raise PermissionError(f"Auth failed (Phase 2): {result}")
            
        return self

    def __getattr__(self, name):
        async def rpc_wrapper(*args, **kwargs):
            if not self.connection:
                await self.connect()
            
            request = {"method": name, "args": args, "kwargs": kwargs}
            response = await self.connection.call_rpc(request)
            
            if isinstance(response, dict) and response.get("status") == "error":
                error_type = response.get("error_type")
                message = response.get("message", "Unknown error")
                exc_class = EXCEPTION_MAP.get(error_type, RuntimeError)
                raise exc_class(message)
            
            return response.get("result") if isinstance(response, dict) else response
        return rpc_wrapper

    async def close(self):
        if self.connection:
            self.connection.close()
            await self.connection.wait_closed()

    # Async helpers for magic methods
    async def set_item_async(self, key, value):
        return await self.__getattr__("__setitem__")(key, value)

    async def get_item_async(self, key):
        return await self.__getattr__("__getitem__")(key)

    async def del_item_async(self, key):
        return await self.__getattr__("__delitem__")(key)

    async def contains_async(self, key):
        return await self.__getattr__("__contains__")(key)

    async def len_async(self):
        return await self.__getattr__("__len__")()
