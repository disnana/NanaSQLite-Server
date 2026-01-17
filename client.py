import asyncio
import ssl
from typing import TYPE_CHECKING, Any, Dict, Optional, Union
from aioquic.asyncio import QuicConnectionProtocol, connect
from aioquic.quic.configuration import QuicConfiguration
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import protocol

# IDE補完用
if TYPE_CHECKING:
    from nanasqlite import NanaSQLite
    Base = NanaSQLite
else:
    Base = object

PRIVATE_KEY_PATH = "nana_private.pem"

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
    def __init__(self, host="127.0.0.1", port=4433):
        self.host = host
        self.port = port
        self.configuration = QuicConfiguration(
            is_client=True,
            verify_mode=ssl.CERT_NONE,
            server_name="localhost",
        )
        self.connection = None
        
        # 秘密鍵のロード
        try:
            with open(PRIVATE_KEY_PATH, "rb") as f:
                self.private_key = serialization.load_pem_private_key(
                    f.read(), password=None
                )
        except Exception as e:
            print(f"Error loading private key: {e}")
            self.private_key = None

    async def connect(self):
        """サーバーに接続し、Ed25519署名による認証を行う"""
        print(f"Connecting to {self.host}:{self.port}...")
        self._ctx = connect(
            self.host,
            self.port,
            configuration=self.configuration,
            create_protocol=NanaRpcClientProtocol,
        )
        self.connection = await self._ctx.__aenter__()
        print("QUIC Connection established.")
        
        # 1. 認証開始 (チャレンジの要求)
        print("Starting Passkey Authentication...")
        challenge_msg = await self.connection.call_rpc("AUTH_START")
        
        if not isinstance(challenge_msg, dict) or challenge_msg.get("type") != "challenge":
            raise PermissionError(f"Failed to get challenge from server: {challenge_msg}")
        
        challenge_data = challenge_msg.get("data")
        
        # 2. 署名の生成
        signature = self.private_key.sign(challenge_data)
        
        # 3. 署名の送付
        result = await self.connection.call_rpc({"type": "response", "data": signature})
        
        if result == "AUTH_OK":
            print("Authentication successful!")
        else:
            raise PermissionError(f"Authentication failed: {result}")
            
        return self

    def __getattr__(self, name):
        async def rpc_wrapper(*args, **kwargs):
            if not self.connection:
                await self.connect()
            
            request = {"method": name, "args": args, "kwargs": kwargs}
            response = await self.connection.call_rpc(request)
            
            if isinstance(response, dict) and response.get("status") == "error":
                raise RuntimeError(response.get("message"))
            
            return response.get("result") if isinstance(response, dict) else response
        return rpc_wrapper

    async def __setitem__(self, key, value):
        return await self.__getattr__("__setitem__")(key, value)

    async def __getitem__(self, key):
        return await self.__getattr__("__getitem__")(key)

    async def __delitem__(self, key):
        return await self.__getattr__("__delitem__")(key)

    async def close(self):
        if self.connection:
            self.connection.close()
            await self.connection.wait_closed()

# デモ
async def example():
    client = RemoteNanaSQLite()
    try:
        await client.connect()
        print("Setting 'security_test' = 'Passkey Works!'")
        await client.__setitem__("security_test", "Passkey Authentication Success!")
        
        val = await client.__getitem__("security_test")
        print(f"Read back: {val}")
        
    finally:
        await client.close()

if __name__ == "__main__":
    asyncio.run(example())
