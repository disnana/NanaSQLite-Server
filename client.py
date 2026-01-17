import asyncio
import ssl
from typing import TYPE_CHECKING, Any, Dict, Optional, Union
from aioquic.asyncio import QuicConnectionProtocol, connect
from aioquic.quic.configuration import QuicConfiguration
import protocol

# IDE補完（PyCharm等）のためのトリック
if TYPE_CHECKING:
    from nanasqlite import NanaSQLite
    # 実行時は object を継承するが、静的解析時は NanaSQLite を継承しているように見せる
    Base = NanaSQLite
else:
    Base = object

AUTH_TOKEN = "nana-secret-key-2026"

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
    """
    NanaSQLiteのリモートプロキシ。
    PyCharmなどのIDEでは本物のNanaSQLiteとして補完が効きます。
    """
    def __init__(self, host="localhost", port=4433):
        self.host = host
        self.port = port
        self.configuration = QuicConfiguration(
            is_client=True,
            verify_mode=ssl.CERT_NONE,  # 自己署名証明書のため検証スキップ
            server_name="localhost",    # SNIを指定して証明書と一致させる
        )
        self.connection = None

    async def connect(self):
        """サーバーに接続し認証を行う"""
        print(f"Connecting to {self.host}:{self.port}...")
        self._ctx = connect(
            "127.0.0.1",
            self.port,
            configuration=self.configuration,
            create_protocol=NanaRpcClientProtocol,
        )
        self.connection = await self._ctx.__aenter__()
        print("QUIC Connection established.")
        
        # 認証の実行
        print("Authenticating...")
        result = await self.connection.call_rpc(AUTH_TOKEN)
        print(f"Auth result: {result}")

    def __getattr__(self, name):
        """存在しないメソッド（NanaSQLiteの各メソッド）が呼ばれたらRPCに変換する"""
        async def rpc_wrapper(*args, **kwargs):
            if not self.connection:
                await self.connect()
            
            request = {
                "method": name,
                "args": args,
                "kwargs": kwargs
            }
            response = await self.connection.call_rpc(request)
            
            if isinstance(response, dict) and response.get("status") == "error":
                raise RuntimeError(response.get("message"))
            
            return response.get("result") if isinstance(response, dict) else response

        return rpc_wrapper

    async def close(self):
        if self.connection:
            self.connection.close()
            await self.connection.wait_closed()

# 使用例のデモ
async def example():
    client = RemoteNanaSQLite()
    print("Connecting to NanaSQLite Server...")
    await client.connect()

    print("Executing: db['test_key'] = 'Hello QUIC!'")
    # 本来の辞書操作やメソッドが補完付きで呼べる（__setitem__などもRPC化可能だが、今回はメソッド呼び出しを優先）
    await client.set("test_key", "Hello from Client via QUIC!")
    
    val = await client.get("test_key")
    print(f"Result from Server: {val}")

    await client.close()

if __name__ == "__main__":
    asyncio.run(example())
