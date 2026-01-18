import asyncio
import ssl
from typing import TYPE_CHECKING, Any, Dict, Optional, Union
from aioquic.asyncio import QuicConnectionProtocol, connect
from aioquic.quic.configuration import QuicConfiguration
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from . import protocol
import secrets
from colorama import Fore, Back, Style, init

# colorama初期化（全プラットフォーム対応）
init(autoreset=True)

import nanasqlite.exceptions as nana_exc

# IDE補完用
if TYPE_CHECKING:
    from nanasqlite import NanaSQLite
    Base = NanaSQLite
else:
    Base = object

# NanaSQLiteの例外クラスをマッピング
EXCEPTION_MAP = {
    name: obj for name, obj in vars(nana_exc).items()
    if isinstance(obj, type) and issubclass(obj, BaseException)
}
# 一般的なPythonの組み込み例外も追加
import builtins
for _name in ["AttributeError", "TypeError", "ValueError", "KeyError", "RuntimeError", "PermissionError"]:
    EXCEPTION_MAP[_name] = getattr(builtins, _name)

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
    def __init__(self, host="127.0.0.1", port=4433, ca_cert_path="cert.pem", verify_ssl=True):
        """
        RemoteNanaSQLite クライアント
        
        Args:
            host: サーバーホスト
            port: サーバーポート
            ca_cert_path: サーバー証明書のパス (verify_ssl=True時に使用)
            verify_ssl: SSL証明書を検証するか (本番環境ではTrueを推奨)
        """
        self.host = host
        self.port = port
        
        # [FIX 2] SSL証明書検証の設定
        if verify_ssl:
            self.configuration = QuicConfiguration(
                is_client=True,
                verify_mode=ssl.CERT_REQUIRED,
                server_name="localhost",
            )
            # CA証明書をロード
            try:
                self.configuration.load_verify_locations(ca_cert_path)
            except Exception as e:
                print(f"{Fore.YELLOW}Warning: Could not load CA cert: {e}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}Falling back to CERT_NONE (insecure){Style.RESET_ALL}")
                self.configuration = QuicConfiguration(
                    is_client=True,
                    verify_mode=ssl.CERT_NONE,
                    server_name="localhost",
                )
        else:
            # 開発環境用: 証明書検証なし (非推奨)
            print(f"{Fore.YELLOW}Warning: SSL verification disabled (insecure){Style.RESET_ALL}")
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
            print(f"{Fore.RED}Error loading private key: {e}{Style.RESET_ALL}")
            self.private_key = None

    async def connect(self):
        """サーバーに接続し、Ed25519署名による認証を行う"""
        print(f"{Fore.CYAN}Connecting to {self.host}:{self.port}...{Style.RESET_ALL}")
        self._ctx = connect(
            self.host,
            self.port,
            configuration=self.configuration,
            create_protocol=NanaRpcClientProtocol,
        )
        self.connection = await self._ctx.__aenter__()
        print(f"{Fore.GREEN}QUIC Connection established.{Style.RESET_ALL}")

        # 1. 認証開始 (チャレンジの要求)
        print(f"{Fore.YELLOW}Starting Passkey Authentication...{Style.RESET_ALL}")
        challenge_msg = await self.connection.call_rpc("AUTH_START")
        
        if not isinstance(challenge_msg, dict) or challenge_msg.get("type") != "challenge":
            raise PermissionError(f"Failed to get challenge from server: {challenge_msg}")
        
        challenge_data = challenge_msg.get("data")
        
        # 2. 署名の生成
        signature = self.private_key.sign(challenge_data)
        
        # 3. 署名の送付
        result = await self.connection.call_rpc({"type": "response", "data": signature})
        
        if result == "AUTH_OK":
            print(f"{Fore.GREEN}Authentication successful!{Style.RESET_ALL}")
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
                error_type = response.get("error_type")
                message = response.get("message", "Unknown error")
                # サーバー側と同じ例外クラスをインスタンス化して送出
                exc_class = EXCEPTION_MAP.get(error_type, RuntimeError)
                raise exc_class(message)
            
            return response.get("result") if isinstance(response, dict) else response
        return rpc_wrapper

    def __setitem__(self, key, value):
        """同期版の__setitem__ - 実際の使用ではset_item_asyncを使う"""
        raise NotImplementedError("Use 'await set_item_async()' instead")

    def __getitem__(self, key):
        """同期版の__getitem__ - 実際の使用ではget_item_asyncを使う"""
        raise NotImplementedError("Use 'await get_item_async()' instead")

    def __delitem__(self, key):
        """同期版の__delitem__ - 実際の使用ではdel_item_asyncを使う"""
        raise NotImplementedError("Use 'await del_item_async()' instead")

    async def set_item_async(self, key, value):
        """非同期版のsetitem"""
        return await self.__getattr__("__setitem__")(key, value)

    async def get_item_async(self, key):
        """非同期版のgetitem"""
        return await self.__getattr__("__getitem__")(key)

    async def del_item_async(self, key):
        """非同期版のdelitem"""
        return await self.__getattr__("__delitem__")(key)

    async def close(self):
        if self.connection:
            self.connection.close()
            await self.connection.wait_closed()

def random_uuid():
    return secrets.token_hex(16)

# デモ
async def example():
    client = RemoteNanaSQLite(host="127.0.0.1", port=4433)
    try:
        await client.connect()
        print(f"{Fore.MAGENTA}Setting 'security_test' = 'Passkey Works!'{Style.RESET_ALL}")
        rnd_uuid = str(random_uuid())
        temp = f"Passkey Authentication Success! (random_uuid: {rnd_uuid})"
        print(f"{Fore.BLUE}Generated random UUID: {rnd_uuid}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Sending: {temp}{Style.RESET_ALL}")
        await client.set_item_async("security_test", value=temp)
        print(f"{Fore.GREEN}Done!{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Reading back...{Style.RESET_ALL}")
        val = await client.get_item_async("security_test")
        print(f"{Fore.BLUE}Read back: {val}{Style.RESET_ALL}")
        if temp == val:
            print(f"{Fore.GREEN}{Back.BLACK}✓ Success!{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}{Back.BLACK}✗ Failed!{Style.RESET_ALL}")
    finally:
        await client.close()

if __name__ == "__main__":
    asyncio.run(example())
