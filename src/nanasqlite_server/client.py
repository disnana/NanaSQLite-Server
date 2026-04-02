import asyncio
import base64
import builtins
import json
import secrets
import ssl
from typing import TYPE_CHECKING

import nanasqlite.exceptions as nana_exc
from aioquic.asyncio import QuicConnectionProtocol, connect
from aioquic.quic.configuration import QuicConfiguration
from colorama import Fore, Back, Style, init
from cryptography.hazmat.primitives import serialization

from . import protocol

# colorama初期化（全プラットフォーム対応）
init(autoreset=True)

# IDE補完用
if TYPE_CHECKING:
    from nanasqlite import NanaSQLite

    class Base(NanaSQLite): ...
else:
    Base = object

# liboqs-python サポート (オプション: pip install liboqs-python)
# 耐量子暗号 (PQC) による認証署名を有効にする
try:
    import oqs  # type: ignore[import]

    HAS_OQS = True
except ImportError:
    oqs = None  # type: ignore[assignment]
    HAS_OQS = False

# NanaSQLiteの例外クラスをマッピング
EXCEPTION_MAP = {
    name: obj
    for name, obj in vars(nana_exc).items()
    if isinstance(obj, type) and issubclass(obj, BaseException)
}
# 一般的なPythonの組み込み例外も追加
for _name in [
    "AttributeError",
    "TypeError",
    "ValueError",
    "KeyError",
    "RuntimeError",
    "PermissionError",
]:
    EXCEPTION_MAP[_name] = getattr(builtins, _name)

PRIVATE_KEY_PATH = "nana_private.pem"
PQC_PRIVATE_KEY_PATH = "nana_private_pqc.json"


class NanaRpcClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._responses = asyncio.Queue()
        self.session_key = None  # KEM後に導出されたAES-256セッション鍵

    def quic_event_received(self, event):
        from aioquic.quic.events import StreamDataReceived

        if isinstance(event, StreamDataReceived):
            if self.session_key:
                message, _ = protocol.decrypt_message(event.data, self.session_key)
            else:
                message, _ = protocol.decode_message(event.data)
            self._responses.put_nowait(message)

    async def call_rpc(self, data):
        stream_id = self._quic.get_next_available_stream_id()
        if self.session_key:
            payload = protocol.encrypt_message(data, self.session_key)
        else:
            payload = protocol.encode_message(data)
        self._quic.send_stream_data(stream_id, payload, end_stream=True)
        self.transmit()
        return await self._responses.get()


class RemoteNanaSQLite(Base):
    def __init__(
        self, host="127.0.0.1", port=4433, ca_cert_path="cert.pem", verify_ssl=True,
        private_key_path=PRIVATE_KEY_PATH, pqc_key_path=None,
    ):
        """
        RemoteNanaSQLite クライアント

        Args:
            host: サーバーホスト
            port: サーバーポート
            ca_cert_path: サーバー証明書のパス (verify_ssl=True時に使用)
            verify_ssl: SSL証明書を検証するか (本番環境ではTrueを推奨)
            private_key_path: Ed25519秘密鍵ファイルのパス (デフォルト: nana_private.pem)
            pqc_key_path: OQS PQC秘密鍵JSONファイルのパス (指定時はPQC認証を使用)
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
                print(
                    f"{Fore.YELLOW}Warning: Could not load CA cert: {e}{Style.RESET_ALL}"
                )
                print(
                    f"{Fore.YELLOW}Falling back to CERT_NONE (insecure){Style.RESET_ALL}"
                )
                self.configuration = QuicConfiguration(
                    is_client=True,
                    verify_mode=ssl.CERT_NONE,
                    server_name="localhost",
                )
        else:
            # 開発環境用: 証明書検証なし (非推奨)
            print(
                f"{Fore.YELLOW}Warning: SSL verification disabled (insecure){Style.RESET_ALL}"
            )
            self.configuration = QuicConfiguration(
                is_client=True,
                verify_mode=ssl.CERT_NONE,
                server_name="localhost",
            )

        self.connection = None

        # PQC秘密鍵のロード (指定された場合)
        self._pqc_secret_key_bytes = None
        self._pqc_algorithm = None
        if pqc_key_path:
            if not HAS_OQS:
                print(
                    f"{Fore.RED}Error: PQC key specified but liboqs-python is not installed. "
                    f"Install with: pip install liboqs-python{Style.RESET_ALL}"
                )
            else:
                try:
                    with open(pqc_key_path, "r") as f:
                        pqc_key_data = json.load(f)
                    self._pqc_algorithm = pqc_key_data["algorithm"]
                    self._pqc_secret_key_bytes = base64.b64decode(pqc_key_data["secret_key"])
                    print(
                        f"{Fore.CYAN}PQC key loaded: {self._pqc_algorithm}{Style.RESET_ALL}"
                    )
                except Exception as e:
                    print(f"{Fore.RED}Error loading PQC key: {e}{Style.RESET_ALL}")
                    self._pqc_secret_key_bytes = None
                    self._pqc_algorithm = None

        # Ed25519秘密鍵のロード (PQCキーが未指定または失敗した場合)
        self.private_key = None
        if not self._pqc_secret_key_bytes:
            try:
                with open(private_key_path, "rb") as f:
                    self.private_key = serialization.load_pem_private_key(
                        f.read(), password=None
                    )
            except Exception as e:
                print(f"{Fore.RED}Error loading private key: {e}{Style.RESET_ALL}")

    async def connect(self, account_name=None):
        """サーバーに接続し、Ed25519またはOQS PQC署名による認証を行う。
        
        認証成功後にサーバーがPQC KEM交換を提示した場合は、
        自動的にKEM鍵交換を行い、AES-256-GCMでの通信暗号化を確立する。
        """
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
        auth_mode = (
            f"PQC ({self._pqc_algorithm})"
            if self._pqc_secret_key_bytes
            else "Ed25519 Passkey"
        )
        print(f"{Fore.YELLOW}Starting {auth_mode} Authentication...{Style.RESET_ALL}")
        challenge_msg = await self.connection.call_rpc("AUTH_START")

        if (
            not isinstance(challenge_msg, dict)
            or challenge_msg.get("type") != "challenge"
        ):
            raise PermissionError(
                f"Failed to get challenge from server: {challenge_msg}"
            )

        challenge_data = challenge_msg.get("data")

        # 2. 署名の生成 (PQC または Ed25519)
        if self._pqc_secret_key_bytes and HAS_OQS:
            with oqs.Signature(self._pqc_algorithm, self._pqc_secret_key_bytes) as signer:
                signature = signer.sign(challenge_data)
        else:
            signature = self.private_key.sign(challenge_data)

        # 3. 署名の送付 (アカウント名ヒントがあれば含める)
        auth_response = {"type": "response", "data": signature}
        if account_name:
            auth_response["account"] = account_name

        result = await self.connection.call_rpc(auth_response)

        # 4. 認証結果を処理 (KEM交換を含む可能性あり)
        if result == "AUTH_OK":
            # レガシーサーバーまたは --pqc-kem なしのサーバー
            print(f"{Fore.GREEN}Authentication successful!{Style.RESET_ALL}")
        elif isinstance(result, dict) and result.get("type") == "auth_ok":
            kem_info = result.get("kem")
            if kem_info and HAS_OQS:
                # PQC KEM 鍵交換を実施
                algorithm = kem_info["algorithm"]
                server_pubkey = kem_info["public_key"]
                print(
                    f"{Fore.YELLOW}Performing PQC KEM key exchange "
                    f"({algorithm})...{Style.RESET_ALL}"
                )
                with oqs.KeyEncapsulation(algorithm) as kem:
                    ciphertext, shared_secret = kem.encap_secret(server_pubkey)
                session_key = protocol.derive_session_key(shared_secret)

                kem_ack = await self.connection.call_rpc(
                    {"type": "kem_response", "ciphertext": ciphertext}
                )
                if kem_ack == "KEM_OK":
                    self.connection.session_key = session_key
                    print(
                        f"{Fore.GREEN}PQC session key established ({algorithm}). "
                        f"All subsequent communication is encrypted with "
                        f"AES-256-GCM!{Style.RESET_ALL}"
                    )
                else:
                    raise PermissionError(f"KEM exchange failed: {kem_ack}")
            elif kem_info and not HAS_OQS:
                print(
                    f"{Fore.YELLOW}Warning: Server offered PQC KEM ({kem_info.get('algorithm')}) "
                    f"but liboqs-python is not installed. "
                    f"Communication will proceed without session encryption. "
                    f"Install liboqs-python to enable encrypted sessions.{Style.RESET_ALL}"
                )
            print(f"{Fore.GREEN}Authentication successful!{Style.RESET_ALL}")
        else:
            raise PermissionError(f"Authentication failed: {result}")

        return self

    def __getattr__(self, name):
        async def rpc_wrapper(*args, **kwargs):
            if not self.connection:
                await self.connect()

            # db引数があればRPCメッセージのトップレベルに移す
            db = kwargs.pop("db", None)
            request = {"method": name, "args": args, "kwargs": kwargs}
            if db:
                request["db"] = db

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

    async def set_item_async(self, key, value, db=None):
        """非同期版のsetitem"""
        return await self.__getattr__("__setitem__")(key, value, db=db)

    async def get_item_async(self, key, db=None):
        """非同期版のgetitem"""
        return await self.__getattr__("__getitem__")(key, db=db)

    async def del_item_async(self, key, db=None):
        """非同期版のdelitem"""
        return await self.__getattr__("__delitem__")(key, db=db)

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
        print(
            f"{Fore.MAGENTA}Setting 'security_test' = 'Passkey Works!'{Style.RESET_ALL}"
        )
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
