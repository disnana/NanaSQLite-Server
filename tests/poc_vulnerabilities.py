import asyncio
import ssl
import pytest
from nanasqlite_server.client import RemoteNanaSQLite
from nanasqlite_server import protocol
from aioquic.asyncio import connect, QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived
import ormsgpack
import os

PORT = int(os.environ.get("NANASQLITE_TEST_PORT", 4433))

class RawTestClient(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._responses = asyncio.Queue()

    def quic_event_received(self, event):
        if isinstance(event, StreamDataReceived):
            message, _ = protocol.decode_message(event.data)
            self._responses.put_nowait(message)

    async def send_raw(self, data):
        stream_id = self._quic.get_next_available_stream_id()
        payload = protocol.encode_message(data)
        self._quic.send_stream_data(stream_id, payload, end_stream=True)
        self.transmit()
        return await asyncio.wait_for(self._responses.get(), timeout=5.0)

async def get_raw_connection():
    configuration = QuicConfiguration(is_client=True, verify_mode=ssl.CERT_NONE)
    async with connect("127.0.0.1", PORT, configuration=configuration, create_protocol=RawTestClient) as client:
        return client

@pytest.mark.asyncio
async def test_poc_auth_bypass_dangerous_methods():
    """FORBIDDEN_METHODSにない危険なメソッドの呼び出しを試行"""
    client = RemoteNanaSQLite(host="127.0.0.1", port=PORT, verify_ssl=False)
    await client.connect()
    try:
        # 'drop_table' は FORBIDDEN_METHODS に含まれていない
        # (ただし dir(NanaSQLite) には含まれているため、現在の動的保護では許可されるはず)
        print("\n[PoC] Attempting to call 'drop_table' (should be forbidden but likely isn't)...")
        try:
            result = await client.drop_table("non_existent_table")
            print(f"Result: {result}")
        except Exception as e:
            print(f"Caught expected/unexpected error: {e}")
            # もし PermissionError なら防げている、AttributeError ならテーブルがないだけ
            if "forbidden" in str(e).lower():
                print("✓ Success: Method was forbidden.")
            else:
                print(f"✗ Failure: Method was NOT forbidden (Error: {e})")

        # 'clear' メソッド
        print("[PoC] Attempting to call 'clear'...")
        try:
            await client.clear()
            print("✗ Failure: Method 'clear' was executed!")
        except Exception as e:
            if "forbidden" in str(e).lower():
                print("✓ Success: Method 'clear' was forbidden.")
            else:
                print(f"Result: {e}")
    finally:
        await client.close()

@pytest.mark.asyncio
async def test_poc_dos_large_payload():
    """認証前の巨大ペイロード送信によるリソース枯渇の検証"""
    print("\n[PoC] Sending large payload before authentication...")
    configuration = QuicConfiguration(is_client=True, verify_mode=ssl.CERT_NONE)
    async with connect("127.0.0.1", PORT, configuration=configuration, create_protocol=RawTestClient) as conn:
        # 10MB制限ギリギリまたは超えるデータを送信
        large_data = "A" * (10 * 1024 * 1024 + 100)
        try:
            # 直接エンコードして送信（AUTH_STARTを無視）
            payload = protocol.encode_message(large_data)
            stream_id = conn._quic.get_next_available_stream_id()
            conn._quic.send_stream_data(stream_id, payload, end_stream=True)
            conn.transmit()
            print("Sent ~10MB payload. Waiting for response or disconnection...")
            await asyncio.sleep(2)
        except Exception as e:
            print(f"Connection closed or error: {e}")

@pytest.mark.asyncio
async def test_poc_info_disclosure_traceback():
    """意図的なエラーによるスタックトレース等の情報漏洩の検証"""
    print("\n[PoC] Attempting to leak info via invalid RPC call...")
    client = RemoteNanaSQLite(host="127.0.0.1", port=PORT, verify_ssl=False)
    await client.connect()
    try:
        # 存在しないメソッドの呼び出し
        try:
            await client.this_method_does_not_exist()
        except Exception as e:
            print(f"Error message: {e}")
            if "/" in str(e) or "\\" in str(e) or "File" in str(e):
                print("✗ Failure: Possible path or traceback leak detected!")
            else:
                print("✓ Success: Error message seems sanitized.")

        # 不正な引数
        try:
            await client.get_item_async(key=None)
        except Exception as e:
            print(f"Error message with invalid args: {e}")

    finally:
        await client.close()

@pytest.mark.asyncio
async def test_poc_ormsgpack_unexpected_type():
    """ormsgpackに予期しない型を送り込む(DoSまたは例外の検証)"""
    print("\n[PoC] Sending unexpected types to ormsgpack...")
    configuration = QuicConfiguration(is_client=True, verify_mode=ssl.CERT_NONE)
    async with connect("127.0.0.1", PORT, configuration=configuration, create_protocol=RawTestClient) as conn:
        # packbできるが受け側で期待しない型（例：巨大な整数やリストの入れ子）
        nested_data = [1] * 1000
        for _ in range(10): nested_data = [nested_data]

        try:
            result = await conn.send_raw(nested_data)
            print(f"Server response to nested data: {result}")
        except Exception as e:
            print(f"Server behavior on nested data: {e}")
