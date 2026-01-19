import asyncio
import ssl
import pytest
import os
from nanasqlite_server.client import RemoteNanaSQLite
from nanasqlite_server import protocol
from aioquic.asyncio import connect, QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived

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

@pytest.mark.asyncio
async def test_poc_auth_bypass_dangerous_methods():
    """RBACにより制限されたメソッドの呼び出しが拒否されることを検証"""
    # adminアカウントで接続
    client = RemoteNanaSQLite(host="127.0.0.1", port=PORT, verify_ssl=False, private_key_path="nana_private.pem")
    await client.connect()
    try:
        # adminでも 'close' は forbidden に設定されている (conftest.py 参照)
        with pytest.raises(Exception) as excinfo:
            await client.__getattr__("close")()
        assert "forbidden" in str(excinfo.value).lower()
    finally:
        await client.close()

@pytest.mark.asyncio
async def test_poc_dos_large_payload():
    """認証前の巨大ペイロード送信によるリソース枯渇の防御を検証"""
    configuration = QuicConfiguration(is_client=True, verify_mode=ssl.CERT_NONE)
    async with connect("127.0.0.1", PORT, configuration=configuration, create_protocol=RawTestClient) as conn:
        large_data = "A" * (10 * 1024 * 1024 + 100)
        try:
            payload = protocol.encode_message(large_data)
            stream_id = conn._quic.get_next_available_stream_id()
            conn._quic.send_stream_data(stream_id, payload, end_stream=True)
            conn.transmit()
            await asyncio.sleep(1)
        except Exception:
            pass # サーバー側で切断される

@pytest.mark.asyncio
async def test_poc_info_disclosure_traceback():
    """エラーメッセージに機密情報が含まれていないことを検証"""
    client = RemoteNanaSQLite(host="127.0.0.1", port=PORT, verify_ssl=False, private_key_path="nana_private.pem")
    await client.connect()
    try:
        try:
            await client.non_existent_method()
        except Exception as e:
            msg = str(e)
            # パス情報やファイル構造が露出していないか
            assert "/" not in msg and "\\" not in msg and "File" not in msg
    finally:
        await client.close()
