import asyncio
import pytest
import ssl
from aioquic.asyncio import QuicConnectionProtocol, connect
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived
from cryptography.hazmat.primitives import serialization
from nanasqlite_server import protocol

class FragClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._responses = asyncio.Queue()

    def quic_event_received(self, event):
        if isinstance(event, StreamDataReceived):
            message, _ = protocol.decode_message(event.data)
            self._responses.put_nowait(message)

    async def send_fragmented(self, data):
        stream_id = self._quic.get_next_available_stream_id()
        payload = protocol.encode_message(data)

        # Split into two parts
        mid = len(payload) // 2
        part1 = payload[:mid]
        part2 = payload[mid:]

        self._quic.send_stream_data(stream_id, part1, end_stream=False)
        self.transmit()
        await asyncio.sleep(0.1) # Ensure separate packets
        self._quic.send_stream_data(stream_id, part2, end_stream=True)
        self.transmit()

        return await asyncio.wait_for(self._responses.get(), timeout=5.0)

@pytest.mark.asyncio
async def test_fragmentation(server_factory, certs):
    config = await server_factory()

    with open(certs["priv"], "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    configuration = QuicConfiguration(
        is_client=True,
        verify_mode=ssl.CERT_NONE,
        server_name="localhost",
    )

    async with connect(config.host, config.port, configuration=configuration, create_protocol=FragClientProtocol) as conn:
        # Authenticate (normally)
        stream_id = conn._quic.get_next_available_stream_id()
        conn._quic.send_stream_data(stream_id, protocol.encode_message({"type": "AUTH_START", "username": "admin"}), end_stream=True)
        conn.transmit()
        challenge_msg = await conn._responses.get()

        challenge = challenge_msg.get("data")
        signature = private_key.sign(challenge)

        # Send response fragmented
        result = await conn.send_fragmented({"type": "response", "data": signature})
        assert result == "AUTH_OK"
