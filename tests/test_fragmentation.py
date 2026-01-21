import asyncio
import ssl
from aioquic.asyncio import QuicConnectionProtocol, connect
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived
from cryptography.hazmat.primitives import serialization
import os
from nanasqlite_server import protocol

PRIVATE_KEY_PATH = "nana_private.pem"
PORT = int(os.environ.get("NANASQLITE_TEST_PORT", 4433))


class FragClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._responses = asyncio.Queue()

    def quic_event_received(self, event):
        if isinstance(event, StreamDataReceived):
            # No buffering here, just like the current server
            message, _ = protocol.decode_message(event.data)
            self._responses.put_nowait(message)

    async def send_fragmented(self, data):
        stream_id = self._quic.get_next_available_stream_id()
        payload = protocol.encode_message(data)

        # Split into two parts
        mid = len(payload) // 2
        part1 = payload[:mid]
        part2 = payload[mid:]

        print(f"Sending fragmented message: {len(part1)} + {len(part2)} bytes")
        self._quic.send_stream_data(stream_id, part1, end_stream=False)
        self.transmit()
        await asyncio.sleep(0.1)  # Ensure separate packets
        self._quic.send_stream_data(stream_id, part2, end_stream=True)
        self.transmit()

        return await asyncio.wait_for(self._responses.get(), timeout=5.0)


def load_private_key():
    with open(PRIVATE_KEY_PATH, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


async def create_connection(host="127.0.0.1", port=PORT):
    configuration = QuicConfiguration(
        is_client=True,
        verify_mode=ssl.CERT_NONE,
        server_name="localhost",
    )
    ctx = connect(
        host, port, configuration=configuration, create_protocol=FragClientProtocol
    )
    connection = await ctx.__aenter__()
    return ctx, connection


async def test_fragmentation():
    print("Testing fragmentation handling...")
    private_key = load_private_key()
    ctx, conn = await create_connection()
    try:
        # Authenticate (normally)
        stream_id = conn._quic.get_next_available_stream_id()
        conn._quic.send_stream_data(
            stream_id, protocol.encode_message("AUTH_START"), end_stream=True
        )
        conn.transmit()
        challenge_msg = await conn._responses.get()

        challenge = challenge_msg.get("data")
        signature = private_key.sign(challenge)

        # Send response fragmented
        result = await conn.send_fragmented({"type": "response", "data": signature})
        print(f"Result of fragmented auth response: {result}")

    except Exception as e:
        print(f"Error or timeout: {e}")
    finally:
        conn.close()
        await conn.wait_closed()


if __name__ == "__main__":
    asyncio.run(test_fragmentation())
