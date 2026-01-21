import asyncio
import os
import ssl
from aioquic.asyncio import connect
from aioquic.quic.configuration import QuicConfiguration
from nanasqlite_server.client import NanaRpcClientProtocol

async def run_poc():
    print("[*] Starting Anti-DoS Stream Limit PoC")
    port = int(os.environ.get("NANASQLITE_TEST_PORT", 4433))
    config = QuicConfiguration(is_client=True, verify_mode=ssl.CERT_NONE)

    print(f"[*] Connecting to server on port {port}...")
    try:
        async with connect("127.0.0.1", port, configuration=config, create_protocol=NanaRpcClientProtocol) as conn:
            print("[*] Flooding server with 100 concurrent streams (Limit is 50)...")
            resets = 0
            for i in range(100):
                try:
                    stream_id = conn._quic.get_next_available_stream_id()
                    conn._quic.send_stream_data(stream_id, b"data", end_stream=False)
                    conn.transmit()
                    # We don't wait here to simulate rapid fire
                except Exception as e:
                    resets += 1

            print(f"[*] Sent 100 streams. Waiting a moment for server processing...")
            await asyncio.sleep(1.0)

            print("[*] Attempting to open a new connection to check server availability...")
            async with connect("127.0.0.1", port, configuration=config, create_protocol=NanaRpcClientProtocol) as conn2:
                try:
                    await conn2.call_rpc("AUTH_START")
                    print("[+] Success! Server is still responsive to new connections (DoS mitigated).")
                except Exception as e:
                    print(f"[-] Failure: Server is unresponsive: {e}")

    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    asyncio.run(run_poc())
