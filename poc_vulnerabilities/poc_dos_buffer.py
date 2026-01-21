import asyncio
import os
import ssl
from aioquic.asyncio import connect
from aioquic.quic.configuration import QuicConfiguration
from nanasqlite_server.client import NanaRpcClientProtocol

async def run_poc():
    print("[*] Starting Anti-DoS Buffer Limit PoC")
    port = int(os.environ.get("NANASQLITE_TEST_PORT", 4433))
    config = QuicConfiguration(is_client=True, verify_mode=ssl.CERT_NONE)

    print(f"[*] Connecting to server on port {port}...")
    try:
        async with connect("127.0.0.1", port, configuration=config, create_protocol=NanaRpcClientProtocol) as conn:
            stream_id = conn._quic.get_next_available_stream_id()
            chunk = b"A" * (1024 * 1024) # 1MB

            print("[*] Flooding server with 60MB of data (Limit is 50MB)...")
            for i in range(60):
                try:
                    conn._quic.send_stream_data(stream_id, chunk, end_stream=False)
                    conn.transmit()
                    # Small sleep to allow server to process and potentially close the connection
                    await asyncio.sleep(0.01)
                except Exception as e:
                    print(f"[*] Connection closed by server as expected at {i}MB.")
                    break

            await asyncio.sleep(1.0)
            print("[*] Verifying server health with a new connection...")
            async with connect("127.0.0.1", port, configuration=config, create_protocol=NanaRpcClientProtocol) as conn2:
                try:
                    await conn2.call_rpc("AUTH_START")
                    print("[+] Success! Server is still responsive (DoS mitigated).")
                except Exception as e:
                    print(f"[-] Failure: Server is unresponsive: {e}")

    except Exception as e:
        print(f"[*] Connection ended: {e}")

if __name__ == "__main__":
    asyncio.run(run_poc())
