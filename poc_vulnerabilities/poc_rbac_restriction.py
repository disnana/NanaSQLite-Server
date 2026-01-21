import asyncio
import os
import json
from nanasqlite_server.client import RemoteNanaSQLite
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


async def run_poc():
    print("[*] Starting RBAC Restriction PoC")

    # 1. Setup temporary account
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    ).decode()

    accounts_file = "accounts_poc.json"
    with open(accounts_file, "w") as f:
        json.dump(
            {
                "accounts": [
                    {
                        "name": "restricted_user",
                        "public_key": pub_bytes,
                        "allowed_methods": ["list_tables"],  # Only list_tables allowed
                        "forbidden_methods": None,
                    }
                ]
            },
            f,
        )

    print(
        f"[*] Created account 'restricted_user' with limited permissions in {accounts_file}"
    )

    # 2. Connect to server
    # Note: Assumes server is running on 4433 with --accounts accounts_poc.json
    # For this PoC to be standalone, we'd need to start the server,
    # but usually PoCs are run against a target.
    # Here we'll just demonstrate the client logic.

    port = int(os.environ.get("NANASQLITE_TEST_PORT", 4433))
    client = RemoteNanaSQLite(host="127.0.0.1", port=port, verify_ssl=False)
    client.private_key = private_key

    try:
        print(f"[*] Connecting to server on port {port}...")
        await client.connect(account_name="restricted_user")
        print("[+] Authenticated successfully.")

        print("[*] Attempting allowed method: list_tables()")
        tables = await client.list_tables()
        print(f"[+] Success! Tables: {tables}")

        print("[*] Attempting forbidden method: set_item_async('poc', 'data')")
        try:
            await client.set_item_async("poc", "data")
            print("[-] Failure: Method was NOT restricted!")
        except PermissionError as e:
            print(f"[+] Success! Method was blocked as expected: {e}")

    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        await client.close()
        if os.path.exists(accounts_file):
            os.remove(accounts_file)


if __name__ == "__main__":
    asyncio.run(run_poc())
