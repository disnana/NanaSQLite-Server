import asyncio
import os
import sys

# Add src to path
sys.path.append(os.path.join(os.getcwd(), "src"))

from nanasqlite_server.server import main
from nanasqlite_server.client import RemoteNanaSQLite


async def run_test():
    # Setup: generate keys and certs if they don't exist
    if not os.path.exists("cert.pem"):
        from nanasqlite_server.cert_gen import generate_certificate

        generate_certificate()
    if not os.path.exists("nana_public.pub"):
        from nanasqlite_server.key_gen import generate_keys

        generate_keys()

    # Define custom allowed/forbidden methods
    # Allow 'close' (normally forbidden)
    # Forbidden '__setitem__' (normally allowed)
    allowed = {"close"}
    forbidden = {"__setitem__"}

    # Start server in background
    server_task = asyncio.create_task(
        main(allowed_methods=allowed, forbidden_methods=forbidden)
    )
    await asyncio.sleep(2)

    try:
        db = RemoteNanaSQLite(host="127.0.0.1", port=4433)
        await db.connect()

        print("Testing normally allowed but custom-forbidden method '__setitem__'...")
        try:
            await db.set_item_async("test", "val")
            print("FAILED: '__setitem__' should have been forbidden")
        except Exception as e:
            print(f"SUCCESS: '__setitem__' was forbidden: {e}")

        print("Testing normally forbidden but custom-allowed method 'close'...")
        try:
            # We use __getattr__ because RemoteNanaSQLite.close() is a local method
            # We want to test calling the remote 'close' method
            result = await db.__getattr__("close")()
            print(f"SUCCESS: 'close' was allowed: {result}")
        except Exception as e:
            print(f"FAILED: 'close' should have been allowed: {e}")

        await db.close()
    finally:
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            # テスト終了時のサーバータスクキャンセルを明示的に記録
            print("Server task cancelled.")
        if os.path.exists("server_db.sqlite"):
            os.remove("server_db.sqlite")


if __name__ == "__main__":
    asyncio.run(run_test())
