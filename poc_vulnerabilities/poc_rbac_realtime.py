import asyncio
import os
import sys
import json
from nanasqlite_server.client import RemoteNanaSQLite
from nanasqlite_server.cert_gen import generate_certificate
from nanasqlite_server.key_gen import generate_keys
import subprocess
import time
import signal

async def run_poc():
    print("--- PoC: RBAC and Real-time Policy Enforcement ---")

    # 準備
    if not os.path.exists("cert.pem"): generate_certificate()
    if not os.path.exists("nana_public.pub"): generate_keys()

    # 公開鍵を取得
    with open("nana_public.pub", "r") as f:
        pub_key = f.read().strip()

    # アカウント設定ファイルの作成
    accounts = {
        "accounts": [
            {
                "name": "admin",
                "public_key": pub_key,
                "allowed_methods": None,
                "forbidden_methods": []
            }
        ]
    }
    with open("accounts.json", "w") as f:
        json.dump(accounts, f)

    port = 5560
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
        print("Successfully connected as 'admin'")

        # 1. 権限の即時反映テスト: 実行中に権限を奪う
        print("\n[Test 1] Real-time Permission Revocation")
        # 権限を変更（禁止リストに __setitem__ を追加）
        accounts["accounts"][0]["forbidden_methods"] = ["__setitem__"]
        with open("accounts.json", "w") as f:
            json.dump(accounts, f)

        print("Updated accounts.json: forbidden_methods = ['__setitem__']")
        # OSのファイル更新日時が1秒単位の場合があるため少し待機
        await asyncio.sleep(1.1)

        try:
            await client.set_item_async("test", "value")
            print("FAILED: set_item_async was still allowed!")
        except PermissionError as e:
            print(f"PASSED: set_item_async was blocked immediately: {e}")

        # 2. アカウントの即時無効化テスト
        print("\n[Test 2] Real-time Account Disabling")
        accounts["accounts"] = [] # 全アカウント削除
        with open("accounts.json", "w") as f:
            json.dump(accounts, f)

        print("Updated accounts.json: All accounts removed")
        await asyncio.sleep(1.1)

        try:
            await client.get_item_async("test")
            print("FAILED: get_item_async was still allowed!")
        except PermissionError as e:
            print(f"PASSED: Account was disabled immediately: {e}")

    finally:
        await client.close()
        server_proc.send_signal(signal.SIGINT)
        server_proc.wait()
        for f in ["accounts.json", "server_db.sqlite"]:
            if os.path.exists(f): os.remove(f)

if __name__ == "__main__":
    asyncio.run(run_poc())
