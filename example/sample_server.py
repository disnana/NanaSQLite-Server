import asyncio
import os
import sys

# プロジェクトルートをインポートパスに追加
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.nanasqlite_server.server import main

async def start_server():
    # exampleディレクトリをカレントディレクトリとして動作させる
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    # setup_example.py が実行されているか確認
    if not os.path.exists("cert.pem") or not os.path.exists("accounts.json"):
        print("Error: Required files (cert.pem, accounts.json) not found.")
        print("Please run 'python setup_example.py' first.")
        return

    print("Starting Sample NanaSQLite Server...")
    # プログラムから直接サーバーを起動
    # port 4433, db_path="example.sqlite", accounts="accounts.json"
    await main(
        port=4433,
        account_config="accounts.json",
        db_path="example.sqlite"
    )

if __name__ == "__main__":
    try:
        asyncio.run(start_server())
    except KeyboardInterrupt:
        print("\nServer stopped.")
