import asyncio
import os
import sys
from colorama import Fore, Style

# プロジェクトルートをインポートパスに追加
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.nanasqlite_server.client import RemoteNanaSQLite

async def run_test():
    # exampleディレクトリをカレントディレクトリとして動作させる
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    if not os.path.exists("nana_private.pem"):
        print(f"{Fore.RED}Error: nana_private.pem not found.{Style.RESET_ALL}")
        print("Please run 'python setup_example.py' first.")
        return

    print(f"{Fore.CYAN}--- NanaSQLite Sample Client & Test ---{Style.RESET_ALL}")
    
    # 1. 接続と認証
    client = RemoteNanaSQLite(
        host="127.0.0.1",
        port=4433,
        ca_cert_path="cert.pem",
        verify_ssl=True
    )
    
    try:
        await client.connect(account_name="example_user")
        
        # 2. 基本的なデータ操作のテスト
        print(f"\n{Fore.YELLOW}[Step 1] Basic Data Operations{Style.RESET_ALL}")
        
        print("Setting data: 'greeting' = 'Hello from Client!'")
        await client.set_item_async("greeting", "Hello from Client!")
        
        val = await client.get_item_async("greeting")
        print(f"Read back: {val}")
        
        if val == "Hello from Client!":
            print(f"{Fore.GREEN}✓ Success{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}✗ Failed{Style.RESET_ALL}")

        # 3. 削除のテスト
        print(f"\n{Fore.YELLOW}[Step 2] Deletion Test{Style.RESET_ALL}")
        await client.del_item_async("greeting")
        # get() はキーが存在しない場合に None を返す
        val_after_del = await client.get("greeting")
        print(f"Value after deletion: {val_after_del}")
        
        if val_after_del is None:
            print(f"{Fore.GREEN}✓ Success{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}✗ Failed{Style.RESET_ALL}")

        # 4. 複合データのテスト
        print(f"\n{Fore.YELLOW}[Step 3] Complex Data Types{Style.RESET_ALL}")
        complex_data = {
            "user_id": 12345,
            "roles": ["admin", "developer"],
            "meta": {"last_login": "2026-01-25"}
        }
        await client.set_item_async("user_info", complex_data)
        read_complex = await client.get_item_async("user_info")
        print(f"Read info: {read_complex}")
        
        if read_complex == complex_data:
            print(f"{Fore.GREEN}✓ Success{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}✗ Failed{Style.RESET_ALL}")

        # 5. エラーハンドリング（例外の再発生）のテスト
        print(f"\n{Fore.YELLOW}[Step 4] Exception Handling{Style.RESET_ALL}")
        print("Attempting to call a forbidden method...")
        try:
            # サーバー側で禁止されているメソッドの呼び出しを試みる
            await client.__getattr__("execute")("SELECT * FROM sqlite_master")
        except PermissionError as e:
            print(f"{Fore.GREEN}✓ Caught expected exception: {e}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}✗ Caught unexpected exception type: {type(e).__name__}: {e}{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}--- All tests completed! ---{Style.RESET_ALL}")

    except Exception as e:
        print(f"{Fore.RED}An error occurred during the test: {e}{Style.RESET_ALL}")
    finally:
        await client.close()

if __name__ == "__main__":
    asyncio.run(run_test())
