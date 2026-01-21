import asyncio
import sys
import os

# プロジェクトルートをパスに追加
sys.path.append(os.getcwd())

from client import RemoteNanaSQLite
from nanasqlite.exceptions import NanaSQLiteValidationError
from colorama import Fore, Style, init

init(autoreset=True)


async def verify():
    client = RemoteNanaSQLite(host="127.0.0.1", port=4433)
    try:
        await client.connect()

        print(f"\n{Fore.CYAN}--- Test 1: Method Auto-Wrapping ---{Style.RESET_ALL}")
        # create_table(table_name, columns, ...)
        await client.create_table(
            "test_table_remote_verify", {"id": "INTEGER PRIMARY KEY", "data": "TEXT"}
        )
        print(f"{Fore.GREEN}✓ create_table executed successfully.{Style.RESET_ALL}")

        print(
            f"\n{Fore.CYAN}--- Test 2: Exception Reconstruction (AttributeError) ---{Style.RESET_ALL}"
        )
        try:
            # table_create は存在しない（サーバー側で発生したAttributeErrorを期待）
            await client.table_create("should_fail")
        except AttributeError as e:
            print(f"{Fore.GREEN}✓ Caught expected AttributeError: {e}{Style.RESET_ALL}")
        except Exception as e:
            print(
                f"{Fore.RED}✗ Caught WRONG exception type: {type(e).__name__}: {e}{Style.RESET_ALL}"
            )

        print(
            f"\n{Fore.CYAN}--- Test 3: NanaSQLite Specific Exception (ValidationError) ---{Style.RESET_ALL}"
        )
        try:
            # 不正なテーブル名（数字開始）で ValidationError を誘発
            await client.create_table("123invalid", {"id": "INTEGER"})
        except NanaSQLiteValidationError as e:
            print(
                f"{Fore.GREEN}✓ Caught expected NanaSQLiteValidationError: {e}{Style.RESET_ALL}"
            )
        except Exception as e:
            print(
                f"{Fore.RED}✗ Caught WRONG exception type: {type(e).__name__}: {e}{Style.RESET_ALL}"
            )

        print(
            f"\n{Fore.CYAN}--- Test 4: Data persistence via auto-wrapping ---{Style.RESET_ALL}"
        )
        await client.set_item_async("verify_key", "Remote Perfection")
        val = await client.get_item_async("verify_key")
        if val == "Remote Perfection":
            print(f"{Fore.GREEN}✓ Data persistence verified.{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}✗ Data mismatch: {val}{Style.RESET_ALL}")

    finally:
        await client.close()


if __name__ == "__main__":
    asyncio.run(verify())
