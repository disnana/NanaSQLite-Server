# NanaSQLite-Server

[English](#english) | [日本語](#日本語)

---

## English

A secure, high-performance, QUIC-based RPC server for [NanaSQLite](https://github.com/disnana/NanaSQLite/).

### ⚠️ Security Warning
The security of this server depends on the method structure of the `NanaSQLite` class. While we use a dynamic protection mechanism, **updates to NanaSQLite may introduce new methods that could potentially bypass current security restrictions.** Always review the `FORBIDDEN_METHODS` in `server.py` when updating the underlying `nanasqlite` library.

**Current Supported NanaSQLite Version:** v1.3.2+

### Features
- **QUIC Protocol**: Built on top of HTTP/3 technology for low latency and high reliability.
- **Ed25519 Passkey Authentication**: Secure challenge-response authentication.
- **Performance**: Optimized with `ormsgpack` for ultra-fast message serialization.
- **Concurrency & Safety**: Thread-safe operations using `RLock` and optimized with `WAL` mode.
- **Reliability**: Enhanced task management for Python 3.13+ compatibility.
- **Role-Based Access Control (RBAC)**: Manage allowed/forbidden methods per account.
- **Multi-DB Support**: Securely access multiple databases within a designated directory.
- **Cross-Platform**: Fully optimized for Windows, Linux, and macOS.

### Quick Start
```bash
pip install nanasqlite-server
nanasqlite-cert-gen
nanasqlite-key-gen
nanasqlite-server
```

### Multi-Database & RBAC Configuration
Configure accounts and database access in `accounts.json`:

```json
{
    "db_dir": "./data",
    "accounts": [
        {
            "name": "admin",
            "public_key": "ssh-ed25519 ...",
            "allowed_methods": null,
            "allowed_dbs": ["main.sqlite", "logs.sqlite"]
        },
        {
            "name": "readonly_user",
            "public_key": "ssh-ed25519 ...",
            "allowed_methods": ["get_item_async", "list_tables"],
            "allowed_dbs": ["main.sqlite"]
        }
    ]
}
```
*Note: `db_dir` is the base directory. Remote clients can only access databases explicitly listed in their `allowed_dbs`.*

### Client Usage Example
```python
import asyncio
from nanasqlite_server.client import RemoteNanaSQLite

async def main():
    # Specify connection info
    db = RemoteNanaSQLite(host="127.0.0.1", port=4433)
    
    # Connect and authenticate (requires nana_private.pem)
    await db.connect()
    
    # Perform data operations (async methods)
    await db.set_item_async("key", "value")
    val = await db.get_item_async("key")
    print(f"Read back: {val}")
    
    # Close connection
    await db.close()

if __name__ == "__main__":
    asyncio.run(main())
```
*Note: If no database is specified by the client and the account has no `allowed_dbs` restriction, the database specified by the server's `--db` option (default: `server_db.sqlite`) will be used.*

### Concurrency & Locking Design
NanaSQLite-Server uses a high-concurrency model optimized for safety:
- **Threadpool Offloading**: All database operations are offloaded to a shared thread pool (default 10 workers) to prevent blocking the async event loop.
- **Per-DB Locking**: Each database instance is protected by a thread-safe `RLock`. Multiple readers/writers are safely queued.
- **WAL Mode**: Databases are initialized in `WAL` (Write-Ahead Logging) mode, allowing concurrent reads even during write operations.

---

## 日本語

[NanaSQLite](https://github.com/disnana/NanaSQLite/) のためのセキュアで高速な QUIC ベースの RPC サーバーです。

### ⚠️ セキュリティに関する重要な警告
このサーバーのセキュリティは `NanaSQLite` クラスのメソッド構造に依存しています。動的な保護メカニズムを採用していますが、**NanaSQLite のアップデートにより、現在の制限を回避できる新しいメソッドが導入される可能性があります。** `nanasqlite` ライブラリを更新する際は、必ず `server.py` 内の `FORBIDDEN_METHODS` を確認し、必要に応じて更新してください。

**現在対応している NanaSQLite バージョン:** v1.3.2+

### 特徴
- **QUIC プロトコル**: HTTP/3 テクノロジーをベースにした低遅延で信頼性の高い通信。
- **Ed25519 パスキー認証**: チャレンジ/レスポンス方式によるセキュアな認証。
- **ロールベースアクセス制御 (RBAC)**: アカウントごとの許可/禁止メソッドの管理。
- **マルチDB対応**: 指定したディレクトリ内の複数のDBへ安全にアクセス。
- **動的保護**: ライブラリの更新に自動対応しつつ、許可されたメソッドのみを実行可能。
- **マルチプラットフォーム**: Windows, Linux, macOS に最適化。
- **非ブロッキング I/O**: すべての DB 操作をスレッドプールで実行し、イベントループを停止させません。

### クイックスタート
```bash
pip install nanasqlite-server
# 証明書と鍵の生成
nanasqlite-cert-gen
nanasqlite-key-gen
# サーバーの起動
nanasqlite-server
```

### マルチDB & RBAC 設定
`accounts.json` でアカウントとアクセス可能なDBを構成します：

```json
{
    "db_dir": "./data",
    "accounts": [
        {
            "name": "admin",
            "public_key": "ssh-ed25519 ...",
            "allowed_methods": null,
            "allowed_dbs": ["main.sqlite", "logs.sqlite"]
        },
        {
            "name": "readonly_user",
            "public_key": "ssh-ed25519 ...",
            "allowed_methods": ["get_item_async", "list_tables"],
            "allowed_dbs": ["main.sqlite"]
        }
    ]
}
```
*注: `db_dir` はベースディレクトリです。クライアントは `allowed_dbs` に明記されたDBにのみアクセス可能です。*

### 許可メソッドのカスタマイズ
プログラムからサーバーを起動する場合、許可または禁止するメソッドをカスタマイズできます。

```python
import asyncio
from nanasqlite_server.server import main

async def start_server():
    # 'close' を明示的に許可し、'__setitem__' を禁止する例
    await main(
        allowed_methods={"close"},
        forbidden_methods={"__setitem__"}
    )

if __name__ == "__main__":
    asyncio.run(start_server())
```

### クライアントの使用例
```python
import asyncio
from nanasqlite_server.client import RemoteNanaSQLite

async def main():
    # 接続情報の指定
    db = RemoteNanaSQLite(host="127.0.0.1", port=4433)
    
    # 接続と認証（秘密鍵 nana_private.pem が必要）
    await db.connect()
    
    # 非同期メソッドによるデータ操作
    await db.set_item_async("key", "value")
    val = await db.get_item_async("key")
    print(f"Read back: {val}")
    
    # 終了
    await db.close()

if __name__ == "__main__":
    asyncio.run(main())
```

*注: サーバー側で DB が指定されていない場合、またはアカウントの `allowed_dbs` が設定されていない場合、サーバー起動時に `--db` で指定されたデータベースがデフォルトとして使用されます。*

## License
MIT License
