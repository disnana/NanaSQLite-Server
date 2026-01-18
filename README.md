# NanaSQLite-Server

[English](#english) | [日本語](#日本語)

---

## English

A secure, high-performance, QUIC-based RPC server for [NanaSQLite](https://github.com/NanaSQLite/nanasqlite).

### ⚠️ Security Warning
The security of this server depends on the method structure of the `NanaSQLite` class. While we use a dynamic protection mechanism, **updates to NanaSQLite may introduce new methods that could potentially bypass current security restrictions.** Always review the `FORBIDDEN_METHODS` in `server.py` when updating the underlying `nanasqlite` library.

**Current Supported NanaSQLite Version:** v1.3.2

### Features
- **QUIC Protocol**: Built on top of HTTP/3 technology for low latency and high reliability.
- **Ed25519 Passkey Authentication**: Secure challenge-response authentication.
- **Dynamic Protection**: Automatically adapts to updates while strictly controlling method access.
- **Cross-Platform**: Optimized for Windows, Linux, and macOS.
- **Non-Blocking IO**: Database operations run in a thread pool.

### Quick Start
```bash
pip install nanasqlite-server
nanasqlite-cert-gen
nanasqlite-key-gen
nanasqlite-server
```

---

## 日本語

[NanaSQLite](https://github.com/NanaSQLite/nanasqlite) のためのセキュアで高速な QUIC ベースの RPC サーバーです。

### ⚠️ セキュリティに関する重要な警告
このサーバーのセキュリティは `NanaSQLite` クラスのメソッド構造に依存しています。動的な保護メカニズムを採用していますが、**NanaSQLite のアップデートにより、現在の制限を回避できる新しいメソッドが導入される可能性があります。** `nanasqlite` ライブラリを更新する際は、必ず `server.py` 内の `FORBIDDEN_METHODS` を確認し、必要に応じて更新してください。

**現在対応している NanaSQLite バージョン:** v1.3.2

### 特徴
- **QUIC プロトコル**: HTTP/3 テクノロジーをベースにした低遅延で信頼性の高い通信。
- **Ed25519 パスキー認証**: チャレンジ/レスポンス方式によるセキュアな認証。
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

### クライアントの使用例
```python
import asyncio
from nanasqlite_server.client import RemoteNanaSQLite

async def main():
    db = RemoteNanaSQLite(host="127.0.0.1", port=4433)
    await db.connect()
    await db.set_item_async("key", "value")
    print(await db.get_item_async("key"))
    await db.close()

asyncio.run(main())
```

## License
MIT License
