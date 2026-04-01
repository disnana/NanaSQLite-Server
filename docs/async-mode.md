# Async Mode (`--async-mode`)

[English](#english) | [日本語](#日本語)

---

## English

### Overview

By default, NanaSQLite-Server uses a `ThreadPoolExecutor` to run synchronous `NanaSQLite` methods without blocking the async event loop. When `--async-mode` is enabled the server switches its database backend to `AsyncNanaSQLite`, which exposes native coroutine methods that are awaited directly — removing the thread-pool indirection entirely.

```
Normal mode:   RPC request → event loop → ThreadPoolExecutor → NanaSQLite (sync)
Async mode:    RPC request → event loop → AsyncNanaSQLite (native async) ← no thread pool
```

The client-side interface (`RemoteNanaSQLite`) is **completely unchanged**. You do not need to modify any client code to switch server modes.

### Requirements

`AsyncNanaSQLite` must be importable from the installed `nanasqlite` package. If the class is not available the server will refuse to start with a clear error message.

**Recommended nanasqlite version:** v1.5.0dev1 or later  
*(Introduced complete `AsyncNanaSQLite` V2 async methods via ASYNC-01 and lazy-lock init via QUAL-04)*

No minimum version is enforced at install time. If you start the server with `--async-mode` and `AsyncNanaSQLite` cannot be imported, you will see:

```
RuntimeError: --async-mode requires AsyncNanaSQLite, which is not available in the
currently installed version of nanasqlite.
Recommended: nanasqlite v1.5.0dev1 or later.
See docs/async-mode.md for details.
```

### Enabling Async Mode

```bash
# Basic usage
nanasqlite-server --async-mode

# With a custom port
nanasqlite-server --async-mode --port 4433

# Combined with the v2 write engine
nanasqlite-server --async-mode --v2 --flush-mode time --flush-interval 1.0

# Combined with v2 + metrics
nanasqlite-server --async-mode --v2 --flush-mode time --enable-metrics
```

### Method Mapping

`RemoteNanaSQLite` clients call methods using the same names regardless of server mode. Internally the server translates certain names before calling `AsyncNanaSQLite`:

#### Dunder → async method

| Client calls | Server calls on `AsyncNanaSQLite` |
|---|---|
| `__getitem__` | `aget` |
| `__setitem__` | `aset` |
| `__delitem__` | `adelete` |
| `__contains__` | `acontains` |
| `__len__` | `alen` |

#### `a`-prefix fallback

For any other method where `AsyncNanaSQLite` exposes the async version with an `a` prefix (e.g. `batch_get` → `abatch_get`, `flush` → `aflush`), the server detects this automatically:

1. Check whether `AsyncNanaSQLite` has the method under its original name.
2. If not, prepend `a` and check again.
3. If the `a`-prefixed version exists, use it; otherwise fall back to the original name.

This means all methods that have a native coroutine equivalent are awaited directly with no thread pool.

### Security

All `FORBIDDEN_METHODS` restrictions defined in `server.py` apply identically in async mode. There is no change to the security surface.

### Shutdown Cleanup

When the server shuts down it iterates over all open `AsyncNanaSQLite` instances and calls `await instance.close()` to release resources cleanly before the event loop exits.

### Combining with the V2 Engine

Async mode and the V2 engine (`--v2`) are independently controllable:

| Combination | Behaviour |
|---|---|
| Neither | Classic sync NanaSQLite via thread pool |
| `--v2` only | Sync NanaSQLite with background V2 write engine, via thread pool |
| `--async-mode` only | `AsyncNanaSQLite`, no V2 engine |
| `--async-mode --v2` | `AsyncNanaSQLite` with V2 background engine — highest throughput |

When both are used together the V2 engine buffers writes in memory and flushes to SQLite in the background, while `AsyncNanaSQLite` ensures that all of this happens without blocking the event loop.

### Limitations

- `AsyncNanaSQLite` lazy-initialises its internal thread pool on the first async call. There is a negligible one-time overhead on the very first database access after a new database file is opened.
- The server uses a 15-second timeout per RPC call regardless of mode. Long-running operations (large batch imports, heavy queries) should be designed with this limit in mind.
- `AsyncNanaSQLite` is designed for **single-process** use only. Do not run multiple NanaSQLite-Server processes pointing at the same database file with `--async-mode` enabled.

---

## 日本語

### 概要

デフォルトでは、NanaSQLite-Server は `ThreadPoolExecutor` を使用して同期的な `NanaSQLite` メソッドを実行し、非同期イベントループをブロックしないようにしています。`--async-mode` を有効にすると、サーバーのデータベースバックエンドが `AsyncNanaSQLite` に切り替わり、ネイティブなコルーチンメソッドを直接 `await` して実行するため、スレッドプールを経由する必要がなくなります。

```
通常モード:    RPC要求 → イベントループ → ThreadPoolExecutor → NanaSQLite（同期）
Asyncモード:   RPC要求 → イベントループ → AsyncNanaSQLite（ネイティブ非同期）← スレッドプール不要
```

クライアント側のインターフェース（`RemoteNanaSQLite`）は**変更不要**です。サーバーモードを切り替えても、クライアントのコードを修正する必要はありません。

### 動作要件

インストールされている `nanasqlite` パッケージから `AsyncNanaSQLite` がインポートできる必要があります。クラスが利用できない場合、サーバーは明確なエラーメッセージを表示して起動を拒否します。

**推奨 nanasqlite バージョン:** v1.5.0dev1 以降  
*（ASYNC-01 による `AsyncNanaSQLite` V2 非同期メソッドの完全実装、および QUAL-04 による遅延ロック初期化が含まれるバージョン）*

インストール時にバージョンの下限を強制することはしていません。`--async-mode` でサーバーを起動しようとしたときに `AsyncNanaSQLite` がインポートできない場合は、以下のエラーが表示されます。

```
RuntimeError: --async-mode requires AsyncNanaSQLite, which is not available in the
currently installed version of nanasqlite.
Recommended: nanasqlite v1.5.0dev1 or later.
See docs/async-mode.md for details.
```

### Asyncモードの有効化

```bash
# 基本的な使い方
nanasqlite-server --async-mode

# ポートを指定する場合
nanasqlite-server --async-mode --port 4433

# v2書き込みエンジンと組み合わせる場合
nanasqlite-server --async-mode --v2 --flush-mode time --flush-interval 1.0

# v2 + メトリクス収集と組み合わせる場合
nanasqlite-server --async-mode --v2 --flush-mode time --enable-metrics
```

### メソッドのマッピング

`RemoteNanaSQLite` クライアントは、サーバーモードに関わらず同じメソッド名で呼び出しを行います。サーバー内部では `AsyncNanaSQLite` を呼び出す前に一部のメソッド名を変換します。

#### ダンダーメソッド → 非同期メソッド

| クライアントの呼び出し | サーバーが `AsyncNanaSQLite` で呼び出すメソッド |
|---|---|
| `__getitem__` | `aget` |
| `__setitem__` | `aset` |
| `__delitem__` | `adelete` |
| `__contains__` | `acontains` |
| `__len__` | `alen` |

#### `a` プレフィックスへのフォールバック

それ以外のメソッドで `AsyncNanaSQLite` が `a` プレフィックス付きの非同期版（例: `batch_get` → `abatch_get`、`flush` → `aflush`）を持つ場合、サーバーは自動的にこれを検出します。

1. `AsyncNanaSQLite` に元の名前でメソッドが存在するか確認する。
2. なければ `a` を先頭に付けて再確認する。
3. `a` プレフィックス版が存在すればそれを使用し、なければ元の名前にフォールバックする。

これにより、ネイティブなコルーチン版が存在するすべてのメソッドがスレッドプールを介さずに直接 `await` されます。

### セキュリティ

`server.py` で定義されているすべての `FORBIDDEN_METHODS` 制限は、Asyncモードでも同一に適用されます。セキュリティの範囲に変更はありません。

### シャットダウン時のクリーンアップ

サーバーのシャットダウン時、開いているすべての `AsyncNanaSQLite` インスタンスに対して `await instance.close()` を呼び出し、イベントループが終了する前にリソースを適切に解放します。

### V2エンジンとの組み合わせ

Asyncモードと V2 エンジン（`--v2`）は独立して制御できます。

| 組み合わせ | 動作 |
|---|---|
| どちらも無効 | 従来の同期 NanaSQLite をスレッドプール経由で使用 |
| `--v2` のみ | V2バックグラウンド書き込みエンジンを持つ同期 NanaSQLite をスレッドプール経由で使用 |
| `--async-mode` のみ | `AsyncNanaSQLite` を使用（V2エンジンなし） |
| `--async-mode --v2` | V2バックグラウンドエンジンを持つ `AsyncNanaSQLite` — 最高スループット |

両方を組み合わせると、V2 エンジンが書き込みをメモリにバッファリングしてバックグラウンドで SQLite にフラッシュしつつ、`AsyncNanaSQLite` によってイベントループを一切ブロックしない構成になります。

### 制限事項

- `AsyncNanaSQLite` は内部スレッドプールを最初の非同期呼び出し時に遅延初期化します。新しいデータベースファイルを開いた直後の最初のアクセスに、ごくわずかなオーバーヘッドが発生します。
- サーバーはモードに関わらず、RPC 呼び出しごとに 15 秒のタイムアウトを適用します。大量のバッチインポートや重いクエリなど、時間のかかる操作はこの制限を考慮して設計してください。
- `AsyncNanaSQLite` は**単一プロセス**専用です。`--async-mode` を有効にして、同じデータベースファイルを複数の NanaSQLite-Server プロセスで共有しないでください。
