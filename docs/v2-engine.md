# V2 Write Engine (`--v2`)

[English](#english) | [日本語](#日本語)

---

## English

### Overview

The V2 engine is an optional background write architecture for `NanaSQLite`. When enabled, all write operations are buffered in memory and flushed to SQLite asynchronously by a background thread. Read operations always return immediately from the in-memory buffer, so read latency is unchanged.

```
V2 disabled:  write → SQLite (blocking, on caller thread)
V2 enabled:   write → staging buffer (non-blocking) → background thread → SQLite
```

The client-side interface (`RemoteNanaSQLite`) is **completely unchanged**.

### Enabling the V2 Engine

```bash
# Basic: immediate flush (default behaviour, same as no --v2 except using the engine)
nanasqlite-server --v2

# Time-based flush (flush every 1 second)
nanasqlite-server --v2 --flush-mode time --flush-interval 1.0

# Count-based flush (flush every 500 writes)
nanasqlite-server --v2 --flush-mode count --flush-count 500

# Manual flush only (flush when client calls flush() via RPC)
nanasqlite-server --v2 --flush-mode manual

# Enable metrics collection
nanasqlite-server --v2 --flush-mode time --enable-metrics
```

### Flush Modes

| Mode | Description |
|---|---|
| `immediate` | Flush after every write (default). Lowest latency, highest I/O. |
| `time` | Flush at a regular interval (`--flush-interval`, default 3.0 s). Best for write-heavy workloads. |
| `count` | Flush after `--flush-count` writes accumulate (default 100). |
| `manual` | Flush only when `flush()` is explicitly called via RPC. |

### Configuration Options

| Flag | Default | Description |
|---|---|---|
| `--flush-mode` | `immediate` | Flush strategy (see above) |
| `--flush-interval` | `3.0` | Seconds between flushes in `time` mode |
| `--flush-count` | `100` | Write count threshold in `count` mode |
| `--v2-chunk-size` | `1000` | Maximum writes per flush transaction |
| `--enable-metrics` | off | Enable V2 metrics collection |

### RPC Methods Available in V2 Mode

The following methods can be called by clients when V2 mode is active:

| Method | Description |
|---|---|
| `flush()` | Manually trigger a flush to SQLite |
| `get_dlq()` | Retrieve failed tasks in the Dead-Letter Queue |
| `retry_dlq()` | Retry failed tasks from the DLQ |
| `clear_dlq()` | Clear the Dead-Letter Queue |
| `get_v2_metrics()` | Retrieve engine statistics (requires `--enable-metrics`) |

### Dead-Letter Queue (DLQ)

If a background flush fails (e.g. due to a constraint violation), the failed write is isolated in a Dead-Letter Queue rather than crashing the engine. Other writes continue normally. Use `get_dlq()` to inspect failures and `retry_dlq()` to attempt reprocessing.

### Metrics

When `--enable-metrics` is passed, `get_v2_metrics()` returns engine statistics including total flush count, processing time, and DLQ entries. Metrics collection has a small memory overhead and is opt-in.

### Combining with Async Mode

See [async-mode.md](async-mode.md#combining-with-the-v2-engine) for details on using `--v2` and `--async-mode` together.

### Limitations

- The V2 engine is designed for **single-process** use only. Running multiple server processes pointing at the same database with `--v2` enabled will cause data corruption.
- `begin_transaction()` is disabled in V2 mode to prevent conflicts with the background flush thread.
- Writes are visible to subsequent reads immediately (staging buffer is consulted first), but they are not durable until flushed to SQLite.

---

## 日本語

### 概要

V2 エンジンは `NanaSQLite` のオプションのバックグラウンド書き込みアーキテクチャです。有効にすると、すべての書き込み操作はメモリ上にバッファリングされ、バックグラウンドスレッドによって非同期に SQLite へフラッシュされます。読み取り操作はインメモリバッファから即座に返るため、読み取りレイテンシは変わりません。

```
V2 無効:  書き込み → SQLite（呼び出し元スレッドでブロッキング）
V2 有効:  書き込み → ステージングバッファ（非ブロッキング）→ バックグラウンドスレッド → SQLite
```

クライアント側のインターフェース（`RemoteNanaSQLite`）は**変更不要**です。

### V2エンジンの有効化

```bash
# 基本: 即時フラッシュ（デフォルト）
nanasqlite-server --v2

# 時間ベースのフラッシュ（1秒ごとにフラッシュ）
nanasqlite-server --v2 --flush-mode time --flush-interval 1.0

# 件数ベースのフラッシュ（500件書き込みごとにフラッシュ）
nanasqlite-server --v2 --flush-mode count --flush-count 500

# 手動フラッシュのみ（クライアントが flush() をRPC経由で呼び出したときだけフラッシュ）
nanasqlite-server --v2 --flush-mode manual

# メトリクス収集を有効化
nanasqlite-server --v2 --flush-mode time --enable-metrics
```

### フラッシュモード

| モード | 説明 |
|---|---|
| `immediate` | 書き込みのたびにフラッシュ（デフォルト）。最低レイテンシ、最高 I/O。 |
| `time` | 一定間隔でフラッシュ（`--flush-interval`、デフォルト 3.0秒）。書き込みが多いワークロードに最適。 |
| `count` | `--flush-count` 件の書き込みが蓄積したらフラッシュ（デフォルト 100件）。 |
| `manual` | RPC 経由で `flush()` が明示的に呼び出されたときのみフラッシュ。 |

### 設定オプション

| フラグ | デフォルト | 説明 |
|---|---|---|
| `--flush-mode` | `immediate` | フラッシュ戦略（上記参照） |
| `--flush-interval` | `3.0` | `time` モードでのフラッシュ間隔（秒） |
| `--flush-count` | `100` | `count` モードでの書き込み件数閾値 |
| `--v2-chunk-size` | `1000` | 1回のフラッシュトランザクションあたりの最大書き込み件数 |
| `--enable-metrics` | 無効 | V2 メトリクス収集を有効化 |

### V2モードで利用可能な RPC メソッド

V2 モードが有効な場合、クライアントは以下のメソッドを呼び出せます。

| メソッド | 説明 |
|---|---|
| `flush()` | SQLite への手動フラッシュをトリガー |
| `get_dlq()` | デッドレターキュー内の失敗タスクを取得 |
| `retry_dlq()` | DLQ 内の失敗タスクを再試行 |
| `clear_dlq()` | デッドレターキューをクリア |
| `get_v2_metrics()` | エンジン統計情報を取得（`--enable-metrics` が必要） |

### デッドレターキュー (DLQ)

バックグラウンドフラッシュが失敗した場合（例: 制約違反）、失敗した書き込みはエンジンをクラッシュさせる代わりにデッドレターキューへ隔離されます。他の書き込みは正常に継続されます。`get_dlq()` で失敗内容を確認し、`retry_dlq()` で再処理を試みることができます。

### メトリクス

`--enable-metrics` を指定すると、`get_v2_metrics()` がフラッシュ総件数、処理時間、DLQ エントリ数などのエンジン統計情報を返します。メトリクス収集はわずかなメモリオーバーヘッドがあるためオプトイン方式です。

### Asyncモードとの組み合わせ

`--v2` と `--async-mode` を組み合わせる場合の詳細は [async-mode.md](async-mode.md#v2エンジンとの組み合わせ) を参照してください。

### 制限事項

- V2 エンジンは**単一プロセス**専用です。`--v2` を有効にして、同じデータベースを複数のサーバープロセスで共有するとデータ破損の原因になります。
- `begin_transaction()` はバックグラウンドフラッシュスレッドとの競合を防ぐため、V2 モードでは無効化されています（呼び出すと例外が発生します）。
- 書き込みは後続の読み取りにはすぐに見えます（ステージングバッファを優先参照するため）が、SQLite にフラッシュされるまでは永続化されていません。
