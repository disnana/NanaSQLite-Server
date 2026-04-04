# IP アドレスフィルタリング

[English](#english) | [日本語](#日本語)

---

## English

### Overview

NanaSQLite-Server v1.3.4 adds IP address filtering support via `--allow-ips` and `--block-ips` command-line options. Both individual IP addresses and CIDR ranges are supported.

IP filtering is applied **before authentication**, providing an additional layer of protection for environments where only specific network segments should be allowed to connect.

---

### Options

| Option | Description |
|---|---|
| `--allow-ips <LIST>` | Comma-separated list of allowed IPs or CIDR ranges. When set, **only** connections from these addresses are accepted. |
| `--block-ips <LIST>` | Comma-separated list of blocked IPs or CIDR ranges. Connections from these addresses are always rejected. |

Both options can be specified simultaneously.

---

### Usage Examples

```sh
# Allow only connections from a specific subnet
nanasqlite-server --allow-ips "192.168.1.0/24"

# Allow multiple ranges or specific IPs (comma-separated)
nanasqlite-server --allow-ips "192.168.1.0/24,10.0.0.1,172.16.0.0/12"

# Block a specific IP address
nanasqlite-server --block-ips "10.0.0.99"

# Block an entire subnet
nanasqlite-server --block-ips "10.0.0.0/8"

# Combine allow and block (block overrides allow)
nanasqlite-server \
  --allow-ips "192.168.1.0/24" \
  --block-ips "192.168.1.100"
```

---

### Decision Rules

Priority order (evaluated in sequence):

1. **IP unknown** — When the client IP cannot be determined from the QUIC/UDP transport, the IP filter is skipped and authentication proceeds normally. A warning is logged.
2. **Block list** — If the IP matches any entry in `--block-ips`, the connection is rejected immediately.
3. **Allow list** — If `--allow-ips` is set and the IP does **not** match any entry, the connection is rejected.
4. **Default** — All other connections are permitted.

| `--allow-ips` set | `--block-ips` set | IP in allow list | IP in block list | Result |
|---|---|---|---|---|
| No | No | — | — | ✅ Allow |
| Yes | No | Yes | — | ✅ Allow |
| Yes | No | No | — | ❌ Reject |
| No | Yes | — | Yes | ❌ Reject |
| No | Yes | — | No | ✅ Allow |
| Yes | Yes | Yes | No | ✅ Allow |
| Yes | Yes | Yes | Yes | ❌ Reject (block wins) |
| Yes | Yes | No | No | ❌ Reject |

---

### Important Notes

- **CIDR notation** is fully supported (e.g., `192.168.1.0/24`, `10.0.0.0/8`).
- Invalid entries are **skipped** with a warning log; the server continues to start.
- IP filtering is a **best-effort** mechanism for QUIC/UDP servers because the transport layer may not always expose the peer address. Always use challenge-response authentication as the primary security mechanism.
- `--block-ips` always takes **precedence** over `--allow-ips`.

---

## 日本語

### 概要

NanaSQLite-Server v1.3.4 では、コマンドラインオプション `--allow-ips` および `--block-ips` による IP アドレスフィルタリングが追加されました。個別の IP アドレスと CIDR 範囲の両方に対応しています。

IP フィルタリングは**認証よりも前の段階**で適用されるため、特定のネットワークセグメントからの接続のみを許可したい環境での追加セキュリティ層として機能します。

---

### オプション

| オプション | 説明 |
|---|---|
| `--allow-ips <LIST>` | 許可する IP またはカンマ区切り CIDR リスト。設定した場合、**このリストに含まれる接続のみ**許可されます。 |
| `--block-ips <LIST>` | ブロックする IP またはカンマ区切り CIDR リスト。リストに含まれる接続は常に拒否されます。 |

両オプションは同時に指定できます。

---

### 使用例

```sh
# 特定サブネットからの接続のみ許可
nanasqlite-server --allow-ips "192.168.1.0/24"

# 複数の範囲または個別 IP を許可 (カンマ区切り)
nanasqlite-server --allow-ips "192.168.1.0/24,10.0.0.1,172.16.0.0/12"

# 特定 IP をブロック
nanasqlite-server --block-ips "10.0.0.99"

# サブネット全体をブロック
nanasqlite-server --block-ips "10.0.0.0/8"

# allow と block の組み合わせ (block が優先)
nanasqlite-server \
  --allow-ips "192.168.1.0/24" \
  --block-ips "192.168.1.100"
```

---

### 判定ルール

優先順位順に評価されます:

1. **IP 不明** — QUIC/UDP トランスポートからクライアント IP を取得できない場合、IP フィルタをスキップして認証を続行します。警告ログが出力されます。
2. **block リスト** — IP が `--block-ips` のいずれかに一致する場合、即座に接続を拒否します。
3. **allow リスト** — `--allow-ips` が設定されており、IP がリストに含まれない場合、接続を拒否します。
4. **デフォルト** — それ以外は全て許可します。

| `--allow-ips` | `--block-ips` | allowに含まれる | blockに含まれる | 結果 |
|---|---|---|---|---|
| 未設定 | 未設定 | — | — | ✅ 許可 |
| 設定あり | 未設定 | はい | — | ✅ 許可 |
| 設定あり | 未設定 | いいえ | — | ❌ 拒否 |
| 未設定 | 設定あり | — | はい | ❌ 拒否 |
| 未設定 | 設定あり | — | いいえ | ✅ 許可 |
| 設定あり | 設定あり | はい | いいえ | ✅ 許可 |
| 設定あり | 設定あり | はい | はい | ❌ 拒否 (blockが優先) |
| 設定あり | 設定あり | いいえ | いいえ | ❌ 拒否 |

---

### 注意事項

- **CIDR 表記**に完全対応 (例: `192.168.1.0/24`, `10.0.0.0/8`)。
- 不正なエントリは**スキップ**され、警告ログが出力されます。サーバーは正常に起動を続けます。
- IP フィルタリングは QUIC/UDP サーバーにおける**ベストエフォート**機能です。トランスポート層がピアアドレスを常に公開するとは限りません。主要なセキュリティ機構には必ずチャレンジ・レスポンス認証を使用してください。
- `--block-ips` は常に `--allow-ips` より**優先**されます。
