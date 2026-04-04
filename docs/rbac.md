# RBAC 強化 — read_only・テーブル制限・アカウント名の厳格検証

[English](#english) | [日本語](#日本語)

---

## English

### Overview

NanaSQLite-Server v1.3.3 introduces two new RBAC (Role-Based Access Control) features designed to make permission management simpler and more granular, without breaking any existing configuration.

v1.3.4 adds **strict account name enforcement** during authentication.

---

### 0. Strict Account Name Enforcement (v1.3.4)

When a client calls `connect(account_name="...")`, the server now **strictly** validates that the provided account name matches the signing key.

**Behavior:**
| `account_name` provided | Account exists | Signature valid | Result |
|---|---|---|---|
| Yes | Yes | Yes (for that account) | ✅ Authentication success |
| Yes | Yes | No (wrong key) | ❌ Authentication failure |
| Yes | No | — | ❌ Authentication failure |
| No | — | Yes (for any account) | ✅ Authentication success (linear search) |

When `account_name` is specified, the server **does not fall back** to a linear search of other accounts if the named account's signature check fails. This prevents the following attack scenario:

```
# Before v1.3.4 (vulnerable):
attacker has user1's private key, specifies account_name="admin"
→ "admin"'s signature check fails → falls through to linear search
→ "user1" signature check succeeds → authenticated as "user1"

# v1.3.4 (fixed):
attacker has user1's private key, specifies account_name="admin"
→ "admin"'s signature check fails → authentication rejected immediately
```

For backward compatibility, if `account_name` is **not** specified, the existing linear search behavior is preserved.

---

### 1. Read-Only Accounts (`read_only`)

Add `"read_only": true` to an account in `accounts.json` to instantly prevent all write operations for that account.

**Example:**
```json
{
  "name": "viewer",
  "public_key": "ssh-ed25519 AAAA...",
  "read_only": true
}
```

**Blocked methods** (defined in `WRITE_METHODS`):
`__setitem__`, `__delitem__`, `set`, `delete`, `batch_update`, `batch_update_partial`, `batch_delete`, `clear`, `upsert`, `import_from_dict_list`, `flush`, `retry_dlq`, `clear_dlq`

Any attempt to call a write method will raise a `PermissionError` immediately, without reaching the database.

---

### 2. Per-DB Table Restrictions (`allowed_dbs` — dict format)

Extend `allowed_dbs` from a simple list to a dictionary to restrict which tables a user can access within each database.

**Example:**
```json
{
  "name": "limited_user",
  "public_key": "ssh-ed25519 AAAA...",
  "allowed_dbs": {
    "logs.sqlite": null,
    "data.sqlite": ["public_info", "stats"]
  }
}
```

- **`null`**: All tables in the database are accessible.
- **`["table1", "table2"]`**: Only the listed tables are accessible. Any RPC call specifying a `table_name` not in this list will raise a `PermissionError`.

**Backward compatibility:** The old list format (`"allowed_dbs": ["db.sqlite"]`) continues to work and is automatically converted to a dict with `null` values for all databases.

---

### Combining Features

Both features can be combined:

```json
{
  "name": "limited_viewer",
  "public_key": "ssh-ed25519 AAAA...",
  "read_only": true,
  "allowed_dbs": {
    "data.sqlite": ["public_info"]
  }
}
```

This account can only read from the `public_info` table in `data.sqlite`.

---

## 日本語

### 概要

NanaSQLite-Server v1.3.3 では、既存の設定を壊すことなく、より簡単かつ強力にアクセス制御を設定できる 2 つの新しい RBAC 機能が追加されました。

v1.3.4 では**認証時のアカウント名厳格検証**が追加されました。

---

### 0. アカウント名の厳格検証 (v1.3.4)

クライアントが `connect(account_name="...")` を呼び出した場合、サーバーは指定されたアカウント名が署名キーと一致することを**厳格に**検証します。

**動作:**
| `account_name` 指定 | アカウント存在 | 署名正当性 | 結果 |
|---|---|---|---|
| あり | あり | 正当 (そのアカウントの鍵) | ✅ 認証成功 |
| あり | あり | 不正 (別のアカウントの鍵) | ❌ 認証失敗 |
| あり | なし | — | ❌ 認証失敗 |
| なし | — | 正当 (いずれかのアカウントの鍵) | ✅ 認証成功 (線形探索) |

`account_name` が指定された場合、指定されたアカウントの署名検証が失敗しても、他のアカウントへのフォールバック（線形探索）は行いません。これにより以下の攻撃を防止します:

```
# v1.3.4 以前 (脆弱):
攻撃者が user1 の秘密鍵を持ち、account_name="admin" を指定する
→ "admin" の署名検証失敗 → 線形探索にフォールバック
→ "user1" の署名検証成功 → "user1" として認証されてしまう

# v1.3.4 (修正済み):
攻撃者が user1 の秘密鍵を持ち、account_name="admin" を指定する
→ "admin" の署名検証失敗 → 即座に認証失敗
```

後方互換性のため、`account_name` を**指定しない**場合は従来通りの線形探索が適用されます。

---

### 1. 一括 Read-Only 設定 (`read_only`)

`accounts.json` のアカウント設定に `"read_only": true` を追加するだけで、そのアカウントからの全ての書き込み操作を一括で禁止できます。

**例:**
```json
{
  "name": "viewer",
  "public_key": "ssh-ed25519 AAAA...",
  "read_only": true
}
```

**禁止されるメソッド** (`WRITE_METHODS` として定義):
`__setitem__`, `__delitem__`, `set`, `delete`, `batch_update`, `batch_update_partial`, `batch_delete`, `clear`, `upsert`, `import_from_dict_list`, `flush`, `retry_dlq`, `clear_dlq`

書き込み系メソッドを呼び出すと、データベースに到達する前に即座に `PermissionError` が返されます。

---

### 2. DB 名に紐づくテーブル制限 (`allowed_dbs` — 辞書形式)

`allowed_dbs` を辞書形式で指定することで、各データベース内でアクセス可能なテーブルを制限できます。

**例:**
```json
{
  "name": "limited_user",
  "public_key": "ssh-ed25519 AAAA...",
  "allowed_dbs": {
    "logs.sqlite": null,
    "data.sqlite": ["public_info", "stats"]
  }
}
```

- **`null`**: そのデータベース内の全テーブルにアクセス可能。
- **`["table1", "table2"]`**: 指定したテーブルのみアクセス可能。`table_name` に未許可のテーブルを指定した RPC 呼び出しは `PermissionError` になります。

**後方互換性:** 従来のリスト形式 (`"allowed_dbs": ["db.sqlite"]`) は引き続き動作します。内部で全テーブル許可 (`null`) の辞書に自動変換されます。

---

### 機能の組み合わせ

両機能は組み合わせて使用できます:

```json
{
  "name": "limited_viewer",
  "public_key": "ssh-ed25519 AAAA...",
  "read_only": true,
  "allowed_dbs": {
    "data.sqlite": ["public_info"]
  }
}
```

このアカウントは `data.sqlite` の `public_info` テーブルのみ読み取り可能です。
