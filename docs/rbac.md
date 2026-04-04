# RBAC 強化 — read_only・テーブル制限

[English](#english) | [日本語](#日本語)

---

## English

### Overview

NanaSQLite-Server v1.3.3 introduces two new RBAC (Role-Based Access Control) features designed to make permission management simpler and more granular, without breaking any existing configuration.

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
