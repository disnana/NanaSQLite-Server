# NanaSQLite-Server Documentation

## 1. 概要
NanaSQLite-Serverは、QUICプロトコルを使用したセキュアなRPCサーバーです。Ed25519パスキー認証と、アカウントごとの詳細な権限管理（RBAC）をサポートしています。

## 2. セットアップ

### インストール
```bash
pip install -r requirements.txt
```

### 証明書と鍵の生成
```bash
nanasqlite-cert-gen
nanasqlite-key-gen
```

## 3. 設定

### サーバー設定 (.env)
サーバーの動作設定は、デフォルトで `.env` ファイルから読み込まれます。

```env
host=127.0.0.1
port=4433
cert_file=cert.pem
key_file=key.pem
db_path=server_db.sqlite
accounts_file=accounts.json
max_failed_attempts=3
ban_duration=900
```

### アカウントと権限設定 (accounts.json)
`accounts.json` で複数のユーザーとそれぞれの権限を定義できます。

```json
[
  {
    "name": "admin",
    "public_key_path": "nana_public.pub",
    "allowed": ["*"],
    "forbidden": ["close", "vacuum"]
  },
  {
    "name": "readonly",
    "public_key_path": "user_public.pub",
    "allowed": ["get", "keys", "values", "items", "exists"],
    "forbidden": ["*"]
  }
]
```

- `allowed`: 許可するメソッドのリスト。`["*"]` はすべてを許可します。
- `forbidden`: 明示的に禁止するメソッドのリスト。`allowed` よりも優先されます。

## 4. セキュリティ機能

### Ed25519 認証
Ed25519署名を用いたチャレンジ・レスポンス方式を採用しており、パスワードの送受分が発生しません。

### BAN機能
連続して認証に失敗したIPアドレスを自動的に一定時間ブロックします。

### RBAC (Role-Based Access Control)
メソッドレベルでの実行可否をアカウントごとに制御できます。

## 5. テスト
`pytest` を使用して、機能、セキュリティ、パフォーマンスのテストを実行できます。

```bash
# 全テストの実行
pytest

# パフォーマンステストのみ
pytest tests/test_performance.py
```
