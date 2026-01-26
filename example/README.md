# NanaSQLite-Server Example

NanaSQLite-Server の基本的な使用方法を示すサンプルコードです。
テスト機能も兼ねており、サーバーとの接続、認証、データの読み書き、例外処理の動作を確認できます。

## 構成ファイル

- `setup_example.py`: 証明書、秘密鍵、およびマルチDB対応のアカウント設定を生成します。
- `sample_server.py`: QUICベースのRPCサーバーを起動します。
- `sample_client.py`: サーバーに接続し、テスト（読み書き、削除、エラー処理、マルチDBアクセス）を実行します。

## 実行手順

### 1. 準備 (セットアップ)

まず、実行に必要な証明書やキーを生成します。

```bash
python setup_example.py
```

### 2. サーバーの起動

別のターミナルを開き、サーバーを起動します。

```bash
python sample_server.py
```

### 3. クライアントの実行 (テスト)

サーバーが起動している状態で、クライアントを実行して動作確認を行います。

```bash
python sample_client.py
```

## 注意事項

- このサンプルで使用する `cert.pem` は自己署名証明書です。
- `nana_private.pem` はクライアントの秘密鍵です。本番環境では厳重に管理してください。
- サーバーのデータは `example.sqlite` に保存されます。
