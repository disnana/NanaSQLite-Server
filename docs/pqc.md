# Post-Quantum Cryptography (PQC) 耐量子暗号 ガイド

[English](#english) | [日本語](#日本語)

---

## English

NanaSQLite-Server optionally supports **post-quantum cryptography (PQC)** for authentication via [liboqs-python](https://github.com/open-quantum-safe/liboqs-python). This allows you to protect against future quantum computer attacks on current asymmetric cryptography (such as Ed25519).

> **Note:** PQC authentication is fully **optional**. The default Ed25519-based authentication continues to work without any changes.

### Supported Algorithms

Any signature algorithm provided by [liboqs](https://openquantumsafe.org/) can be used, including:

| Algorithm | Security Level | Notes |
|-----------|---------------|-------|
| `Dilithium2` | 2 (128-bit) | Fast, moderate key size |
| `Dilithium3` | 3 (192-bit) | **Recommended default** |
| `Dilithium5` | 5 (256-bit) | Highest security |
| `Falcon-512` | 1 (128-bit) | Compact signatures |
| `Falcon-1024` | 5 (256-bit) | Compact, high security |
| `SPHINCS+-SHA2-128f-simple` | 1 (128-bit) | Hash-based, conservative |

> NIST standardized Dilithium (as ML-DSA) and Falcon (as FN-DSA) in 2024. Dilithium3 is a practical default choice.

### Installation

```bash
pip install "nanasqlite-server[pqc]"
```

Or install liboqs-python separately:

```bash
pip install liboqs-python
```

#### Windows — Additional DLL Setup

On Windows, `liboqs-python` requires the `liboqs` native library. The recommended installation method is via [MSYS2](https://www.msys2.org/):

1. **Install MSYS2** from https://www.msys2.org/ and open the MSYS2 MinGW64 shell.

2. **Install liboqs**:
   ```bash
   pacman -S mingw-w64-x86_64-liboqs
   ```

3. **Copy and rename the DLL** (the Python binding looks for `oqs.dll`):
   ```powershell
   # Copy the versioned DLL and rename it to oqs.dll
   Copy-Item C:\msys64\mingw64\bin\liboqs-9.dll C:\msys64\mingw64\bin\oqs.dll

   # Set the environment variable permanently so Python can find it
   [System.Environment]::SetEnvironmentVariable(
     "OQS_INSTALL_PATH", "C:\msys64\mingw64", "User"
   )

   # Also copy next to the Python executable for reliable loading
   $pydir = Split-Path (python -c "import sys; print(sys.executable)")
   Copy-Item C:\msys64\mingw64\bin\liboqs-9.dll "$pydir\oqs.dll"
   ```

4. **Verify the installation**:
   ```python
   import oqs
   print(oqs.get_version())
   ```

### Quick Start

#### 1. Generate a PQC Key Pair

```bash
nanasqlite-pqc-key-gen --algorithm Dilithium3 --prefix nana
```

This creates:
- `nana_private_pqc.json` — Secret key file (**keep this safe, never share**)
- `nana_public_pqc.pub` — Public key to register on the server

The `nana_public_pqc.pub` file contains a single line like:
```
oqs-Dilithium3:BASE64ENCODEDPUBLICKEY...
```

#### 2. Register the Public Key in accounts.json

```json
{
    "db_dir": "./data",
    "accounts": [
        {
            "name": "pqc_admin",
            "public_key": "oqs-Dilithium3:BASE64ENCODEDPUBLICKEY...",
            "allowed_methods": null,
            "allowed_dbs": ["main.sqlite"]
        }
    ]
}
```

The `public_key` value is the full content of `nana_public_pqc.pub` (without the trailing newline).

> **Mixed mode:** You can have both Ed25519 and PQC accounts in the same `accounts.json`. The server automatically detects the key type per account.

#### 3. Connect from the Client

```python
import asyncio
from nanasqlite_server.client import RemoteNanaSQLite

async def main():
    db = RemoteNanaSQLite(
        host="127.0.0.1",
        port=4433,
        pqc_key_path="nana_private_pqc.json",  # Use PQC authentication
    )
    await db.connect(account_name="pqc_admin")

    await db.set_item_async("key", "value")
    val = await db.get_item_async("key")
    print(f"Read back: {val}")

    await db.close()

asyncio.run(main())
```

### PQC Key File Format

**Private key** (`nana_private_pqc.json`):
```json
{
  "algorithm": "Dilithium3",
  "secret_key": "BASE64ENCODEDSECRETKEY..."
}
```

**Public key** (`nana_public_pqc.pub`):
```
oqs-Dilithium3:BASE64ENCODEDPUBLICKEY...
```

### Security Notes

- The transport layer (QUIC/TLS 1.3) is independent of the authentication key type. PQC authentication protects the **identity verification** step; the **transport** is protected by TLS 1.3 (classical).
- For full post-quantum security, a post-quantum TLS key exchange algorithm would also be needed. This is outside the scope of this feature.
- PQC signatures are generally larger than Ed25519 signatures. This has negligible impact on performance given they are only sent once per connection.
- The `nana_private_pqc.json` file should be protected with appropriate file-system permissions, just like `nana_private.pem`.

---

## 日本語

NanaSQLite-Server は [liboqs-python](https://github.com/open-quantum-safe/liboqs-python) を使用した**耐量子暗号 (PQC)** による認証をオプションでサポートしています。これにより、現在の非対称暗号（Ed25519 など）に対する将来の量子コンピュータ攻撃からシステムを保護できます。

> **注意:** PQC 認証は完全に**オプション**です。デフォルトの Ed25519 ベースの認証は、変更なしに引き続き機能します。

### 対応アルゴリズム

[liboqs](https://openquantumsafe.org/) が提供する任意の署名アルゴリズムを使用できます。主な選択肢：

| アルゴリズム | セキュリティレベル | 備考 |
|-------------|-----------------|------|
| `Dilithium2` | 2 (128ビット) | 高速、中程度の鍵サイズ |
| `Dilithium3` | 3 (192ビット) | **推奨デフォルト** |
| `Dilithium5` | 5 (256ビット) | 最高セキュリティ |
| `Falcon-512` | 1 (128ビット) | コンパクトな署名 |
| `Falcon-1024` | 5 (256ビット) | コンパクト、高セキュリティ |
| `SPHINCS+-SHA2-128f-simple` | 1 (128ビット) | ハッシュベース、保守的 |

> NIST は 2024 年に Dilithium (ML-DSA として) と Falcon (FN-DSA として) を標準化しました。Dilithium3 は実用的なデフォルト選択です。

### インストール

```bash
pip install "nanasqlite-server[pqc]"
```

または liboqs-python を別途インストール:

```bash
pip install liboqs-python
```

#### Windows — DLL のセットアップ

Windows では、`liboqs-python` はネイティブライブラリが必要です。[MSYS2](https://www.msys2.org/) 経由のインストールを推奨します。

1. **MSYS2 のインストール**: https://www.msys2.org/ から MSYS2 をインストールし、MSYS2 MinGW64 シェルを開きます。

2. **liboqs のインストール**:
   ```bash
   pacman -S mingw-w64-x86_64-liboqs
   ```

3. **DLL のコピーとリネーム** (Python バインディングは `oqs.dll` を探します):
   ```powershell
   # バージョン付き DLL を oqs.dll という名前でコピー（バインディングが oqs.dll を探すため）
   Copy-Item C:\msys64\mingw64\bin\liboqs-9.dll C:\msys64\mingw64\bin\oqs.dll

   # 環境変数に永続設定
   [System.Environment]::SetEnvironmentVariable(
     "OQS_INSTALL_PATH", "C:\msys64\mingw64", "User"
   )

   # Python の隣にもコピー（確実に認識させる）
   $pydir = Split-Path (python -c "import sys; print(sys.executable)")
   Copy-Item C:\msys64\mingw64\bin\liboqs-9.dll "$pydir\oqs.dll"
   ```

4. **インストールの確認**:
   ```python
   import oqs
   print(oqs.get_version())
   ```

### クイックスタート

#### 1. PQC 鍵ペアの生成

```bash
nanasqlite-pqc-key-gen --algorithm Dilithium3 --prefix nana
```

生成されるファイル:
- `nana_private_pqc.json` — 秘密鍵ファイル (**厳重に保管し、決して共有しないこと**)
- `nana_public_pqc.pub` — サーバーに登録する公開鍵

`nana_public_pqc.pub` ファイルには以下のような 1 行が含まれます:
```
oqs-Dilithium3:BASE64ENCODEDPUBLICKEY...
```

#### 2. accounts.json に公開鍵を登録

```json
{
    "db_dir": "./data",
    "accounts": [
        {
            "name": "pqc_admin",
            "public_key": "oqs-Dilithium3:BASE64ENCODEDPUBLICKEY...",
            "allowed_methods": null,
            "allowed_dbs": ["main.sqlite"]
        }
    ]
}
```

`public_key` の値は `nana_public_pqc.pub` の全内容（末尾の改行を除く）です。

> **混在モード:** 同じ `accounts.json` に Ed25519 と PQC のアカウントを混在させることができます。サーバーはアカウントごとに鍵の種類を自動検出します。

#### 3. クライアントからの接続

```python
import asyncio
from nanasqlite_server.client import RemoteNanaSQLite

async def main():
    db = RemoteNanaSQLite(
        host="127.0.0.1",
        port=4433,
        pqc_key_path="nana_private_pqc.json",  # PQC 認証を使用
    )
    await db.connect(account_name="pqc_admin")

    await db.set_item_async("key", "value")
    val = await db.get_item_async("key")
    print(f"Read back: {val}")

    await db.close()

asyncio.run(main())
```

### PQC 鍵ファイル形式

**秘密鍵** (`nana_private_pqc.json`):
```json
{
  "algorithm": "Dilithium3",
  "secret_key": "BASE64ENCODEDSECRETKEY..."
}
```

**公開鍵** (`nana_public_pqc.pub`):
```
oqs-Dilithium3:BASE64ENCODEDPUBLICKEY...
```

### セキュリティに関する注意

- トランスポート層 (QUIC/TLS 1.3) は認証鍵の種類に依存しません。PQC 認証は**身元確認**ステップを保護します。**通信**は TLS 1.3 (古典的暗号) で保護されます。
- 完全な耐量子セキュリティには、耐量子 TLS 鍵交換アルゴリズムも必要です。これはこの機能のスコープ外です。
- PQC 署名は一般に Ed25519 署名よりも大きいです。ただし、接続ごとに 1 回しか送信されないため、パフォーマンスへの影響はごくわずかです。
- `nana_private_pqc.json` ファイルは `nana_private.pem` と同様に、適切なファイルシステムのパーミッションで保護してください。
