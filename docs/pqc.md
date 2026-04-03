# Post-Quantum Cryptography (PQC) 耐量子暗号 ガイド

[English](#english) | [日本語](#日本語)

---

## English

NanaSQLite-Server optionally supports **post-quantum cryptography (PQC)** via [liboqs-python](https://github.com/open-quantum-safe/liboqs-python) for two independent layers of protection:

1. **PQC Authentication** (signature) — identity verification using Dilithium, Falcon, or SPHINCS+
2. **PQC Session Encryption** (KEM + AES-256-GCM) — post-auth key exchange using Kyber/ML-KEM, followed by encrypted communication

> **Note:** Both features are fully **optional**. The default Ed25519-based authentication and unencrypted (but TLS 1.3-protected) communication continue to work without any changes.

### Supported Algorithms

#### Signature Algorithms (for authentication)

| Algorithm | Security Level | Notes |
|-----------|---------------|-------|
| `Dilithium2` | 2 (128-bit) | Fast, moderate key size |
| `Dilithium3` | 3 (192-bit) | **Recommended default** |
| `Dilithium5` | 5 (256-bit) | Highest security |
| `Falcon-512` | 1 (128-bit) | Compact signatures |
| `Falcon-1024` | 5 (256-bit) | Compact, high security |
| `SPHINCS+-SHA2-128f-simple` | 1 (128-bit) | Hash-based, conservative |

> NIST standardized Dilithium (as ML-DSA) and Falcon (as FN-DSA) in 2024. Dilithium3 is a practical default choice.

#### KEM Algorithms (for session key exchange)

| Algorithm | Security Level | Notes |
|-----------|---------------|-------|
| `Kyber512` | 1 (128-bit) | Fast, smaller keys |
| `Kyber768` | 3 (192-bit) | **Recommended default** |
| `Kyber1024` | 5 (256-bit) | Highest security |
| `ML-KEM-768` | 3 (192-bit) | NIST FIPS 203 standard name |

> NIST standardized Kyber as ML-KEM (FIPS 203) in 2024. Kyber768 is a practical default choice.

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

---

## Feature 2: PQC Session Encryption (`--pqc-kem`)

After successful authentication, the server can perform a **post-quantum KEM key exchange** with the client, then use the resulting shared secret to derive an **AES-256-GCM session key**. All subsequent RPC messages in that connection are encrypted at the application level.

### Protocol Flow

```
CLIENT                              SERVER
  AUTH_START ─────────────────────►
             ◄──── challenge ────────
  sign(challenge) ─────────────────►
             ◄──── {type:"auth_ok", kem:{algorithm, pubkey}} ──

  # KEM encapsulation (client side)
  ciphertext, client_ss = kem.encap(server_pubkey)
  session_key = HKDF(client_ss)

  {type:"kem_response", ciphertext} ►
             ◄────────── "KEM_OK" ──
  # server: server_ss = kem.decap(ciphertext)
  #         session_key = HKDF(server_ss)

  [AES-256-GCM encrypted RPC messages]  ◄──────────────────────►
```

### Starting the Server with PQC KEM Encryption

```bash
nanasqlite-server --pqc-kem Kyber768
```

With all PQC features:
```bash
nanasqlite-server --pqc-kem Kyber768  # Kyber768 KEM + AES-256-GCM session encryption
```

> `--pqc-kem` requires `liboqs-python`. If it is not installed, the server will refuse to start.

### Client — KEM Exchange is Automatic

When the server offers KEM, the client handles it automatically in `connect()`:

```python
db = RemoteNanaSQLite(
    host="127.0.0.1",
    port=4433,
    pqc_key_path="nana_private_pqc.json",  # PQC signature auth (optional)
)
await db.connect(account_name="pqc_admin")
# If server has --pqc-kem, session key is established automatically.
# All subsequent calls are transparently encrypted.
await db.set_item_async("key", "value")
```

If the server is started with `--pqc-kem`, the client **must** have `liboqs-python` installed to complete the KEM exchange. Without it, `connect()` will raise a `RuntimeError` and close the connection, since the server requires KEM completion before accepting any RPC.

### Security Notes

- **Transport security**: QUIC/TLS 1.3 encrypts the transport layer regardless of PQC settings. `--pqc-kem` adds an **application-level** encryption layer on top of TLS 1.3, providing defense-in-depth against future quantum attacks on the TLS key exchange.
- **Forward secrecy**: A new ephemeral KEM keypair is generated per connection. Compromising one session key does not affect other sessions.
- **Authentication integrity**: PQC authentication (`oqs-<ALG>:...` public key) and PQC session encryption (`--pqc-kem`) are independent. You can use either, both, or neither.
- **Session key derivation**: HKDF-SHA256 with context `nanasqlite-pqc-session` is used to derive the 256-bit AES key from the KEM shared secret.
- **Encryption scheme**: AES-256-GCM with a random 96-bit nonce per message. The 128-bit authentication tag provides message integrity.
- The `nana_private_pqc.json` file should be protected with appropriate filesystem permissions, just like `nana_private.pem`.

---

## 日本語

NanaSQLite-Server は [liboqs-python](https://github.com/open-quantum-safe/liboqs-python) を使用した**耐量子暗号 (PQC)** を 2 つの独立したレイヤーでオプションサポートしています：

1. **PQC 認証** (署名) — Dilithium・Falcon・SPHINCS+ による身元確認
2. **PQC セッション暗号化** (KEM + AES-256-GCM) — Kyber/ML-KEM による認証後鍵交換と暗号化通信

> **注意:** 両機能は完全に**オプション**です。デフォルトの Ed25519 ベースの認証と (TLS 1.3 で保護された) 暗号化されていないアプリケーション層の通信は、変更なしに引き続き機能します。

### 対応アルゴリズム

#### 署名アルゴリズム (認証用)

| アルゴリズム | セキュリティレベル | 備考 |
|-------------|-----------------|------|
| `Dilithium2` | 2 (128ビット) | 高速、中程度の鍵サイズ |
| `Dilithium3` | 3 (192ビット) | **推奨デフォルト** |
| `Dilithium5` | 5 (256ビット) | 最高セキュリティ |
| `Falcon-512` | 1 (128ビット) | コンパクトな署名 |
| `Falcon-1024` | 5 (256ビット) | コンパクト、高セキュリティ |
| `SPHINCS+-SHA2-128f-simple` | 1 (128ビット) | ハッシュベース、保守的 |

> NIST は 2024 年に Dilithium (ML-DSA として) と Falcon (FN-DSA として) を標準化しました。Dilithium3 は実用的なデフォルト選択です。

#### KEM アルゴリズム (セッション鍵交換用)

| アルゴリズム | セキュリティレベル | 備考 |
|-------------|-----------------|------|
| `Kyber512` | 1 (128ビット) | 高速、小さい鍵 |
| `Kyber768` | 3 (192ビット) | **推奨デフォルト** |
| `Kyber1024` | 5 (256ビット) | 最高セキュリティ |
| `ML-KEM-768` | 3 (192ビット) | NIST FIPS 203 標準名 |

> NIST は 2024 年に Kyber を ML-KEM (FIPS 203) として標準化しました。Kyber768 は実用的なデフォルト選択です。

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
   pacman -Syu
   pacman -S mingw-w64-x86_64-liboqs
   ```

3. **DLL のコピーとリネーム** (Python バインディングは `oqs.dll` を探します):
   ```powershell
   # バージョン付き DLL を oqs.dll という名前でコピー（バインディングが oqs.dll を探すため。今回の例では-9だが変わる場合がある）
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

---

## 機能2: PQC セッション暗号化 (`--pqc-kem`)

認証成功後、サーバーはクライアントと **耐量子 KEM 鍵交換** を行い、得られた共有秘密から **AES-256-GCM セッション鍵** を導出します。以降のすべての RPC メッセージはアプリケーション層で暗号化されます。

### プロトコルフロー

```
クライアント                           サーバー
  AUTH_START ──────────────────────►
              ◄── チャレンジ ──────────
  sign(チャレンジ) ────────────────────►
              ◄── {type:"auth_ok", kem:{algorithm, pubkey}} ──

  # KEM カプセル化 (クライアント側)
  ciphertext, client_ss = kem.encap(server_pubkey)
  session_key = HKDF(client_ss)

  {type:"kem_response", ciphertext} ──►
              ◄───────── "KEM_OK" ──
  # サーバー: server_ss = kem.decap(ciphertext)
  #           session_key = HKDF(server_ss)

  [AES-256-GCM 暗号化された RPC メッセージ]  ◄─────────────────────────────────►
```

### PQC KEM 暗号化でサーバーを起動する

```bash
nanasqlite-server --pqc-kem Kyber768
```

PQC 機能をすべて使用する場合:
```bash
nanasqlite-server --pqc-kem Kyber768
# クライアントは PQC 署名認証 (pqc_key_path) と組み合わせて使用可能
```

> `--pqc-kem` は `liboqs-python` が必要です。インストールされていない場合、サーバーは起動を拒否します。

### クライアント — KEM 交換は自動

サーバーが KEM を提示すると、クライアントは `connect()` 内で自動的に処理します:

```python
db = RemoteNanaSQLite(
    host="127.0.0.1",
    port=4433,
    pqc_key_path="nana_private_pqc.json",  # PQC 署名認証 (任意)
)
await db.connect(account_name="pqc_admin")
# サーバーに --pqc-kem が設定されていれば、セッション鍵が自動的に確立されます。
# 以降のすべての呼び出しは透過的に暗号化されます。
await db.set_item_async("key", "value")
```

サーバーを `--pqc-kem` 付きで起動した場合、クライアントも `liboqs-python` がインストールされている必要があります。インストールされていない場合、`connect()` は `RuntimeError` を送出して接続を閉じます。サーバーは KEM 交換が完了するまで RPC を受け付けないためです。

### セキュリティに関する注意

- **トランスポートセキュリティ**: QUIC/TLS 1.3 は PQC 設定に関わらずトランスポート層を暗号化します。`--pqc-kem` は TLS 1.3 の上に**アプリケーション層**の暗号化を追加し、TLS 鍵交換への将来の量子攻撃に対する多層防御を実現します。
- **前方秘匿性 (Forward Secrecy)**: 接続ごとに新しいエフェメラル KEM 鍵ペアが生成されます。1 つのセッション鍵が漏洩しても他のセッションには影響しません。
- **認証との独立性**: PQC 認証 (`oqs-<ALG>:...` 公開鍵) と PQC セッション暗号化 (`--pqc-kem`) は独立しています。どちらか一方、両方、またはどちらも使用しないことができます。
- **セッション鍵導出**: KEM 共有秘密から 256 ビット AES 鍵を導出するために、コンテキスト `nanasqlite-pqc-session` を持つ HKDF-SHA256 を使用します。
- **暗号化方式**: メッセージごとにランダムな 96 ビット nonce を使用する AES-256-GCM。128 ビット認証タグがメッセージの整合性を提供します。
- `nana_private_pqc.json` ファイルは `nana_private.pem` と同様に、適切なファイルシステムのパーミッションで保護してください。
- PQC 署名は一般に Ed25519 署名よりも大きいです。ただし、接続ごとに 1 回しか送信されないため、パフォーマンスへの影響はごくわずかです。
