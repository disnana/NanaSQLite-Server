import base64
import json
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

# liboqs-python サポート (オプション: pip install liboqs-python)
try:
    import oqs  # type: ignore[import]

    HAS_OQS = True
except ImportError:
    oqs = None  # type: ignore[assignment]
    HAS_OQS = False


def generate_keys(prefix="nana"):
    """Ed25519の秘密鍵と公開鍵を生成して保存する"""
    print(f"Generating Ed25519 key pair with prefix: {prefix}")

    # 秘密鍵の生成
    private_key = ed25519.Ed25519PrivateKey.generate()

    # 公開鍵の取得
    public_key = private_key.public_key()

    # 秘密鍵の保存 (PEM形式)
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(f"{prefix}_private.pem", "wb") as f:
        f.write(private_bytes)

    # 公開鍵の保存 (PEM形式)
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    )
    with open(f"{prefix}_public.pub", "wb") as f:
        f.write(public_bytes)

    print("Done! Created:")
    print(f" - Private Key: {prefix}_private.pem (Keep this secret!)")
    print(f" - Public Key:  {prefix}_public.pub  (Register this on the server)")


if __name__ == "__main__":
    generate_keys()


def generate_pqc_keys(algorithm="Dilithium3", prefix="nana"):
    """OQS PQC 署名鍵ペアを生成して保存する。

    Args:
        algorithm: OQS署名アルゴリズム名 (例: "Dilithium3", "Falcon-512", "SPHINCS+-SHA2-128f-simple")
        prefix: 出力ファイルのプレフィックス (デフォルト: "nana")

    生成されるファイル:
        - {prefix}_private_pqc.json: 秘密鍵 (JSON形式, 秘密厳守)
        - {prefix}_public_pqc.pub:   公開鍵 (accounts.json に登録する)

    Raises:
        ImportError: liboqs-python がインストールされていない場合
        ValueError: 指定されたアルゴリズムがサポートされていない場合
    """
    if not HAS_OQS:
        raise ImportError(
            "liboqs-python is required for PQC key generation.\n"
            "Install with: pip install liboqs-python\n"
            "See docs/pqc.md for platform-specific installation instructions."
        )

    print(f"Generating OQS PQC key pair: algorithm={algorithm}, prefix={prefix}")

    try:
        with oqs.Signature(algorithm) as signer:
            public_key_bytes = signer.generate_keypair()
            secret_key_bytes = signer.export_secret_key()
    except Exception as e:
        raise ValueError(
            f"Failed to generate keys for algorithm '{algorithm}': {e}\n"
            f"Available algorithms can be listed with: python -c \"import oqs; print(oqs.get_enabled_sig_mechanisms())\""
        ) from e

    # 秘密鍵の保存 (JSON形式)
    private_data = {
        "algorithm": algorithm,
        "secret_key": base64.b64encode(secret_key_bytes).decode(),
    }
    private_path = f"{prefix}_private_pqc.json"
    with open(private_path, "w") as f:
        json.dump(private_data, f, indent=2)

    # 公開鍵の保存 (テキスト形式: "oqs-<ALGORITHM>:<BASE64>")
    public_key_str = f"oqs-{algorithm}:{base64.b64encode(public_key_bytes).decode()}"
    public_path = f"{prefix}_public_pqc.pub"
    with open(public_path, "w") as f:
        f.write(public_key_str + "\n")

    print("Done! Created PQC key pair:")
    print(f" - Private Key: {private_path} (Keep this secret!)")
    print(f" - Public Key:  {public_path}  (Register this on the server)")
    print("\nAdd the following to accounts.json:")
    print(f'  "public_key": "{public_key_str}"')


def generate_pqc_keys_sync():
    """PQC鍵生成のCLIエントリーポイント"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Generate OQS post-quantum cryptography key pair for NanaSQLite-Server"
    )
    parser.add_argument(
        "--algorithm",
        type=str,
        default="Dilithium3",
        help="OQS signature algorithm (default: Dilithium3). "
             "Examples: Dilithium3, Falcon-512, SPHINCS+-SHA2-128f-simple",
    )
    parser.add_argument(
        "--prefix",
        type=str,
        default="nana",
        help="Output file prefix (default: nana)",
    )
    args = parser.parse_args()
    generate_pqc_keys(algorithm=args.algorithm, prefix=args.prefix)
