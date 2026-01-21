from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


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
