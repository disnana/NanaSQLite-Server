import os
import json
import sys

# プロジェクトルートをインポートパスに追加
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.nanasqlite_server.cert_gen import generate_certificate
from src.nanasqlite_server.key_gen import generate_keys

def setup():
    print("Setting up example files...")
    
    # exampleディレクトリに移動してファイルを生成
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    # 1. サーバー用証明書の生成 (cert.pem, key.pem)
    generate_certificate("cert.pem", "key.pem")
    
    # 2. クライアント用Ed25519キーペアの生成 (nana_private.pem, nana_public.pub)
    generate_keys("nana")
    
    # 3. アカウント設定ファイルの作成 (accounts.json)
    # 生成した公開鍵を読み込む
    with open("nana_public.pub", "r") as f:
        public_key = f.read().strip()
    
    accounts = {
        "accounts": [
            {
                "name": "example_user",
                "public_key": public_key,
                "allowed_methods": None,  # Noneは制限なし
                "forbidden_methods": []
            }
        ]
    }
    
    with open("accounts.json", "w") as f:
        json.dump(accounts, f, indent=4)
    
    print("\nSetup complete!")
    print("Files created:")
    print(" - cert.pem, key.pem (Server SSL/TLS)")
    print(" - nana_private.pem (Client Private Key)")
    print(" - nana_public.pub (Client Public Key)")
    print(" - accounts.json (Server Account Configuration)")

if __name__ == "__main__":
    setup()
