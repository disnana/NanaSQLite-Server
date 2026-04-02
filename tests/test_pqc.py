"""
PQC (Post-Quantum Cryptography) サポートのテスト

liboqs-python が利用できる場合に PQC 鍵の生成、アカウント登録、
署名検証が正しく動作することを検証します。
liboqs-python がインストールされていない場合は全テストをスキップします。
"""

import base64
import json
import os
import sys
import pytest

# プロジェクトルートとsrcをパスに追加
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
src_dir = os.path.join(project_root, "src")
for p in (project_root, src_dir):
    if p not in sys.path:
        sys.path.insert(0, p)

# liboqs が利用できるか確認
try:
    import oqs
    HAS_OQS = True
except ImportError:
    oqs = None
    HAS_OQS = False

pytestmark = pytest.mark.skipif(
    not HAS_OQS,
    reason="liboqs-python is not installed. Install with: pip install liboqs-python",
)


@pytest.fixture(scope="session")
def pqc_keypair():
    """Dilithium3 鍵ペアを生成して返す (セッション内で再利用)"""
    with oqs.Signature("Dilithium3") as signer:
        public_key_bytes = signer.generate_keypair()
        secret_key_bytes = signer.export_secret_key()
    return {
        "algorithm": "Dilithium3",
        "public_key_bytes": public_key_bytes,
        "secret_key_bytes": secret_key_bytes,
        "public_key_str": f"oqs-Dilithium3:{base64.b64encode(public_key_bytes).decode()}",
    }


class TestPqcKeyGeneration:
    """PQC 鍵生成のテスト"""

    def test_generate_pqc_keys_creates_files(self, tmp_path, monkeypatch):
        """generate_pqc_keys() が正しくファイルを作成することを確認"""
        monkeypatch.chdir(tmp_path)
        from nanasqlite_server.key_gen import generate_pqc_keys

        generate_pqc_keys(algorithm="Dilithium3", prefix="test")

        private_path = tmp_path / "test_private_pqc.json"
        public_path = tmp_path / "test_public_pqc.pub"

        assert private_path.exists(), "Private key file should be created"
        assert public_path.exists(), "Public key file should be created"

    def test_private_key_file_format(self, tmp_path, monkeypatch):
        """秘密鍵ファイルが正しい JSON 形式であることを確認"""
        monkeypatch.chdir(tmp_path)
        from nanasqlite_server.key_gen import generate_pqc_keys

        generate_pqc_keys(algorithm="Dilithium3", prefix="test")

        with open(tmp_path / "test_private_pqc.json") as f:
            data = json.load(f)

        assert data["algorithm"] == "Dilithium3"
        assert "secret_key" in data
        # Base64 デコードできることを確認
        decoded = base64.b64decode(data["secret_key"])
        assert len(decoded) > 0

    def test_public_key_file_format(self, tmp_path, monkeypatch):
        """公開鍵ファイルが正しい形式であることを確認"""
        monkeypatch.chdir(tmp_path)
        from nanasqlite_server.key_gen import generate_pqc_keys

        generate_pqc_keys(algorithm="Dilithium3", prefix="test")

        with open(tmp_path / "test_public_pqc.pub") as f:
            content = f.read().strip()

        assert content.startswith("oqs-Dilithium3:"), (
            f"Public key should start with 'oqs-Dilithium3:', got: {content[:50]}"
        )
        # Base64 部分がデコードできることを確認
        b64_part = content.split(":", 1)[1]
        decoded = base64.b64decode(b64_part)
        assert len(decoded) > 0

    def test_generate_pqc_keys_no_oqs_raises(self, monkeypatch):
        """liboqs-python がない場合に ImportError が発生することを確認"""
        import nanasqlite_server.key_gen as kg_module

        # HAS_OQS を一時的に False に設定
        monkeypatch.setattr(kg_module, "HAS_OQS", False)
        with pytest.raises(ImportError, match="liboqs-python"):
            kg_module.generate_pqc_keys()


class TestPqcAccount:
    """PQC アカウントの作成と署名検証のテスト"""

    def test_account_detects_pqc_key(self, pqc_keypair):
        """Account クラスが PQC 公開鍵を正しく検出することを確認"""
        from nanasqlite_server.accounts import Account

        account = Account(
            name="pqc_user",
            public_key_pem=pqc_keypair["public_key_str"],
        )

        assert account.key_type == "oqs"
        assert account.pqc_algorithm == "Dilithium3"
        assert account.pqc_public_key_bytes is not None
        assert account.public_key is None  # Ed25519 key should not be set

    def test_account_detects_ed25519_key(self):
        """Account クラスが Ed25519 公開鍵を正しく検出することを確認"""
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization
        from nanasqlite_server.accounts import Account

        priv = ed25519.Ed25519PrivateKey.generate()
        pub = priv.public_key()
        pub_bytes = pub.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH,
        )

        account = Account(name="ed_user", public_key_pem=pub_bytes.decode())

        assert account.key_type == "ed25519"
        assert account.pqc_algorithm is None
        assert account.pqc_public_key_bytes is None
        assert account.public_key is not None

    def test_pqc_signature_verification(self, pqc_keypair):
        """PQC 署名の検証が正しく動作することを確認"""
        from nanasqlite_server.accounts import Account, AccountManager
        import secrets

        challenge = secrets.token_bytes(32)

        # 署名
        with oqs.Signature(
            pqc_keypair["algorithm"], pqc_keypair["secret_key_bytes"]
        ) as signer:
            signature = signer.sign(challenge)

        account = Account(
            name="pqc_user",
            public_key_pem=pqc_keypair["public_key_str"],
        )

        # _verify_account_signature をテスト
        manager = object.__new__(AccountManager)
        result = manager._verify_account_signature(account, signature, challenge)
        assert result is True

    def test_pqc_wrong_signature_rejected(self, pqc_keypair):
        """誤った PQC 署名が拒否されることを確認"""
        from nanasqlite_server.accounts import Account, AccountManager
        import secrets

        challenge = secrets.token_bytes(32)
        wrong_signature = secrets.token_bytes(64)  # ランダムバイト = 不正な署名

        account = Account(
            name="pqc_user",
            public_key_pem=pqc_keypair["public_key_str"],
        )

        manager = object.__new__(AccountManager)
        result = manager._verify_account_signature(account, wrong_signature, challenge)
        assert result is False

    def test_find_account_by_pqc_signature(self, pqc_keypair):
        """AccountManager が PQC 署名でアカウントを検索できることを確認"""
        from nanasqlite_server.accounts import Account, AccountManager
        import secrets

        challenge = secrets.token_bytes(32)

        # 署名
        with oqs.Signature(
            pqc_keypair["algorithm"], pqc_keypair["secret_key_bytes"]
        ) as signer:
            signature = signer.sign(challenge)

        account = Account(
            name="pqc_user",
            public_key_pem=pqc_keypair["public_key_str"],
        )

        manager = object.__new__(AccountManager)
        manager.accounts = [account]

        found = manager.find_account_by_signature(signature, challenge, "pqc_user")
        assert found is not None
        assert found.name == "pqc_user"

    def test_find_account_pqc_wrong_signature_returns_none(self, pqc_keypair):
        """誤った署名では None が返されることを確認"""
        from nanasqlite_server.accounts import Account, AccountManager
        import secrets

        challenge = secrets.token_bytes(32)
        wrong_signature = secrets.token_bytes(64)

        account = Account(
            name="pqc_user",
            public_key_pem=pqc_keypair["public_key_str"],
        )

        manager = object.__new__(AccountManager)
        manager.accounts = [account]

        found = manager.find_account_by_signature(wrong_signature, challenge)
        assert found is None


class TestPqcKeyFormat:
    """PQC 公開鍵フォーマットのテスト"""

    def test_invalid_pqc_key_format_handled_gracefully(self):
        """不正な PQC 鍵フォーマットが適切に処理されることを確認"""
        from nanasqlite_server.accounts import Account

        account = Account(
            name="bad_pqc_user",
            public_key_pem="oqs-Dilithium3:NOT_VALID_BASE64!!!",
        )

        # エラーで例外が出ずに、属性が None になっていることを確認
        assert account.key_type == "oqs"
        assert account.pqc_public_key_bytes is None

    def test_mixed_accounts_verification(self, pqc_keypair):
        """Ed25519 と PQC アカウントが混在する場合の検索をテスト"""
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization
        from nanasqlite_server.accounts import Account, AccountManager
        import secrets

        # Ed25519 アカウント
        priv = ed25519.Ed25519PrivateKey.generate()
        pub = priv.public_key()
        pub_bytes = pub.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH,
        )
        ed_account = Account(name="ed_user", public_key_pem=pub_bytes.decode())

        # PQC アカウント
        pqc_account = Account(
            name="pqc_user",
            public_key_pem=pqc_keypair["public_key_str"],
        )

        manager = object.__new__(AccountManager)
        manager.accounts = [ed_account, pqc_account]

        challenge = secrets.token_bytes(32)

        # PQC 署名で PQC アカウントが見つかることを確認
        with oqs.Signature(
            pqc_keypair["algorithm"], pqc_keypair["secret_key_bytes"]
        ) as signer:
            pqc_sig = signer.sign(challenge)

        found = manager.find_account_by_signature(pqc_sig, challenge)
        assert found is not None
        assert found.name == "pqc_user"

        # Ed25519 署名で Ed25519 アカウントが見つかることを確認
        ed_sig = priv.sign(challenge)
        found_ed = manager.find_account_by_signature(ed_sig, challenge)
        assert found_ed is not None
        assert found_ed.name == "ed_user"
