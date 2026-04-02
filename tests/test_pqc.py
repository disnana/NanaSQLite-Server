"""
PQC (Post-Quantum Cryptography) サポートのテスト

liboqs-python が利用できる場合に PQC 鍵の生成、アカウント登録、
署名検証、KEM鍵交換、暗号化通信が正しく動作することを検証します。
liboqs-python がインストールされていない場合は全テストをスキップします。
"""

import base64
import json
import os
import secrets
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
except (ImportError, SystemExit):
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
        from nanasqlite_server import key_gen as kg_module

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


class TestProtocolEncryptDecrypt:
    """AES-256-GCM 暗号化/復号のテスト (liboqs 不要)"""

    # このクラスのテストは liboqs なしでも動作する
    # ただし pytestmark により liboqs がない場合はスキップされる

    def test_derive_session_key_deterministic(self):
        """同じ共有秘密から常に同じセッション鍵が導出されることを確認"""
        from nanasqlite_server import protocol

        shared = b"test_shared_secret_32_bytes_here!"
        key1 = protocol.derive_session_key(shared)
        key2 = protocol.derive_session_key(shared)
        assert key1 == key2
        assert len(key1) == 32  # 256-bit

    def test_derive_session_key_different_inputs(self):
        """異なる共有秘密から異なるセッション鍵が導出されることを確認"""
        from nanasqlite_server import protocol

        key1 = protocol.derive_session_key(b"secret_a")
        key2 = protocol.derive_session_key(b"secret_b")
        assert key1 != key2

    def test_encrypt_decrypt_roundtrip_dict(self):
        """辞書データの暗号化→復号が正しく動作することを確認"""
        from nanasqlite_server import protocol

        session_key = os.urandom(32)
        data = {"method": "get_item_async", "args": ["key"], "kwargs": {}}
        encrypted = protocol.encrypt_message(data, session_key)
        decrypted, rest = protocol.decrypt_message(encrypted, session_key)
        assert decrypted == data
        assert rest == b""

    def test_encrypt_decrypt_roundtrip_string(self):
        """文字列の暗号化→復号が正しく動作することを確認"""
        from nanasqlite_server import protocol

        session_key = os.urandom(32)
        data = "AUTH_OK"
        encrypted = protocol.encrypt_message(data, session_key)
        decrypted, rest = protocol.decrypt_message(encrypted, session_key)
        assert decrypted == data
        assert rest == b""

    def test_encrypt_nonce_is_random(self):
        """同じデータの暗号化でも毎回異なる暗号文が生成されることを確認"""
        from nanasqlite_server import protocol

        session_key = os.urandom(32)
        data = {"test": "value"}
        enc1 = protocol.encrypt_message(data, session_key)
        enc2 = protocol.encrypt_message(data, session_key)
        assert enc1 != enc2  # nonce がランダムのため毎回異なる

    def test_decrypt_wrong_key_returns_none(self):
        """異なるセッション鍵で復号した場合 None が返されることを確認"""
        from nanasqlite_server import protocol

        key1 = os.urandom(32)
        key2 = os.urandom(32)
        encrypted = protocol.encrypt_message({"test": 1}, key1)
        decrypted, _ = protocol.decrypt_message(encrypted, key2)
        assert decrypted is None

    def test_decrypt_tampered_ciphertext_returns_none(self):
        """改ざんされた暗号文の復号で None が返されることを確認 (AEADの整合性検証)"""
        from nanasqlite_server import protocol

        session_key = os.urandom(32)
        encrypted = bytearray(protocol.encrypt_message({"test": 1}, session_key))
        # 最後のバイトを改ざん
        encrypted[-1] ^= 0xFF
        decrypted, _ = protocol.decrypt_message(bytes(encrypted), session_key)
        assert decrypted is None

    def test_decrypt_truncated_data_returns_none(self):
        """データが途中で切れた場合に None が返されることを確認"""
        from nanasqlite_server import protocol

        session_key = os.urandom(32)
        encrypted = protocol.encrypt_message("hello", session_key)
        decrypted, _ = protocol.decrypt_message(encrypted[:10], session_key)
        assert decrypted is None

    def test_decrypt_empty_data_returns_none(self):
        """空データの復号で None が返されることを確認"""
        from nanasqlite_server import protocol

        decrypted, rest = protocol.decrypt_message(b"", os.urandom(32))
        assert decrypted is None


class TestPqcKemExchange:
    """PQC KEM 鍵交換のテスト (liboqs 必須)"""

    def test_kem_kyber768_shared_secret_matches(self):
        """Kyber768 KEM でクライアントとサーバーの共有秘密が一致することを確認"""
        with oqs.KeyEncapsulation("Kyber768") as kem_server:
            server_pubkey = kem_server.generate_keypair()
            with oqs.KeyEncapsulation("Kyber768") as kem_client:
                ciphertext, client_ss = kem_client.encap_secret(server_pubkey)
            server_ss = kem_server.decap_secret(ciphertext)
        assert client_ss == server_ss

    def test_kem_derived_session_keys_match(self):
        """KEM で交換した共有秘密から導出したセッション鍵が一致することを確認"""
        from nanasqlite_server import protocol

        with oqs.KeyEncapsulation("Kyber768") as kem_server:
            server_pubkey = kem_server.generate_keypair()
            with oqs.KeyEncapsulation("Kyber768") as kem_client:
                ciphertext, client_ss = kem_client.encap_secret(server_pubkey)
            server_ss = kem_server.decap_secret(ciphertext)

        client_key = protocol.derive_session_key(client_ss)
        server_key = protocol.derive_session_key(server_ss)
        assert client_key == server_key
        assert len(client_key) == 32

    def test_kem_encrypted_message_roundtrip(self):
        """KEM で交換したセッション鍵で暗号化→復号が正しく動作することを確認"""
        from nanasqlite_server import protocol

        with oqs.KeyEncapsulation("Kyber768") as kem_server:
            server_pubkey = kem_server.generate_keypair()
            with oqs.KeyEncapsulation("Kyber768") as kem_client:
                ciphertext, client_ss = kem_client.encap_secret(server_pubkey)
            kem_server.decap_secret(ciphertext)

        session_key = protocol.derive_session_key(client_ss)
        data = {"method": "get_item_async", "args": ["test_key"], "kwargs": {}}

        # サーバーが暗号化、クライアントが復号 (同じセッション鍵)
        encrypted = protocol.encrypt_message(data, session_key)
        decrypted, _ = protocol.decrypt_message(encrypted, session_key)
        assert decrypted == data

    def test_kem_different_connections_have_different_keys(self):
        """接続ごとに異なるKEM鍵ペアが生成されることを確認 (前方秘匿性)"""
        from nanasqlite_server import protocol

        session_keys = set()
        for _ in range(3):
            with oqs.KeyEncapsulation("Kyber768") as kem_server:
                server_pubkey = kem_server.generate_keypair()
                with oqs.KeyEncapsulation("Kyber768") as kem_client:
                    ciphertext, client_ss = kem_client.encap_secret(server_pubkey)
                server_ss = kem_server.decap_secret(ciphertext)
            session_key = protocol.derive_session_key(server_ss)
            session_keys.add(session_key)

        # 3回全て異なるセッション鍵が生成されるべき
        assert len(session_keys) == 3

    def test_kem_free_releases_instance(self):
        """KEM インスタンスの free() が正しく動作することを確認"""
        kem = oqs.KeyEncapsulation("Kyber768")
        kem.generate_keypair()
        # free() がエラーなく呼べることを確認
        kem.free()
