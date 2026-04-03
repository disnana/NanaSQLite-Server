"""
protocol.py の暗号化/復号ユニットテスト

AES-256-GCM のメッセージ暗号化・復号、HKDF セッション鍵導出のテスト。
これらのテストは liboqs-python なしで実行できます。
"""

import os

from nanasqlite_server import protocol


class TestDeriveSessionKey:
    """HKDF セッション鍵導出のテスト"""

    def test_derive_session_key_length(self):
        """セッション鍵が 32 バイト (256 ビット) であることを確認"""
        key = protocol.derive_session_key(b"shared_secret")
        assert len(key) == 32

    def test_derive_session_key_deterministic(self):
        """同じ入力から常に同じ鍵が導出されることを確認"""
        key1 = protocol.derive_session_key(b"same_secret")
        key2 = protocol.derive_session_key(b"same_secret")
        assert key1 == key2

    def test_derive_session_key_different_inputs(self):
        """異なる共有秘密から異なる鍵が導出されることを確認"""
        key1 = protocol.derive_session_key(b"secret_a")
        key2 = protocol.derive_session_key(b"secret_b")
        assert key1 != key2

    def test_derive_session_key_produces_bytes(self):
        """セッション鍵がバイト列であることを確認"""
        key = protocol.derive_session_key(os.urandom(32))
        assert isinstance(key, bytes)


class TestEncryptDecryptMessage:
    """AES-256-GCM 暗号化/復号のテスト"""

    def test_encrypt_decrypt_roundtrip_dict(self):
        """辞書データの暗号化→復号が一致することを確認"""
        session_key = os.urandom(32)
        data = {"method": "get_item_async", "args": ["key"], "kwargs": {}}
        encrypted = protocol.encrypt_message(data, session_key)
        decrypted, rest = protocol.decrypt_message(encrypted, session_key)
        assert decrypted == data
        assert rest == b""

    def test_encrypt_decrypt_roundtrip_string(self):
        """文字列の暗号化→復号が一致することを確認"""
        session_key = os.urandom(32)
        encrypted = protocol.encrypt_message("AUTH_OK", session_key)
        decrypted, rest = protocol.decrypt_message(encrypted, session_key)
        assert decrypted == "AUTH_OK"
        assert rest == b""

    def test_encrypt_decrypt_roundtrip_none(self):
        """None 値の暗号化→復号が一致することを確認"""
        session_key = os.urandom(32)
        encrypted = protocol.encrypt_message(None, session_key)
        decrypted, _ = protocol.decrypt_message(encrypted, session_key)
        assert decrypted is None

    def test_encrypt_nonce_is_random(self):
        """同じデータを暗号化しても毎回異なる暗号文になることを確認"""
        session_key = os.urandom(32)
        data = {"test": "value"}
        enc1 = protocol.encrypt_message(data, session_key)
        enc2 = protocol.encrypt_message(data, session_key)
        assert enc1 != enc2

    def test_encrypted_message_has_length_header(self):
        """暗号化メッセージが 4 バイトの長さヘッダーを持つことを確認"""
        import struct

        session_key = os.urandom(32)
        encrypted = protocol.encrypt_message("test", session_key)
        assert len(encrypted) >= 4
        length = struct.unpack("!I", encrypted[:4])[0]
        assert len(encrypted) == 4 + length

    def test_decrypt_wrong_key_returns_none(self):
        """異なる鍵で復号すると None が返されることを確認"""
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        encrypted = protocol.encrypt_message({"test": 1}, key1)
        decrypted, _ = protocol.decrypt_message(encrypted, key2)
        assert decrypted is None

    def test_decrypt_tampered_ciphertext_returns_none(self):
        """改ざんされた暗号文の復号で None が返されることを確認"""
        session_key = os.urandom(32)
        encrypted = bytearray(protocol.encrypt_message({"test": 1}, session_key))
        encrypted[-1] ^= 0xFF  # 最後のバイトを反転
        decrypted, _ = protocol.decrypt_message(bytes(encrypted), session_key)
        assert decrypted is None

    def test_decrypt_truncated_data_returns_none(self):
        """途中で切れたデータの復号で None が返されることを確認"""
        session_key = os.urandom(32)
        encrypted = protocol.encrypt_message("hello", session_key)
        decrypted, _ = protocol.decrypt_message(encrypted[:10], session_key)
        assert decrypted is None

    def test_decrypt_empty_data_returns_none(self):
        """空データの復号で None が返されることを確認"""
        decrypted, rest = protocol.decrypt_message(b"", os.urandom(32))
        assert decrypted is None
        assert rest == b""

    def test_decrypt_too_short_body_returns_none(self):
        """最小サイズ (nonce+tag=28バイト) 未満の本体で None が返されることを確認"""
        import struct

        session_key = os.urandom(32)
        # 長さヘッダーが 10 を示すが本体は 10 バイト (28バイト未満)
        bad_data = struct.pack("!I", 10) + bytes(10)
        decrypted, _ = protocol.decrypt_message(bad_data, session_key)
        assert decrypted is None

    def test_encrypt_output_format(self):
        """暗号化出力のフォーマット確認: [4-byte length | 12-byte nonce | ciphertext+tag]"""
        import struct

        session_key = os.urandom(32)
        data = "test"
        encrypted = protocol.encrypt_message(data, session_key)

        # 4バイトのヘッダーを読む
        length = struct.unpack("!I", encrypted[:4])[0]
        body = encrypted[4:]
        assert len(body) == length
        # body の最初の 12 バイトが nonce
        assert length >= 12 + 16  # nonce + minimum GCM tag

    def test_original_decode_message_unaffected(self):
        """既存の decode_message() が引き続き動作することを確認 (後方互換性)"""
        data = {"key": "value", "number": 42}
        encoded = protocol.encode_message(data)
        decoded, rest = protocol.decode_message(encoded)
        assert decoded == data
        assert rest == b""
