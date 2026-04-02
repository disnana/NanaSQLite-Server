import os
import ormsgpack
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


def encode_message(data):
    """データをシリアライズし、サイズヘッダーを付けて返す"""
    payload = ormsgpack.packb(data)
    header = struct.pack("!I", len(payload))
    return header + payload


def decode_message(data):
    """シリアライズされたデータを復元する"""
    if len(data) < 4:
        return None, data

    length = struct.unpack("!I", data[:4])[0]
    if len(data) < 4 + length:
        return None, data

    payload = data[4 : 4 + length]
    rest = data[4 + length :]
    return ormsgpack.unpackb(payload), rest


def derive_session_key(shared_secret: bytes) -> bytes:
    """共有秘密からHKDF-SHA256を使って256ビットAESセッション鍵を導出する。

    Args:
        shared_secret: KEM(Key Encapsulation Mechanism)から得た共有秘密バイト列

    Returns:
        32バイトのAES-256セッション鍵
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"nanasqlite-pqc-session",
    )
    return hkdf.derive(shared_secret)


def encrypt_message(data, session_key: bytes) -> bytes:
    """AES-256-GCMを使ってメッセージを暗号化する。

    フォーマット: [4バイト長ヘッダー][12バイトnonce][暗号文+16バイトGCMタグ]

    Args:
        data: 暗号化するデータ (msgpackシリアライズ可能なオブジェクト)
        session_key: 32バイトのAES-256セッション鍵

    Returns:
        ヘッダー付き暗号化メッセージバイト列
    """
    payload = ormsgpack.packb(data)
    nonce = os.urandom(12)
    ciphertext = AESGCM(session_key).encrypt(nonce, payload, None)
    body = nonce + ciphertext  # 12バイトnonce + 暗号文+16バイトタグ
    header = struct.pack("!I", len(body))
    return header + body


def decrypt_message(data: bytes, session_key: bytes):
    """AES-256-GCMで暗号化されたメッセージを復号する。

    Args:
        data: 暗号化されたメッセージバイト列 (ヘッダー含む)
        session_key: 32バイトのAES-256セッション鍵

    Returns:
        (復号されたメッセージ, 残りのデータ) のタプル。
        復号に失敗した場合は (None, 残りのデータ) を返す。
    """
    if len(data) < 4:
        return None, data

    length = struct.unpack("!I", data[:4])[0]
    if len(data) < 4 + length:
        return None, data

    body = data[4 : 4 + length]
    rest = data[4 + length :]

    # nonce(12) + tag(16) の最小サイズを確認
    if len(body) < 28:
        return None, rest

    nonce = body[:12]
    ciphertext = body[12:]
    try:
        plaintext = AESGCM(session_key).decrypt(nonce, ciphertext, None)
        return ormsgpack.unpackb(plaintext), rest
    except Exception:
        return None, rest
