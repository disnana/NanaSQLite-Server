"""
PoC: アカウント名バイパス脆弱性 (修正済み)

【概要】
v1.3.3 以前の `find_account_by_signature()` は `account_name_hint` が指定されて
いても、ヒントのアカウントで署名検証が失敗した場合に全アカウントを線形探索していた。
このため、「間違ったアカウント名を指定してもキーさえ正しければ認証が通る」状態だった。

【再現シナリオ】
1. サーバーに "admin" と "user1" の2アカウントが存在する。
2. 攻撃者は "user1" の秘密鍵を持っている。
3. 攻撃者が account_name="admin" (誤ったアカウント名) を指定して接続を試みる。

  修正前: "user1" のキーで "admin" の署名検証が失敗 → 線形探索で "user1" が
          見つかり → "user1" として認証成功。account_name の指定が無意味。

  修正後: ヒントで指定されたアカウント ("admin") の署名検証が失敗した時点で
          認証失敗 (None を返す)。他のアカウントへのフォールバックなし。

【このスクリプトの動作】
- `AccountManager` の `find_account_by_signature` を直接呼び出して動作を検証する。
- サーバーの起動は不要。
"""

import base64
import json
import secrets
import tempfile
import os
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


def make_ed25519_account_entry(name: str, private_key) -> dict:
    """Ed25519鍵ペアからaccounts.jsonエントリを生成する"""
    pub = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    ).decode()
    return {"name": name, "public_key": pub}


def run_poc():
    # --- 鍵ペア生成 ---
    admin_key = ed25519.Ed25519PrivateKey.generate()
    user1_key = ed25519.Ed25519PrivateKey.generate()

    challenge = secrets.token_bytes(32)

    # "user1" の秘密鍵で署名する
    user1_signature = user1_key.sign(challenge)

    with tempfile.TemporaryDirectory() as tmp:
        config_path = os.path.join(tmp, "accounts.json")
        config = {
            "accounts": [
                make_ed25519_account_entry("admin", admin_key),
                make_ed25519_account_entry("user1", user1_key),
            ]
        }
        with open(config_path, "w") as f:
            json.dump(config, f)

        from nanasqlite_server.accounts import AccountManager
        mgr = AccountManager(config_path)

        print("=" * 60)
        print("PoC: アカウント名バイパス脆弱性 (修正検証)")
        print("=" * 60)
        print()
        print("シナリオ: 攻撃者は 'user1' の秘密鍵を持ち、")
        print("          account_name='admin' (誤ったアカウント名) を指定する")
        print()

        # --- テスト1: 誤ったアカウント名 + user1のキーでの署名 ---
        result = mgr.find_account_by_signature(
            user1_signature, challenge, account_name_hint="admin"
        )
        print("[テスト1] account_name_hint='admin', 署名='user1'のキー")
        if result is None:
            print("  [OK] 修正済み: 認証失敗 (None が返された)")
            print("       間違ったアカウント名では認証が通らない")
        else:
            print(f"  [NG] 脆弱: 認証成功 (account={result.name}) ← 修正が必要！")
        print()

        # --- テスト2: 正しいアカウント名 + 正しいキー (正常動作を確認) ---
        result_ok = mgr.find_account_by_signature(
            user1_signature, challenge, account_name_hint="user1"
        )
        print("[テスト2] account_name_hint='user1', 署名='user1'のキー (正常ケース)")
        if result_ok and result_ok.name == "user1":
            print("  [OK] 正常: 認証成功 (account=user1)")
        else:
            print("  [NG] エラー: 正常な認証が失敗した")
        print()

        # --- テスト3: ヒントなし + user1のキー (後方互換性確認) ---
        result_no_hint = mgr.find_account_by_signature(
            user1_signature, challenge, account_name_hint=None
        )
        print("[テスト3] account_name_hint=None (ヒントなし), 署名='user1'のキー")
        if result_no_hint and result_no_hint.name == "user1":
            print("  [OK] 後方互換: ヒントなしでは線形探索で user1 が見つかる")
        else:
            print("  [NG] エラー: 後方互換性が破壊されている")
        print()

        # --- テスト4: 存在しないアカウント名を指定 ---
        result_unknown = mgr.find_account_by_signature(
            user1_signature, challenge, account_name_hint="nonexistent_account"
        )
        print("[テスト4] account_name_hint='nonexistent_account' (存在しないアカウント)")
        if result_unknown is None:
            print("  [OK] 修正済み: 存在しないアカウント名は認証失敗")
        else:
            print(f"  [NG] 脆弱: 認証成功 (account={result_unknown.name}) ← 修正が必要！")

        print()
        print("=" * 60)


if __name__ == "__main__":
    run_poc()
