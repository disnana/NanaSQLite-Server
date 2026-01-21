import json
import os
import time
import logging
from cryptography.hazmat.primitives import serialization

class Account:
    def __init__(self, name, public_key_pem, allowed_methods=None, forbidden_methods=None):
        self.name = name
        self.public_key_pem = public_key_pem
        self.allowed_methods = set(allowed_methods) if allowed_methods else None
        self.forbidden_methods = set(forbidden_methods) if forbidden_methods else None

        # 公開鍵オブジェクトを事前にロード
        try:
            self.public_key = serialization.load_ssh_public_key(public_key_pem.encode() if isinstance(public_key_pem, str) else public_key_pem)
        except Exception as e:
            logging.error(f"Failed to load public key for account {name}: {e}")
            self.public_key = None

class AccountManager:
    def __init__(self, config_path="accounts.json", default_public_key=None):
        self.config_path = config_path
        self.accounts = []
        self.last_loaded = 0
        self.default_public_key = default_public_key
        self._load_throttle_interval = 1.0  # I/O負荷軽減のため、最低1秒は再チェックを控える
        self._last_checked = 0
        self.load_accounts()

    def load_accounts(self, force=False):
        now = time.time()
        # テスト環境など、即時性が極めて重要な場合は _load_throttle_interval を 0 に設定可能
        if not force and now - self._last_checked < self._load_throttle_interval:
            return
        self._last_checked = now

        if not os.path.exists(self.config_path):
            if self.default_public_key:
                # 従来の動作との互換性のため、デフォルトの公開鍵でadminアカウントを自動作成
                self.accounts = [Account("default_admin", self.default_public_key)]
            else:
                self.accounts = []
            return

        try:
            mtime = os.path.getmtime(self.config_path)
            if not force and mtime <= self.last_loaded:
                return

            with open(self.config_path, "r") as f:
                data = json.load(f)

            new_accounts = []
            for acc_data in data.get("accounts", []):
                new_accounts.append(Account(
                    acc_data["name"],
                    acc_data["public_key"],
                    acc_data.get("allowed_methods"),
                    acc_data.get("forbidden_methods")
                ))

            self.accounts = new_accounts
            self.last_loaded = mtime
            logging.info(f"Loaded {len(self.accounts)} accounts from {self.config_path}")
        except Exception as e:
            logging.error(f"Error loading accounts: {e}")

    def find_account_by_name(self, name):
        """名前でアカウントを検索する (キャッシュを使用)"""
        self.load_accounts()
        for account in self.accounts:
            if account.name == name:
                return account
        return None

    def find_account_by_signature(self, signature, challenge, account_name_hint=None):
        """署名を検証して、対応するアカウントを返す"""
        # リクエストごとに再読み込みをチェック (即時反映のため)
        self.load_accounts()

        # アカウント名のヒントがある場合は、まずそのアカウントを検証 (CPU負荷軽減)
        if account_name_hint:
            account = self.find_account_by_name(account_name_hint)
            if account and account.public_key:
                try:
                    account.public_key.verify(signature, challenge)
                    return account
                except Exception:
                    # ヒントが間違っていた場合は通常の線形探索へ進む（後方互換性のため）
                    pass

        for account in self.accounts:
            if not account.public_key:
                continue
            try:
                account.public_key.verify(signature, challenge)
                return account
            except Exception:
                continue
        return None
