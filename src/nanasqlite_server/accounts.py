import json
import os
import logging
import asyncio
from cryptography.hazmat.primitives import serialization
from watchfiles import awatch

class Account:
    def __init__(self, name, public_key_pem, allowed_methods=None, forbidden_methods=None):
        self.name = name
        self.public_key_pem = public_key_pem
        self.allowed_methods = set(allowed_methods) if allowed_methods is not None else None
        self.forbidden_methods = set(forbidden_methods) if forbidden_methods is not None else None

        # 公開鍵オブジェクトを事前にロード
        try:
            self.public_key = serialization.load_ssh_public_key(
                public_key_pem.encode() if isinstance(public_key_pem, str) else public_key_pem
            )
        except Exception as e:
            logging.error(f"Failed to load public key for account {name}: {e}")
            self.public_key = None

class AccountManager:
    def __init__(self, config_path="accounts.json", default_public_key=None):
        self.config_path = os.path.abspath(config_path)
        self.accounts = []
        self.default_public_key = default_public_key
        self._watcher_task = None
        self._stop_event = asyncio.Event()

        # 初回読み込み
        self._do_load()

    def _do_load(self):
        """実際にファイルを読み込む内部メソッド"""
        if not os.path.exists(self.config_path):
            if self.default_public_key:
                # 互換性のため
                self.accounts = [Account("default_admin", self.default_public_key)]
            else:
                self.accounts = []
            return

        try:
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
            logging.info(f"Loaded {len(self.accounts)} accounts from {self.config_path}")
        except Exception as e:
            logging.error(f"Error loading accounts from {self.config_path}: {e}")

    async def watch(self):
        """ファイルを監視して自動更新するバックグラウンドタスク"""
        logging.info(f"Starting file watcher for {self.config_path}")

        # ディレクトリを監視 (ファイル自体だと削除・再作成に弱いため)
        dir_to_watch = os.path.dirname(self.config_path)
        if not dir_to_watch:
            dir_to_watch = "."

        async for changes in awatch(dir_to_watch, stop_event=self._stop_event):
            for change_type, file_path in changes:
                if os.path.abspath(file_path) == self.config_path:
                    logging.info(f"Account config changed detected: {file_path}")
                    self._do_load()

    def start_watching(self):
        """監視タスクを開始"""
        if self._watcher_task is None:
            self._stop_event.clear()
            self._watcher_task = asyncio.create_task(self.watch())

    async def stop_watching(self):
        """監視タスクを停止"""
        if self._watcher_task:
            self._stop_event.set()
            try:
                # 監視タスクの終了を待機
                await asyncio.wait_for(self._watcher_task, timeout=2.0)
            except Exception:
                # タイムアウトした場合はキャンセル
                self._watcher_task.cancel()
                try:
                    await self._watcher_task
                except asyncio.CancelledError:
                    # Ignore cancellation error during shutdown
                    pass
            self._watcher_task = None

    def find_account_by_name(self, name):
        """名前でアカウントを検索する"""
        for account in self.accounts:
            if account.name == name:
                return account
        return None

    def find_account_by_signature(self, signature, challenge, account_name_hint=None):
        """署名を検証して、対応するアカウントを返す"""
        # アカウント名のヒントがある場合は、まずそのアカウントを検証 (CPU負荷軽減)
        if account_name_hint:
            account = self.find_account_by_name(account_name_hint)
            if account and account.public_key:
                try:
                    account.public_key.verify(signature, challenge)
                    return account
                except Exception:
                    # Invalid signature for this account hint, but we allow fall-through to linear search
                    pass

        # 線形探索 (後方互換性)
        for account in self.accounts:
            if not account.public_key:
                continue
            try:
                account.public_key.verify(signature, challenge)
                return account
            except Exception:
                # Signature verification failed for this account, try next one
                continue
        return None
