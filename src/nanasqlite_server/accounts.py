import base64
import json
import os
import logging
import asyncio
from cryptography.hazmat.primitives import serialization

# watchfiles が環境にない場合のフォールバック（CI安定性のため）
try:
    from watchfiles import awatch

    HAS_WATCHFILES = True
except ImportError:
    HAS_WATCHFILES = False
    logging.warning("watchfiles not found, falling back to polling.")

# liboqs-python サポート (オプション: pip install liboqs-python)
# 耐量子暗号 (PQC) による認証を有効にする
try:
    import oqs  # type: ignore[import]

    HAS_OQS = True
except (ImportError, SystemExit):
    oqs = None  # type: ignore[assignment]
    HAS_OQS = False

# PQC公開鍵フォーマットのプレフィックス
OQS_KEY_PREFIX = "oqs-"


class Account:
    def __init__(
        self,
        name,
        public_key_pem,
        allowed_methods=None,
        forbidden_methods=None,
        allowed_dbs=None,
        read_only=False,
    ):
        self.name = name
        self.public_key_pem = public_key_pem
        self.allowed_methods = (
            set(allowed_methods) if allowed_methods is not None else None
        )
        self.forbidden_methods = (
            set(forbidden_methods) if forbidden_methods is not None else None
        )
        self.read_only = bool(read_only)

        # allowed_dbs は以下の形式をサポート:
        #   None                          → 全DB無制限
        #   ["db1.sqlite", "db2.sqlite"]  → 後方互換: 各DBに対し全テーブル許可
        #   {"db1.sqlite": None, "db2.sqlite": ["t1", "t2"]}
        #                                 → DB毎にテーブルを制限 (None=全テーブル許可)
        # 内部では常に dict[str, set[str] | None] として保持する
        if allowed_dbs is None:
            self.allowed_dbs: dict[str, set[str] | None] | None = None
        elif isinstance(allowed_dbs, list):
            # 後方互換: リスト → 全テーブル許可の辞書に変換
            self.allowed_dbs = {db: None for db in allowed_dbs}
        else:
            # 辞書形式: 値が list の場合は set に変換、None はそのまま
            self.allowed_dbs = {
                db: (set(tables) if tables is not None else None)
                for db, tables in allowed_dbs.items()
            }

        key_str = (
            public_key_pem.decode()
            if isinstance(public_key_pem, bytes)
            else public_key_pem
        )

        # OQS PQC公開鍵の検出: "oqs-<ALGORITHM>:<BASE64>" 形式
        if isinstance(key_str, str) and key_str.startswith(OQS_KEY_PREFIX):
            self.key_type = "oqs"
            self.public_key = None
            self.pqc_algorithm = None
            self.pqc_public_key_bytes = None
            try:
                # "oqs-Dilithium3:BASE64..." の解析
                header, b64_key = key_str.split(":", 1)
                self.pqc_algorithm = header[len(OQS_KEY_PREFIX):]
                self.pqc_public_key_bytes = base64.b64decode(b64_key.strip())
            except Exception as e:
                logging.error(f"Failed to load PQC public key for account {name}: {e}")
        else:
            # 従来の Ed25519 公開鍵
            self.key_type = "ed25519"
            self.pqc_algorithm = None
            self.pqc_public_key_bytes = None
            try:
                self.public_key = serialization.load_ssh_public_key(
                    public_key_pem.encode()
                    if isinstance(public_key_pem, str)
                    else public_key_pem
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
        self._load_throttle_interval = 1.0
        self._last_checked = 0
        self.db_dir = "."

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

            self.db_dir = data.get("db_dir", ".")
            # db_dir が存在しない場合は自動作成する
            if not os.path.isdir(self.db_dir):
                try:
                    os.makedirs(self.db_dir, exist_ok=True)
                    logging.warning(
                        f"Database directory '{self.db_dir}' did not exist and was created automatically."
                    )
                except OSError as e:
                    logging.error(
                        f"Failed to create database directory '{self.db_dir}': {e}"
                    )
            new_accounts = []
            for acc_data in data.get("accounts", []):
                new_accounts.append(
                    Account(
                        acc_data["name"],
                        acc_data["public_key"],
                        acc_data.get("allowed_methods"),
                        acc_data.get("forbidden_methods"),
                        acc_data.get("allowed_dbs"),
                        acc_data.get("read_only", False),
                    )
                )

            self.accounts = new_accounts
            logging.info(
                f"Loaded {len(self.accounts)} accounts from {self.config_path}"
            )
        except Exception as e:
            logging.error(f"Error loading accounts from {self.config_path}: {e}")

    async def watch(self):
        """ファイルを監視して自動更新するバックグラウンドタスク"""
        # CI環境や特定の環境でwatchfilesが不安定な場合はポーリングを強制
        force_polling = os.environ.get("NANASQLITE_FORCE_POLLING") == "1"
        try:
            if not HAS_WATCHFILES or force_polling:
                # ポーリングによるフォールバック
                while not self._stop_event.is_set():
                    try:
                        await asyncio.sleep(self._load_throttle_interval)
                        self._do_load()
                    except asyncio.CancelledError:
                        break
                return

            logging.info(f"Starting file watcher for {self.config_path}")
            dir_to_watch = os.path.dirname(self.config_path)
            if not dir_to_watch:
                dir_to_watch = "."

            try:
                async for changes in awatch(dir_to_watch, stop_event=self._stop_event):
                    for _, file_path in changes:
                        if os.path.abspath(file_path) == self.config_path:
                            logging.info(f"Account config change detected: {file_path}")
                            self._do_load()
            except asyncio.CancelledError:
                pass
            except Exception as e:
                logging.error(f"Error in file watcher: {e}")
                # エラー発生時はポーリングに切り替え
                while not self._stop_event.is_set():
                    try:
                        await asyncio.sleep(5.0)
                        self._do_load()
                    except asyncio.CancelledError:
                        break
        finally:
            logging.info("File watcher task stopped")

    def start_watching(self):
        """監視タスクを開始"""
        if self._watcher_task is None:
            self._stop_event.clear()
            self._watcher_task = asyncio.create_task(self.watch())

    async def stop_watching(self):
        """監視タスクを停止"""
        if self._watcher_task:
            self._stop_event.set()
            # 監視タスクの終了を待機。タスク内で CancelledError は処理済み
            try:
                # まずは待ってみる
                await asyncio.wait_for(asyncio.shield(self._watcher_task), timeout=1.0)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                # 終わらなければキャンセル
                self._watcher_task.cancel()
                try:
                    await asyncio.wait_for(self._watcher_task, timeout=1.0)
                except Exception:
                    pass
            self._watcher_task = None

    def _verify_account_signature(self, account, signature, challenge):
        """署名を検証する (Ed25519 または OQS PQC 対応)

        Args:
            account: 検証対象のアカウント
            signature: クライアントから受信した署名バイト列
            challenge: サーバーが送付したチャレンジバイト列

        Returns:
            bool: 署名が有効な場合 True
        """
        if account.key_type == "oqs":
            if not HAS_OQS:
                logging.error(
                    "PQC signature verification requested but liboqs-python is not "
                    "installed. Install with: pip install liboqs-python"
                )
                return False
            if not account.pqc_public_key_bytes or not account.pqc_algorithm:
                logging.warning(
                    "PQC account '%s' has no public key or algorithm configured",
                    account.name,
                )
                return False
            try:
                with oqs.Signature(account.pqc_algorithm) as verifier:
                    return bool(verifier.verify(challenge, signature, account.pqc_public_key_bytes))
            except Exception as e:
                logging.warning(
                    "PQC signature verification failed for account '%s' "
                    "(algorithm=%r): %s",
                    account.name,
                    account.pqc_algorithm,
                    e,
                )
                return False
        else:
            # 従来の Ed25519 検証
            if not account.public_key:
                return False
            try:
                account.public_key.verify(signature, challenge)
                return True
            except Exception:
                return False

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
            if account:
                if self._verify_account_signature(account, signature, challenge):
                    return account

        # 線形探索 (後方互換性)
        for account in self.accounts:
            if self._verify_account_signature(account, signature, challenge):
                return account
        return None
