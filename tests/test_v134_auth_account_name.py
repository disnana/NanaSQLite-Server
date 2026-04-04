"""
NanaSQLite-Server v1.3.4 テスト

アカウント名の厳格検証 (account_name_hint の strict enforcement)

【修正内容】
v1.3.3 以前は `find_account_by_signature` が `account_name_hint` を指定されても
署名検証失敗時に全アカウントへ線形フォールバックしていた。
v1.3.4 ではヒントが指定された場合は指定アカウントのみを検証し、
不一致の場合は即座に None を返すよう変更した。
"""

import asyncio
import json
import os
import signal
import ssl
import subprocess
import sys
import time

import pytest
from aioquic.asyncio import connect
from aioquic.quic.configuration import QuicConfiguration
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from nanasqlite_server.accounts import Account, AccountManager
from nanasqlite_server.cert_gen import generate_certificate
from nanasqlite_server.client import RemoteNanaSQLite
from nanasqlite_server.key_gen import generate_keys


# ---------------------------------------------------------------------------
# ユニットテスト: find_account_by_signature の厳格検証
# ---------------------------------------------------------------------------


def make_account_with_key(name: str):
    """Ed25519 鍵ペアとそれに紐づく Account を生成して返す"""
    priv = ed25519.Ed25519PrivateKey.generate()
    pub_bytes = (
        priv.public_key()
        .public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH,
        )
        .decode()
    )
    account = Account(name, pub_bytes)
    return priv, account


class TestFindAccountBySignatureStrictMode:
    """find_account_by_signature のアカウント名厳格検証テスト"""

    def _make_manager_with_accounts(self, tmp_path, accounts_data):
        """指定アカウント一覧を持つ AccountManager を返す"""
        config = {
            "accounts": [
                {"name": acc.name, "public_key": acc.public_key_pem}
                for acc in accounts_data
            ]
        }
        path = tmp_path / "accounts.json"
        path.write_text(json.dumps(config))
        return AccountManager(str(path))

    def test_wrong_account_name_hint_fails(self, tmp_path):
        """誤ったアカウント名ヒント + 有効な署名 → 認証失敗"""
        import secrets

        admin_key, admin_acc = make_account_with_key("admin")
        user1_key, user1_acc = make_account_with_key("user1")

        mgr = self._make_manager_with_accounts(tmp_path, [admin_acc, user1_acc])
        challenge = secrets.token_bytes(32)

        # user1 のキーで署名し、admin を名乗る
        user1_sig = user1_key.sign(challenge)
        result = mgr.find_account_by_signature(user1_sig, challenge, account_name_hint="admin")

        assert result is None, (
            "誤ったアカウント名ヒントで認証が通ってはいけない"
        )

    def test_correct_account_name_hint_succeeds(self, tmp_path):
        """正しいアカウント名ヒント + 有効な署名 → 認証成功"""
        import secrets

        user1_key, user1_acc = make_account_with_key("user1")
        mgr = self._make_manager_with_accounts(tmp_path, [user1_acc])
        challenge = secrets.token_bytes(32)

        user1_sig = user1_key.sign(challenge)
        result = mgr.find_account_by_signature(user1_sig, challenge, account_name_hint="user1")

        assert result is not None
        assert result.name == "user1"

    def test_nonexistent_account_name_hint_fails(self, tmp_path):
        """存在しないアカウント名ヒント → 認証失敗 (フォールバックなし)"""
        import secrets

        user1_key, user1_acc = make_account_with_key("user1")
        mgr = self._make_manager_with_accounts(tmp_path, [user1_acc])
        challenge = secrets.token_bytes(32)

        user1_sig = user1_key.sign(challenge)
        result = mgr.find_account_by_signature(
            user1_sig, challenge, account_name_hint="nonexistent"
        )

        assert result is None, (
            "存在しないアカウント名ヒントでフォールバックが起きてはいけない"
        )

    def test_no_hint_finds_by_linear_search(self, tmp_path):
        """ヒントなし → 線形探索で対応アカウントを返す (後方互換性)"""
        import secrets

        user1_key, user1_acc = make_account_with_key("user1")
        user2_key, user2_acc = make_account_with_key("user2")
        mgr = self._make_manager_with_accounts(tmp_path, [user1_acc, user2_acc])
        challenge = secrets.token_bytes(32)

        user2_sig = user2_key.sign(challenge)
        # ヒントなしでも user2 を見つけられる
        result = mgr.find_account_by_signature(user2_sig, challenge, account_name_hint=None)

        assert result is not None
        assert result.name == "user2"

    def test_hint_wrong_key_does_not_fallthrough_to_valid_account(self, tmp_path):
        """
        ヒントに指定したアカウントが存在するが署名が不一致の場合、
        別の有効なアカウントへフォールバックしない (セキュリティの核心)
        """
        import secrets

        admin_key, admin_acc = make_account_with_key("admin")
        user1_key, user1_acc = make_account_with_key("user1")
        mgr = self._make_manager_with_accounts(tmp_path, [admin_acc, user1_acc])
        challenge = secrets.token_bytes(32)

        # user1 のキーで署名し、admin を名乗る
        user1_sig = user1_key.sign(challenge)
        result = mgr.find_account_by_signature(
            user1_sig, challenge, account_name_hint="admin"
        )

        # admin のキーで署名していないため admin には一致しない
        # かつ user1 へのフォールバックも起こらない → None
        assert result is None

    def test_invalid_signature_with_correct_hint_fails(self, tmp_path):
        """正しいアカウント名ヒント + 無効な署名 → 認証失敗"""
        import secrets

        user1_key, user1_acc = make_account_with_key("user1")
        mgr = self._make_manager_with_accounts(tmp_path, [user1_acc])
        challenge = secrets.token_bytes(32)

        # 全く無効な署名バイト列
        invalid_sig = b"not_a_real_signature"
        result = mgr.find_account_by_signature(
            invalid_sig, challenge, account_name_hint="user1"
        )
        assert result is None


# ---------------------------------------------------------------------------
# 統合テスト: 専用サーバーを使ったアカウント名検証テスト
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def v134_keys():
    """テスト用の Ed25519 鍵ペア (モジュール全体で1回生成)"""
    admin_key = ed25519.Ed25519PrivateKey.generate()
    admin_pub = (
        admin_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH,
        )
        .decode()
    )
    user1_key = ed25519.Ed25519PrivateKey.generate()
    user1_pub = (
        user1_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH,
        )
        .decode()
    )
    return admin_key, admin_pub, user1_key, user1_pub


@pytest.fixture(scope="module")
def v134_server(tmp_path_factory, v134_keys):
    """v1.3.4 テスト用の専用サーバー (モジュール全体で1回起動)"""
    admin_key, admin_pub, user1_key, user1_pub = v134_keys
    tmp_path = tmp_path_factory.mktemp("v134")
    db_dir = str(tmp_path)
    config_path = tmp_path / "accounts.json"

    orig_cwd = os.getcwd()
    os.chdir(tmp_path)
    proc = None
    log_file = None
    try:
        generate_certificate()
        generate_keys()

        import socket

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()

        # 2アカウントを設定: admin と user1
        with open(config_path, "w") as f:
            json.dump(
                {
                    "db_dir": db_dir,
                    "accounts": [
                        {
                            "name": "admin",
                            "public_key": admin_pub,
                            "allowed_dbs": ["v134_test.sqlite"],
                        },
                        {
                            "name": "user1",
                            "public_key": user1_pub,
                            "allowed_dbs": ["v134_test.sqlite"],
                        },
                    ],
                },
                f,
            )

        env = os.environ.copy()
        env["PYTHONPATH"] = orig_cwd + os.pathsep + os.path.join(orig_cwd, "src")
        env["NANASQLITE_FORCE_POLLING"] = "1"
        env["NANASQLITE_DISABLE_BAN"] = "1"

        db_path = tmp_path / "v134_test.sqlite"
        cmd = [
            sys.executable,
            "-m",
            "nanasqlite_server.server",
            "--port",
            str(port),
            "--accounts",
            str(config_path),
            "--db",
            str(db_path),
        ]

        log_file_path = tmp_path / "v134_server.log"
        log_file = open(log_file_path, "w", encoding="utf-8")

        kwargs = {}
        if sys.platform == "win32":
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP

        proc = subprocess.Popen(
            cmd, env=env, stdout=log_file, stderr=subprocess.STDOUT, text=True, **kwargs
        )

        # サーバー起動待ち
        quic_config = QuicConfiguration(is_client=True, verify_mode=ssl.CERT_NONE)
        start_wait = time.time()
        server_ready = False
        loop = asyncio.new_event_loop()
        try:
            while time.time() - start_wait < 60.0:
                if proc.poll() is not None:
                    break

                async def _check():
                    try:
                        async with connect("127.0.0.1", port, configuration=quic_config):
                            return True
                    except Exception:
                        return False

                if loop.run_until_complete(_check()):
                    server_ready = True
                    break
                time.sleep(1.0)
        finally:
            loop.close()

        if not server_ready:
            log_file.close()
            with open(log_file_path, "r", encoding="utf-8") as f:
                content = f.read()
            raise RuntimeError(f"v134 server failed to start.\nLog:\n{content}")

        yield port, config_path, admin_key, admin_pub, user1_key, user1_pub, db_dir

    finally:
        if proc and proc.poll() is None:
            try:
                if sys.platform == "win32":
                    os.kill(proc.pid, signal.CTRL_BREAK_EVENT)
                else:
                    proc.send_signal(signal.SIGINT)
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
            except Exception:
                if proc:
                    proc.kill()
                    proc.wait()
        if log_file:
            log_file.close()
        os.chdir(orig_cwd)


@pytest.mark.asyncio
async def test_correct_account_name_auth_succeeds(v134_server):
    """正しいアカウント名 + 対応する鍵 → 認証成功 (正常ケース)"""
    port, config_path, admin_key, admin_pub, user1_key, user1_pub, db_dir = v134_server

    client = RemoteNanaSQLite(host="127.0.0.1", port=port, verify_ssl=False)
    client.private_key = user1_key
    try:
        await client.connect(account_name="user1")
        result = await client.list_tables(db="v134_test.sqlite")
        assert result is not None
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_wrong_account_name_auth_fails(v134_server):
    """誤ったアカウント名 + 有効な鍵 → 認証失敗"""
    port, config_path, admin_key, admin_pub, user1_key, user1_pub, db_dir = v134_server

    # user1 のキーを持ちながら "admin" を名乗って接続を試みる
    client = RemoteNanaSQLite(host="127.0.0.1", port=port, verify_ssl=False)
    client.private_key = user1_key
    try:
        with pytest.raises(PermissionError):
            await client.connect(account_name="admin")
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_nonexistent_account_name_auth_fails(v134_server):
    """存在しないアカウント名 + 有効な鍵 → 認証失敗"""
    port, config_path, admin_key, admin_pub, user1_key, user1_pub, db_dir = v134_server

    client = RemoteNanaSQLite(host="127.0.0.1", port=port, verify_ssl=False)
    client.private_key = user1_key
    try:
        with pytest.raises(PermissionError):
            await client.connect(account_name="does_not_exist")
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_no_account_name_auth_succeeds_by_linear_search(v134_server):
    """account_name 未指定 + 有効な鍵 → 線形探索で認証成功 (後方互換性)"""
    port, config_path, admin_key, admin_pub, user1_key, user1_pub, db_dir = v134_server

    client = RemoteNanaSQLite(host="127.0.0.1", port=port, verify_ssl=False)
    client.private_key = user1_key
    try:
        # account_name 未指定 → サーバー側で線形探索 → user1 が見つかる
        await client.connect()
        result = await client.list_tables(db="v134_test.sqlite")
        assert result is not None
    finally:
        await client.close()
