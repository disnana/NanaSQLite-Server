"""
NanaSQLite-Server v1.3.3 新機能テスト

1. read_only フラグ
2. DB名に紐づくテーブル名の動的制限
3. エラー情報の隠蔽強化
"""

import asyncio
import json
import os
import ssl
import sys
import signal
import subprocess
import time
import pytest

from aioquic.asyncio import connect
from aioquic.quic.configuration import QuicConfiguration
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from nanasqlite_server.accounts import Account, AccountManager
from nanasqlite_server.client import RemoteNanaSQLite
from nanasqlite_server.cert_gen import generate_certificate
from nanasqlite_server.key_gen import generate_keys


# ---------------------------------------------------------------------------
# ユニットテスト: Account / AccountManager
# ---------------------------------------------------------------------------


class TestAccountReadOnly:
    """read_only フラグの Account クラス単体テスト"""

    def test_read_only_default_false(self):
        acc = Account("user", "ssh-ed25519 AAAA fake_key")
        assert acc.read_only is False

    def test_read_only_true(self):
        acc = Account("viewer", "ssh-ed25519 AAAA fake_key", read_only=True)
        assert acc.read_only is True

    def test_read_only_false_explicit(self):
        acc = Account("admin", "ssh-ed25519 AAAA fake_key", read_only=False)
        assert acc.read_only is False


class TestAccountAllowedDbsFormat:
    """allowed_dbs の各フォーマット変換テスト"""

    def test_none_stays_none(self):
        acc = Account("u", "k", allowed_dbs=None)
        assert acc.allowed_dbs is None

    def test_list_converted_to_dict(self):
        acc = Account("u", "k", allowed_dbs=["a.sqlite", "b.sqlite"])
        assert isinstance(acc.allowed_dbs, dict)
        assert acc.allowed_dbs == {"a.sqlite": None, "b.sqlite": None}

    def test_dict_with_none_values(self):
        acc = Account("u", "k", allowed_dbs={"a.sqlite": None})
        assert acc.allowed_dbs == {"a.sqlite": None}

    def test_dict_with_table_list(self):
        acc = Account("u", "k", allowed_dbs={"a.sqlite": ["tbl1", "tbl2"]})
        assert acc.allowed_dbs == {"a.sqlite": {"tbl1", "tbl2"}}

    def test_dict_mixed(self):
        acc = Account(
            "u",
            "k",
            allowed_dbs={"logs.sqlite": None, "data.sqlite": ["public_info", "stats"]},
        )
        assert acc.allowed_dbs["logs.sqlite"] is None
        assert acc.allowed_dbs["data.sqlite"] == {"public_info", "stats"}

    def test_empty_list(self):
        acc = Account("u", "k", allowed_dbs=[])
        assert acc.allowed_dbs == {}


class TestAccountManagerLoadReadOnly:
    """AccountManager._do_load が read_only を正しく読み込むテスト"""

    def test_load_read_only_from_json(self, tmp_path):
        config = {
            "accounts": [
                {"name": "viewer", "public_key": "ssh-ed25519 AAAA fake", "read_only": True},
                {"name": "admin", "public_key": "ssh-ed25519 AAAA fake2"},
            ]
        }
        path = tmp_path / "accounts.json"
        path.write_text(json.dumps(config))
        mgr = AccountManager(str(path))
        assert mgr.accounts[0].read_only is True
        assert mgr.accounts[1].read_only is False

    def test_load_allowed_dbs_dict_from_json(self, tmp_path):
        config = {
            "accounts": [
                {
                    "name": "limited",
                    "public_key": "ssh-ed25519 AAAA fake",
                    "allowed_dbs": {"data.sqlite": ["t1", "t2"]},
                }
            ]
        }
        path = tmp_path / "accounts.json"
        path.write_text(json.dumps(config))
        mgr = AccountManager(str(path))
        acc = mgr.accounts[0]
        assert acc.allowed_dbs == {"data.sqlite": {"t1", "t2"}}

    def test_load_allowed_dbs_list_backward_compat(self, tmp_path):
        config = {
            "accounts": [
                {
                    "name": "user",
                    "public_key": "ssh-ed25519 AAAA fake",
                    "allowed_dbs": ["db1.sqlite", "db2.sqlite"],
                }
            ]
        }
        path = tmp_path / "accounts.json"
        path.write_text(json.dumps(config))
        mgr = AccountManager(str(path))
        acc = mgr.accounts[0]
        assert acc.allowed_dbs == {"db1.sqlite": None, "db2.sqlite": None}


# ---------------------------------------------------------------------------
# ユニットテスト: execute_rpc 権限チェック (サーバー内部ロジック)
# ---------------------------------------------------------------------------


class TestWriteMethodsConstant:
    """WRITE_METHODS 定数の検証"""

    def test_write_methods_defined(self):
        from nanasqlite_server.server import WRITE_METHODS
        assert "__setitem__" in WRITE_METHODS
        assert "__delitem__" in WRITE_METHODS
        assert "set" in WRITE_METHODS
        assert "delete" in WRITE_METHODS
        assert "batch_update" in WRITE_METHODS
        assert "clear" in WRITE_METHODS
        assert "upsert" in WRITE_METHODS

    def test_read_methods_not_in_write_methods(self):
        from nanasqlite_server.server import WRITE_METHODS
        assert "__getitem__" not in WRITE_METHODS
        assert "get" not in WRITE_METHODS
        assert "batch_get" not in WRITE_METHODS
        assert "list_tables" not in WRITE_METHODS
        assert "__contains__" not in WRITE_METHODS
        assert "__len__" not in WRITE_METHODS


# ---------------------------------------------------------------------------
# 統合テスト: 専用サーバーを使った read_only / テーブル制限テスト
# ---------------------------------------------------------------------------


@pytest.fixture
def test_keys_v133():
    """テスト用の Ed25519 鍵ペア"""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    ).decode()
    return private_key, pub_bytes


@pytest.fixture
async def v133_server(tmp_path, test_keys_v133):
    """v1.3.3 テスト用の専用サーバー"""
    priv, pub = test_keys_v133
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

        with open(config_path, "w") as f:
            json.dump({"db_dir": db_dir, "accounts": []}, f)

        env = os.environ.copy()
        env["PYTHONPATH"] = orig_cwd + os.pathsep + os.path.join(orig_cwd, "src")
        env["NANASQLITE_FORCE_POLLING"] = "1"
        env["NANASQLITE_DISABLE_BAN"] = "1"

        db_path = tmp_path / "v133_test.sqlite"
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

        log_file_path = tmp_path / "v133_server.log"
        log_file = open(log_file_path, "w", encoding="utf-8")

        kwargs = {}
        if sys.platform == "win32":
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP

        proc = subprocess.Popen(
            cmd, env=env, stdout=log_file, stderr=subprocess.STDOUT, text=True, **kwargs
        )

        async def wait_for_quic():
            config = QuicConfiguration(is_client=True, verify_mode=ssl.CERT_NONE)
            start_wait = time.time()
            while time.time() - start_wait < 60.0:
                if proc.poll() is not None:
                    return False
                try:
                    async with connect("127.0.0.1", port, configuration=config):
                        return True
                except Exception:
                    await asyncio.sleep(1.0)
            return False

        if not await wait_for_quic():
            log_file.close()
            with open(log_file_path, "r", encoding="utf-8") as f:
                content = f.read()
            raise RuntimeError(
                f"v133 server failed to start.\nLog:\n{content}"
            )

        yield port, config_path, priv, pub, db_dir

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
async def test_read_only_blocks_write_methods(v133_server):
    """read_only=true のアカウントは書き込み系メソッドを拒否される"""
    port, config_path, priv, pub, db_dir = v133_server

    with open(config_path, "w") as f:
        json.dump(
            {
                "db_dir": db_dir,
                "accounts": [
                    {
                        "name": "viewer",
                        "public_key": pub,
                        "read_only": True,
                        "allowed_dbs": ["v133_test.sqlite"],
                    }
                ],
            },
            f,
        )
    await asyncio.sleep(2.0)

    client = RemoteNanaSQLite(host="127.0.0.1", port=port, verify_ssl=False)
    client.private_key = priv
    try:
        await client.connect(account_name="viewer")

        # 書き込み系メソッドはすべて PermissionError になる
        with pytest.raises(PermissionError):
            await client.set_item_async("key", "value", db="v133_test.sqlite")
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_read_only_allows_read_methods(v133_server):
    """read_only=true のアカウントでも読み取り系メソッドは使用できる"""
    port, config_path, priv, pub, db_dir = v133_server

    with open(config_path, "w") as f:
        json.dump(
            {
                "db_dir": db_dir,
                "accounts": [
                    {
                        "name": "viewer",
                        "public_key": pub,
                        "read_only": True,
                        "allowed_dbs": ["v133_test.sqlite"],
                    }
                ],
            },
            f,
        )
    await asyncio.sleep(2.0)

    client = RemoteNanaSQLite(host="127.0.0.1", port=port, verify_ssl=False)
    client.private_key = priv
    try:
        await client.connect(account_name="viewer")
        # list_tables は読み取り系なので PermissionError にならない
        result = await client.list_tables(db="v133_test.sqlite")
        assert result is not None
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_table_restriction_blocks_unauthorized_table(v133_server):
    """allowed_dbs に dict 形式でテーブル制限を設定すると、未許可テーブルへのアクセスが拒否される"""
    port, config_path, priv, pub, db_dir = v133_server

    with open(config_path, "w") as f:
        json.dump(
            {
                "db_dir": db_dir,
                "accounts": [
                    {
                        "name": "limited",
                        "public_key": pub,
                        "allowed_dbs": {
                            "v133_test.sqlite": ["allowed_table"],
                        },
                    }
                ],
            },
            f,
        )
    await asyncio.sleep(2.0)

    client = RemoteNanaSQLite(host="127.0.0.1", port=port, verify_ssl=False)
    client.private_key = priv
    try:
        await client.connect(account_name="limited")

        # 許可されていないテーブルへのアクセスは PermissionError
        # __getattr__ を使って table_name を kwargs に直接渡す
        with pytest.raises(PermissionError):
            await client.__getattr__("set")(
                "key", "value", db="v133_test.sqlite", table_name="secret_table"
            )
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_table_restriction_null_allows_all_tables(v133_server):
    """allowed_dbs に null を設定すると全テーブルへのアクセスが許可される"""
    port, config_path, priv, pub, db_dir = v133_server

    with open(config_path, "w") as f:
        json.dump(
            {
                "db_dir": db_dir,
                "accounts": [
                    {
                        "name": "full_access",
                        "public_key": pub,
                        "allowed_dbs": {
                            "v133_test.sqlite": None,
                        },
                    }
                ],
            },
            f,
        )
    await asyncio.sleep(2.0)

    client = RemoteNanaSQLite(host="127.0.0.1", port=port, verify_ssl=False)
    client.private_key = priv
    try:
        await client.connect(account_name="full_access")
        # テーブル制限なし: 書き込みも正常に動作する
        await client.set_item_async("key", "value", db="v133_test.sqlite")
        result = await client.get_item_async("key", db="v133_test.sqlite")
        assert result == "value"
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_backward_compat_list_allowed_dbs(v133_server):
    """allowed_dbs にリスト形式を使用しても引き続き動作する (後方互換)"""
    port, config_path, priv, pub, db_dir = v133_server

    with open(config_path, "w") as f:
        json.dump(
            {
                "db_dir": db_dir,
                "accounts": [
                    {
                        "name": "compat_user",
                        "public_key": pub,
                        "allowed_dbs": ["v133_test.sqlite"],
                    }
                ],
            },
            f,
        )
    await asyncio.sleep(2.0)

    client = RemoteNanaSQLite(host="127.0.0.1", port=port, verify_ssl=False)
    client.private_key = priv
    try:
        await client.connect(account_name="compat_user")
        await client.set_item_async("compat_key", "compat_value", db="v133_test.sqlite")
        result = await client.get_item_async("compat_key", db="v133_test.sqlite")
        assert result == "compat_value"
    finally:
        await client.close()
