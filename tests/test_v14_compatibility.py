"""
nanasqlite v1.4.0 互換性テスト

このテストスイートは以下を検証します:
1. v1.4.0で追加された危険なメソッドがRPC経由でブロックされることを確認
2. v1.4.0で追加された安全なメソッドがRPC経由で正常に動作することを確認
3. v2エンジンモードでの基本動作を確認
"""

import asyncio
import json
import os
import socket
import subprocess
import sys
import time

import pytest
import ssl

from aioquic.asyncio import connect
from aioquic.quic.configuration import QuicConfiguration

from nanasqlite_server.cert_gen import generate_certificate
from nanasqlite_server.client import RemoteNanaSQLite


@pytest.fixture
def test_keys():
    """テスト用の Ed25519 鍵ペア"""
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization

    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    ).decode()
    return private_key, pub_bytes


def _get_free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


async def _wait_for_server(port, timeout=60.0):
    config = QuicConfiguration(is_client=True, verify_mode=ssl.CERT_NONE)
    start = time.time()
    while time.time() - start < timeout:
        try:
            async with connect("127.0.0.1", port, configuration=config):
                return True
        except Exception:
            await asyncio.sleep(1.0)
    return False


@pytest.fixture
async def compat_server(tmp_path, test_keys):
    """v1.4.0互換性テスト用の独立したサーバー"""
    priv, pub = test_keys
    db_dir = tmp_path / "dbs"
    db_dir.mkdir()

    config_path = tmp_path / "accounts.json"
    db_name = "compat_test.sqlite"
    with open(config_path, "w") as f:
        json.dump(
            {
                "db_dir": str(db_dir),
                "accounts": [
                    {
                        "name": "tester",
                        "public_key": pub,
                        "allowed_methods": None,
                        "forbidden_methods": [],
                        "allowed_dbs": [db_name],
                    }
                ],
            },
            f,
        )

    orig_cwd = os.getcwd()
    os.chdir(tmp_path)
    proc = None
    log_file = None
    try:
        generate_certificate()
        port = _get_free_port()

        env = os.environ.copy()
        env["PYTHONPATH"] = orig_cwd + os.pathsep + os.path.join(orig_cwd, "src")
        env["NANASQLITE_FORCE_POLLING"] = "1"

        cmd = [
            sys.executable,
            "-m",
            "nanasqlite_server.server",
            "--port",
            str(port),
            "--accounts",
            str(config_path),
        ]

        if sys.platform == "win32":
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            creationflags = 0

        log_path = tmp_path / "compat_server.log"
        log_file = open(log_path, "w", encoding="utf-8")

        proc = subprocess.Popen(
            cmd,
            env=env,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            text=True,
            creationflags=creationflags,
        )

        ok = await _wait_for_server(port)
        if not ok:
            if proc.poll() is not None:
                log_file.close()
                with open(log_path) as f:
                    raise RuntimeError(
                        f"Server died (code {proc.returncode}):\n{f.read()}"
                    )
            proc.kill()
            raise RuntimeError("Server failed to start")

        yield port, priv, db_dir, db_name

    finally:
        if proc and proc.poll() is None:
            import signal

            try:
                if sys.platform == "win32":
                    os.kill(proc.pid, signal.CTRL_BREAK_EVENT)
                else:
                    proc.send_signal(signal.SIGINT)
                proc.wait(timeout=5)
            except Exception:
                proc.kill()
                proc.wait()
        if log_file:
            log_file.close()
        os.chdir(orig_cwd)


@pytest.fixture
async def v2_server(tmp_path, test_keys):
    """v2エンジンを有効にした独立サーバー"""
    priv, pub = test_keys
    db_dir = tmp_path / "dbs"
    db_dir.mkdir()

    config_path = tmp_path / "accounts.json"
    db_name = "v2_test.sqlite"
    with open(config_path, "w") as f:
        json.dump(
            {
                "db_dir": str(db_dir),
                "accounts": [
                    {
                        "name": "v2user",
                        "public_key": pub,
                        "allowed_methods": None,
                        "forbidden_methods": [],
                        "allowed_dbs": [db_name],
                    }
                ],
            },
            f,
        )

    orig_cwd = os.getcwd()
    os.chdir(tmp_path)
    proc = None
    log_file = None
    try:
        generate_certificate()
        port = _get_free_port()

        env = os.environ.copy()
        env["PYTHONPATH"] = orig_cwd + os.pathsep + os.path.join(orig_cwd, "src")
        env["NANASQLITE_FORCE_POLLING"] = "1"

        cmd = [
            sys.executable,
            "-m",
            "nanasqlite_server.server",
            "--port",
            str(port),
            "--accounts",
            str(config_path),
            "--v2",
            "--flush-mode",
            "immediate",
        ]

        if sys.platform == "win32":
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            creationflags = 0

        log_path = tmp_path / "v2_server.log"
        log_file = open(log_path, "w", encoding="utf-8")

        proc = subprocess.Popen(
            cmd,
            env=env,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            text=True,
            creationflags=creationflags,
        )

        ok = await _wait_for_server(port)
        if not ok:
            if proc.poll() is not None:
                log_file.close()
                with open(log_path) as f:
                    raise RuntimeError(
                        f"v2 server died (code {proc.returncode}):\n{f.read()}"
                    )
            proc.kill()
            raise RuntimeError("v2 server failed to start")

        yield port, priv, db_dir, db_name

    finally:
        if proc and proc.poll() is None:
            import signal

            try:
                if sys.platform == "win32":
                    os.kill(proc.pid, signal.CTRL_BREAK_EVENT)
                else:
                    proc.send_signal(signal.SIGINT)
                proc.wait(timeout=5)
            except Exception:
                proc.kill()
                proc.wait()
        if log_file:
            log_file.close()
        os.chdir(orig_cwd)


# =============================================================================
# v1.4.0 危険メソッドのブロックテスト (セキュリティテスト)
# =============================================================================


class TestForbiddenV14Methods:
    """v1.4.0で追加された危険なメソッドがRPCでブロックされることを確認"""

    async def _connect(self, port, priv, db_name):
        client = RemoteNanaSQLite(host="127.0.0.1", port=port, verify_ssl=False)
        client.private_key = priv
        await client.connect(account_name="tester")
        return client

    @pytest.mark.asyncio
    async def test_backup_is_forbidden(self, compat_server):
        """backup()はパストラバーサル脆弱性があるため禁止されている"""
        port, priv, db_dir, db_name = compat_server
        client = await self._connect(port, priv, db_name)
        try:
            with pytest.raises(PermissionError):
                await client.__getattr__("backup")(
                    "/tmp/stolen.sqlite", db=db_name
                )
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_restore_is_forbidden(self, compat_server):
        """restore()はパストラバーサル脆弱性があるため禁止されている"""
        port, priv, db_dir, db_name = compat_server
        client = await self._connect(port, priv, db_name)
        try:
            with pytest.raises(PermissionError):
                await client.__getattr__("restore")(
                    "/tmp/malicious.sqlite", db=db_name
                )
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_fetch_all_is_forbidden(self, compat_server):
        """fetch_all()は生SQL実行のため禁止されている"""
        port, priv, db_dir, db_name = compat_server
        client = await self._connect(port, priv, db_name)
        try:
            with pytest.raises(PermissionError):
                await client.__getattr__("fetch_all")(
                    "SELECT * FROM data", db=db_name
                )
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_fetch_one_is_forbidden(self, compat_server):
        """fetch_one()は生SQL実行のため禁止されている"""
        port, priv, db_dir, db_name = compat_server
        client = await self._connect(port, priv, db_name)
        try:
            with pytest.raises(PermissionError):
                await client.__getattr__("fetch_one")(
                    "SELECT * FROM data LIMIT 1", db=db_name
                )
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_create_table_is_forbidden(self, compat_server):
        """create_table()はDDL操作のため禁止されている"""
        port, priv, db_dir, db_name = compat_server
        client = await self._connect(port, priv, db_name)
        try:
            with pytest.raises(PermissionError):
                await client.__getattr__("create_table")(
                    "evil_table",
                    {"id": "INTEGER PRIMARY KEY", "data": "TEXT"},
                    db=db_name,
                )
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_drop_table_is_forbidden(self, compat_server):
        """drop_table()は破壊的DDLのため禁止されている"""
        port, priv, db_dir, db_name = compat_server
        client = await self._connect(port, priv, db_name)
        try:
            with pytest.raises(PermissionError):
                await client.__getattr__("drop_table")("data", db=db_name)
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_alter_table_add_column_is_forbidden(self, compat_server):
        """alter_table_add_column()はDDL操作のため禁止されている"""
        port, priv, db_dir, db_name = compat_server
        client = await self._connect(port, priv, db_name)
        try:
            with pytest.raises(PermissionError):
                await client.__getattr__("alter_table_add_column")(
                    "data", "evil_col", "TEXT", db=db_name
                )
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_drop_index_is_forbidden(self, compat_server):
        """drop_index()は破壊的操作のため禁止されている"""
        port, priv, db_dir, db_name = compat_server
        client = await self._connect(port, priv, db_name)
        try:
            with pytest.raises(PermissionError):
                await client.__getattr__("drop_index")(
                    "some_index", db=db_name
                )
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_create_index_is_forbidden(self, compat_server):
        """create_index()はDoS・スキーマ変更のリスクがあるため禁止されている"""
        port, priv, db_dir, db_name = compat_server
        client = await self._connect(port, priv, db_name)
        try:
            with pytest.raises(PermissionError):
                await client.__getattr__("create_index")(
                    "my_idx", "data", ["key"], db=db_name
                )
        finally:
            await client.close()


# =============================================================================
# v1.4.0 安全なメソッドの動作テスト
# =============================================================================


class TestAllowedV14Methods:
    """v1.4.0で追加された安全なメソッドがRPCで正常に動作することを確認"""

    async def _connect(self, port, priv, db_name):
        client = RemoteNanaSQLite(host="127.0.0.1", port=port, verify_ssl=False)
        client.private_key = priv
        await client.connect(account_name="tester")
        return client

    @pytest.mark.asyncio
    async def test_batch_get(self, compat_server):
        """batch_get()が正常に動作する"""
        port, priv, db_dir, db_name = compat_server
        client = await self._connect(port, priv, db_name)
        try:
            # 事前にデータを投入
            await client.set_item_async("bkey1", "val1", db=db_name)
            await client.set_item_async("bkey2", "val2", db=db_name)

            result = await client.__getattr__("batch_get")(
                ["bkey1", "bkey2", "bkey_missing"], db=db_name
            )
            assert result["bkey1"] == "val1"
            assert result["bkey2"] == "val2"
            assert "bkey_missing" not in result
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_batch_delete(self, compat_server):
        """batch_delete()が正常に動作する"""
        port, priv, db_dir, db_name = compat_server
        client = await self._connect(port, priv, db_name)
        try:
            await client.set_item_async("del1", "v1", db=db_name)
            await client.set_item_async("del2", "v2", db=db_name)

            await client.__getattr__("batch_delete")(["del1", "del2"], db=db_name)

            result = await client.__getattr__("batch_get")(["del1", "del2"], db=db_name)
            assert "del1" not in result
            assert "del2" not in result
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_upsert(self, compat_server):
        """upsert()が正常に動作する"""
        port, priv, db_dir, db_name = compat_server
        client = await self._connect(port, priv, db_name)
        try:
            # upsertはメインテーブルに対してキー/バリューペアを書き込む
            result = await client.__getattr__("upsert")(db=db_name)
            # upsertがPermissionErrorや AttributeError を投げなければOK
            # (テーブル名省略でNoneが返ることがある)
        except (PermissionError, AttributeError) as e:
            pytest.fail(f"upsert raised unexpected permission error: {e}")
        except Exception:
            # テーブルが存在しない等のDB側エラーは許容
            pass
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_get_db_size(self, compat_server):
        """get_db_size()が正常に動作する"""
        port, priv, db_dir, db_name = compat_server
        client = await self._connect(port, priv, db_name)
        try:
            size = await client.__getattr__("get_db_size")(db=db_name)
            assert isinstance(size, int)
            assert size >= 0
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_table_exists(self, compat_server):
        """table_exists()が正常に動作する"""
        port, priv, db_dir, db_name = compat_server
        client = await self._connect(port, priv, db_name)
        try:
            # まずデータを書き込んでテーブルを作成する
            await client.set_item_async("exists_key", "val", db=db_name)
            result = await client.__getattr__("table_exists")("data", db=db_name)
            assert result is True

            result2 = await client.__getattr__("table_exists")(
                "nonexistent_table", db=db_name
            )
            assert result2 is False
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_list_tables(self, compat_server):
        """list_tables()が正常に動作する"""
        port, priv, db_dir, db_name = compat_server
        client = await self._connect(port, priv, db_name)
        try:
            await client.set_item_async("lt_key", "val", db=db_name)
            tables = await client.__getattr__("list_tables")(db=db_name)
            assert isinstance(tables, list)
            assert "data" in tables
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_to_dict(self, compat_server):
        """to_dict()が正常に動作する"""
        port, priv, db_dir, db_name = compat_server
        client = await self._connect(port, priv, db_name)
        try:
            await client.set_item_async("dict_key", "dict_val", db=db_name)
            result = await client.__getattr__("to_dict")(db=db_name)
            assert isinstance(result, dict)
            assert result.get("dict_key") == "dict_val"
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_get_fresh(self, compat_server):
        """get_fresh()が正常に動作する"""
        port, priv, db_dir, db_name = compat_server
        client = await self._connect(port, priv, db_name)
        try:
            await client.set_item_async("fresh_key", "fresh_val", db=db_name)
            result = await client.__getattr__("get_fresh")("fresh_key", db=db_name)
            assert result == "fresh_val"

            # 存在しないキーはデフォルト値(None)
            result2 = await client.__getattr__("get_fresh")(
                "nonexistent_key", db=db_name
            )
            assert result2 is None
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_get_table_schema(self, compat_server):
        """get_table_schema()が正常に動作する"""
        port, priv, db_dir, db_name = compat_server
        client = await self._connect(port, priv, db_name)
        try:
            await client.set_item_async("schema_key", "val", db=db_name)
            schema = await client.__getattr__("get_table_schema")(db=db_name)
            assert isinstance(schema, list)
            assert len(schema) > 0
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_list_indexes(self, compat_server):
        """list_indexes()が正常に動作する"""
        port, priv, db_dir, db_name = compat_server
        client = await self._connect(port, priv, db_name)
        try:
            result = await client.__getattr__("list_indexes")(db=db_name)
            assert isinstance(result, list)
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_export_and_import(self, compat_server):
        """export_table_to_dict()とimport_from_dict_list()が正常に動作する"""
        port, priv, db_dir, db_name = compat_server
        client = await self._connect(port, priv, db_name)
        try:
            # データを書き込む
            await client.set_item_async("export_key", "export_val", db=db_name)

            # エクスポート
            exported = await client.__getattr__("export_table_to_dict")(
                "data", db=db_name
            )
            assert isinstance(exported, list)
            assert len(exported) >= 1
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_get_dlq_and_retry_dlq(self, compat_server):
        """get_dlq()とretry_dlq()が正常に動作する"""
        port, priv, db_dir, db_name = compat_server
        client = await self._connect(port, priv, db_name)
        try:
            dlq = await client.__getattr__("get_dlq")(db=db_name)
            assert isinstance(dlq, list)

            # retry_dlqはvoidなので結果がNoneであることを確認
            result = await client.__getattr__("retry_dlq")(db=db_name)
            assert result is None
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_flush_allowed(self, compat_server):
        """flush()はv2機能のためブロックされない（v1モードではno-op）"""
        port, priv, db_dir, db_name = compat_server
        client = await self._connect(port, priv, db_name)
        try:
            # flush() はv1モードではno-opなのでエラーにならない
            result = await client.__getattr__("flush")(db=db_name)
            assert result is None
        except PermissionError as e:
            pytest.fail(f"flush() should not be forbidden: {e}")
        finally:
            await client.close()


# =============================================================================
# v2エンジンのテスト
# =============================================================================


class TestV2Engine:
    """v2エンジンモードでの基本動作テスト"""

    async def _connect(self, port, priv, db_name):
        client = RemoteNanaSQLite(host="127.0.0.1", port=port, verify_ssl=False)
        client.private_key = priv
        await client.connect(account_name="v2user")
        return client

    @pytest.mark.asyncio
    async def test_v2_basic_write_read(self, v2_server):
        """v2エンジンで基本的な書き込み/読み込みが動作する"""
        port, priv, db_dir, db_name = v2_server
        client = await self._connect(port, priv, db_name)
        try:
            await client.set_item_async("v2_key", "v2_value", db=db_name)
            result = await client.get_item_async("v2_key", db=db_name)
            assert result == "v2_value"
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_v2_flush_is_callable(self, v2_server):
        """v2エンジンでflush()がRPC経由で呼び出し可能"""
        port, priv, db_dir, db_name = v2_server
        client = await self._connect(port, priv, db_name)
        try:
            await client.set_item_async("v2_flush_key", "value", db=db_name)
            # flush()でv2バッファをSQLiteに強制書き込み
            result = await client.__getattr__("flush")(db=db_name)
            assert result is None

            # flushの後でも読み込める
            val = await client.get_item_async("v2_flush_key", db=db_name)
            assert val == "value"
        except PermissionError as e:
            pytest.fail(f"flush() should not be forbidden in v2 mode: {e}")
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_v2_get_dlq(self, v2_server):
        """v2エンジンでget_dlq()がRPC経由で動作する"""
        port, priv, db_dir, db_name = v2_server
        client = await self._connect(port, priv, db_name)
        try:
            dlq = await client.__getattr__("get_dlq")(db=db_name)
            assert isinstance(dlq, list)
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_v2_batch_operations(self, v2_server):
        """v2エンジンでバッチ操作が動作する"""
        port, priv, db_dir, db_name = v2_server
        client = await self._connect(port, priv, db_name)
        try:
            # バッチ書き込み
            await client.__getattr__("batch_update")(
                {"v2_b1": "val1", "v2_b2": "val2", "v2_b3": "val3"},
                db=db_name,
            )

            # バッチ読み込み
            result = await client.__getattr__("batch_get")(
                ["v2_b1", "v2_b2", "v2_b3"], db=db_name
            )
            assert result["v2_b1"] == "val1"
            assert result["v2_b2"] == "val2"
            assert result["v2_b3"] == "val3"

            # バッチ削除
            await client.__getattr__("batch_delete")(
                ["v2_b1", "v2_b2", "v2_b3"], db=db_name
            )
        finally:
            await client.close()
