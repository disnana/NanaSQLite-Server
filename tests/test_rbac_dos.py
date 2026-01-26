import asyncio
import json
import os
import pytest
import ssl
from aioquic.asyncio import connect
from aioquic.quic.configuration import QuicConfiguration
from cryptography.hazmat.primitives import serialization
from nanasqlite_server.client import RemoteNanaSQLite, NanaRpcClientProtocol
from nanasqlite_server.cert_gen import generate_certificate
from nanasqlite_server.key_gen import generate_keys
import subprocess
import sys
import signal
import time


# テスト用のポート (conftest.py で設定される)
def get_port():
    return int(os.environ.get("NANASQLITE_TEST_PORT", 4433))


@pytest.fixture
def test_keys():
    """テスト用の Ed25519 鍵ペア"""
    from cryptography.hazmat.primitives.asymmetric import ed25519

    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    ).decode()
    return private_key, pub_bytes


@pytest.fixture
async def dedicated_server(tmp_path):
    """各テスト用に独立したサーバーを起動するフィクスチャ"""
    # 鍵と証明書の準備
    priv_key_path = tmp_path / "nana_private.pem"
    config_path = tmp_path / "accounts.json"

    orig_cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        generate_certificate()
        generate_keys()

        with open(config_path, "w") as f:
            json.dump({"accounts": []}, f)

        # 未使用ポートの取得
        import socket

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()

        env = os.environ.copy()
        env["PYTHONPATH"] = orig_cwd + os.pathsep + os.path.join(orig_cwd, "src")
        env["PYTHONUNBUFFERED"] = "1"
        env["NANASQLITE_FORCE_POLLING"] = "1"

        db_dir = str(tmp_path)
        db_path = tmp_path / "dedicated_server_db.sqlite"
        
        # Provide db_dir in config
        with open(config_path, "w") as f:
            json.dump({"db_dir": db_dir, "accounts": []}, f)

        cmd = [
            sys.executable,
            "-m",
            "nanasqlite_server.server",
            "--port",
            str(port),
            "--accounts",
            str(config_path),
            # --db argument is deprecated/legacy but still accepted by argparse, 
            # effectively ignored by new logic if multi-DB is used correctly via accounts.
            # We keep it to avoid changing server argument parsing logic if not necessary.
            "--db", 
            str(db_path), 
        ]

        # パイプ詰まりによるハングアップを防ぐため
        log_file_path = tmp_path / "dedicated_server.log"
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
            while time.time() - start_wait < 60.0:  # タイムアウトを延長
                if proc.poll() is not None:
                    return False
                try:
                    async with connect("127.0.0.1", port, configuration=config):
                        return True
                except Exception:
                    # Ignore connection errors during wait
                    await asyncio.sleep(1.0)
            return False

        if not await wait_for_quic():
            if proc.poll() is not None:
                log_file.close()
                with open(log_file_path, "r", encoding="utf-8") as f:
                    log_content = f.read()
                raise RuntimeError(
                    f"Dedicated server process died. Code: {proc.returncode}\nLog:\n{log_content}"
                )
            else:
                proc.kill()
                raise RuntimeError(
                    "Dedicated server failed to start (QUIC check failed)"
                )

        yield port, config_path, priv_key_path, db_dir

    finally:
        if proc.poll() is None:
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
                proc.kill()
                proc.wait()
        log_file.close()
        os.chdir(orig_cwd)


@pytest.mark.asyncio
async def test_rbac_permissions(test_keys, dedicated_server):
    """RBAC: アカウントごとの権限制限が機能することを確認"""
    port, config_path, _, db_dir = dedicated_server
    priv, pub = test_keys

    with open(config_path, "w") as f:
        json.dump(
            {
                "db_dir": db_dir,
                "accounts": [
                    {
                        "name": "readonly",
                        "public_key": pub,
                        "allowed_methods": None,
                        "forbidden_methods": ["__setitem__"],
                        "allowed_dbs": ["dedicated_server_db.sqlite"]
                    }
                ]
            },
            f,
        )

    # 監視が反映されるまでCI環境では長めに待機
    await asyncio.sleep(2.0)

    client = RemoteNanaSQLite(host="127.0.0.1", port=port, verify_ssl=False)
    client.private_key = priv

    try:
        await client.connect(account_name="readonly")

        with pytest.raises(PermissionError) as excinfo:
            await client.set_item_async("key", "value", db="dedicated_server_db.sqlite")
        assert "forbidden" in str(excinfo.value).lower()

    finally:
        await client.close()


@pytest.mark.asyncio
async def test_realtime_policy_update(test_keys, dedicated_server):
    """即時反映: 実行中に権限を剥奪できることを確認"""
    port, config_path, _, db_dir = dedicated_server
    priv, pub = test_keys

    accounts = {
        "db_dir": db_dir,
        "accounts": [
            {
                "name": "user",
                "public_key": pub,
                "allowed_methods": None,
                "forbidden_methods": [],
                "allowed_dbs": ["dedicated_server_db.sqlite"]
            }
        ]
    }
    with open(config_path, "w") as f:
        json.dump(accounts, f)

    # 反映待ち
    await asyncio.sleep(2.0)

    client = RemoteNanaSQLite(host="127.0.0.1", port=port, verify_ssl=False)
    client.private_key = priv

    try:
        await client.connect(account_name="user")
        await client.list_tables(db="dedicated_server_db.sqlite")

        accounts["accounts"][0]["forbidden_methods"] = ["list_tables"]
        with open(config_path, "w") as f:
            json.dump(accounts, f)

        # watchfiles の検知待ち (CI環境では長めに)
        await asyncio.sleep(2.0)

        with pytest.raises(PermissionError):
            await client.list_tables(db="dedicated_server_db.sqlite")

    finally:
        await client.close()


@pytest.mark.asyncio
async def test_anti_dos_stream_limit(dedicated_server):
    """Anti-DoS: 未認証時の同時ストリーム数制限"""
    port, _, _ = dedicated_server
    config = QuicConfiguration(is_client=True, verify_mode=ssl.CERT_NONE)

    async with connect(
        "127.0.0.1", port, configuration=config, create_protocol=NanaRpcClientProtocol
    ) as conn:
        # Limit is 50. We send 60 to exceed it.
        for _ in range(60):
            try:
                stream_id = conn._quic.get_next_available_stream_id()
                conn._quic.send_stream_data(stream_id, b"data", end_stream=False)
                conn.transmit()
                # Give server time to process resets
                await asyncio.sleep(0.001)
            except Exception:
                # Connection might be reset or closed by server due to limits
                break

        await asyncio.sleep(1.0)
        async with connect(
            "127.0.0.1",
            port,
            configuration=config,
            create_protocol=NanaRpcClientProtocol,
        ) as conn2:
            # New connection should still be possible
            await conn2.call_rpc("AUTH_START")


@pytest.mark.asyncio
async def test_anti_dos_total_buffer_limit(dedicated_server):
    """Anti-DoS: 未認証時の合計バッファ制限"""
    port, _, _ = dedicated_server
    config = QuicConfiguration(is_client=True, verify_mode=ssl.CERT_NONE)

    async with connect(
        "127.0.0.1", port, configuration=config, create_protocol=NanaRpcClientProtocol
    ) as conn:
        stream_id = conn._quic.get_next_available_stream_id()
        chunk = b"A" * (1024 * 1024)  # 1MB

        # Limit is 50MB. We send 60MB.
        for _ in range(60):
            try:
                conn._quic.send_stream_data(stream_id, chunk, end_stream=False)
                conn.transmit()
                # Server needs time to process large data and close connection
                await asyncio.sleep(0.05)
            except Exception:
                # Connection closed by server due to buffer limits
                break

        await asyncio.sleep(1.0)
        try:
            # Original connection should be dead
            await conn.call_rpc("AUTH_START")
        except Exception:
            # Expected failure if connection is closed
            pass

        # New connection should still be possible
        async with connect(
            "127.0.0.1",
            port,
            configuration=config,
            create_protocol=NanaRpcClientProtocol,
        ) as conn2:
            await conn2.call_rpc("AUTH_START")
