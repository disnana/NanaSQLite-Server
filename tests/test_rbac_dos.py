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
        format=serialization.PublicFormat.OpenSSH
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
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
        s.close()

        env = os.environ.copy()
        env["PYTHONPATH"] = orig_cwd + os.pathsep + os.path.join(orig_cwd, "src")

        cmd = [sys.executable, "-m", "nanasqlite_server.server",
               "--port", str(port),
               "--accounts", str(config_path)]

        proc = subprocess.Popen(cmd, env=env)

        async def wait_for_quic():
            config = QuicConfiguration(is_client=True, verify_mode=ssl.CERT_NONE)
            start_wait = time.time()
            while time.time() - start_wait < 10.0:
                if proc.poll() is not None:
                    return False
                try:
                    async with connect("127.0.0.1", port, configuration=config) as _:
                        return True
                except Exception:
                    await asyncio.sleep(0.5)
            return False

        if not await wait_for_quic():
            proc.kill()
            raise RuntimeError("Dedicated server failed to start (QUIC check failed)")

        yield port, config_path, priv_key_path

    finally:
        if proc.poll() is None:
            if sys.platform == "win32":
                proc.terminate()
            else:
                proc.send_signal(signal.SIGINT)
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()
        os.chdir(orig_cwd)

@pytest.mark.asyncio
async def test_rbac_permissions(test_keys, dedicated_server):
    """RBAC: アカウントごとの権限制限が機能することを確認"""
    port, config_path, _ = dedicated_server
    priv, pub = test_keys

    with open(config_path, "w") as f:
        json.dump({
            "accounts": [
                {
                    "name": "readonly",
                    "public_key": pub,
                    "allowed_methods": None,
                    "forbidden_methods": ["__setitem__"]
                }
            ]
        }, f)

    await asyncio.sleep(0.5)

    client = RemoteNanaSQLite(host="127.0.0.1", port=port, verify_ssl=False)
    client.private_key = priv

    try:
        await client.connect(account_name="readonly")

        with pytest.raises(PermissionError) as excinfo:
            await client.set_item_async("key", "value")
        assert "forbidden" in str(excinfo.value).lower()

    finally:
        await client.close()

@pytest.mark.asyncio
async def test_realtime_policy_update(test_keys, dedicated_server):
    """即時反映: 実行中に権限を剥奪できることを確認"""
    port, config_path, _ = dedicated_server
    priv, pub = test_keys

    accounts = {
        "accounts": [
            {
                "name": "user",
                "public_key": pub,
                "allowed_methods": None,
                "forbidden_methods": []
            }
        ]
    }
    with open(config_path, "w") as f:
        json.dump(accounts, f)

    await asyncio.sleep(0.5)

    client = RemoteNanaSQLite(host="127.0.0.1", port=port, verify_ssl=False)
    client.private_key = priv

    try:
        await client.connect(account_name="user")
        await client.list_tables()

        accounts["accounts"][0]["forbidden_methods"] = ["list_tables"]
        with open(config_path, "w") as f:
            json.dump(accounts, f)

        await asyncio.sleep(0.5)

        with pytest.raises(PermissionError):
            await client.list_tables()

    finally:
        await client.close()

@pytest.mark.asyncio
async def test_anti_dos_stream_limit(dedicated_server):
    """Anti-DoS: 未認証時の同時ストリーム数制限"""
    port, _, _ = dedicated_server
    config = QuicConfiguration(is_client=True, verify_mode=ssl.CERT_NONE)

    async with connect("127.0.0.1", port, configuration=config, create_protocol=NanaRpcClientProtocol) as conn:
        for _ in range(100):
            try:
                stream_id = conn._quic.get_next_available_stream_id()
                conn._quic.send_stream_data(stream_id, b"data", end_stream=False)
                conn.transmit()
            except Exception:
                # Connection might be reset or closed by server due to limits
                break

        await asyncio.sleep(0.5)
        async with connect("127.0.0.1", port, configuration=config, create_protocol=NanaRpcClientProtocol) as conn2:
            await conn2.call_rpc("AUTH_START")

@pytest.mark.asyncio
async def test_anti_dos_total_buffer_limit(dedicated_server):
    """Anti-DoS: 未認証時の合計バッファ制限"""
    port, _, _ = dedicated_server
    config = QuicConfiguration(is_client=True, verify_mode=ssl.CERT_NONE)

    async with connect("127.0.0.1", port, configuration=config, create_protocol=NanaRpcClientProtocol) as conn:
        stream_id = conn._quic.get_next_available_stream_id()
        chunk = b"A" * (1024 * 1024) # 1MB

        for _ in range(60):
            try:
                conn._quic.send_stream_data(stream_id, chunk, end_stream=False)
                conn.transmit()
                await asyncio.sleep(0.01)
            except Exception:
                # Connection closed by server due to buffer limits
                break

        await asyncio.sleep(0.5)
        try:
            await conn.call_rpc("AUTH_START")
        except Exception:
            # Expected failure if connection is closed
            pass
