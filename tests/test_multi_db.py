import asyncio
import json
import os
import pytest
import ssl
from nanasqlite_server.client import RemoteNanaSQLite
from nanasqlite_server.cert_gen import generate_certificate
from nanasqlite_server.key_gen import generate_keys
import subprocess
import sys
import signal
import time
import shutil

@pytest.fixture
def test_keys():
    from cryptography.hazmat.primitives.asymmetric import ed25519
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    from cryptography.hazmat.primitives import serialization
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    ).decode()
    return private_key, pub_bytes

@pytest.fixture
async def multi_db_server(tmp_path, test_keys):
    priv, pub = test_keys
    db_dir = tmp_path / "dbs"
    db_dir.mkdir()
    
    config_path = tmp_path / "accounts.json"
    with open(config_path, "w") as f:
        json.dump({
            "db_dir": str(db_dir),
            "accounts": [
                {
                    "name": "tester",
                    "public_key": pub,
                    "allowed_dbs": ["db1.sqlite", "db2.sqlite", "subdir/db3.sqlite"]
                }
            ]
        }, f)
    
    # Create subdir
    (db_dir / "subdir").mkdir()

    orig_cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        generate_certificate()
        
        # Use a random port
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()

        env = os.environ.copy()
        env["PYTHONPATH"] = orig_cwd + os.pathsep + os.path.join(orig_cwd, "src")
        env["NANASQLITE_FORCE_POLLING"] = "1"
        
        cmd = [
            sys.executable, "-m", "nanasqlite_server.server",
            "--port", str(port),
            "--accounts", str(config_path)
        ]
        
        from aioquic.quic.configuration import QuicConfiguration
        from aioquic.asyncio import connect

        # Wait for server
        start = time.time()
        ready = False
        config = QuicConfiguration(is_client=True, verify_mode=ssl.CERT_NONE)
        while time.time() - start < 30:
            if proc.poll() is not None:
                # Process died
                break
            try:
                # Use a shorter timeout for each connection attempt
                async with asyncio.timeout(1.0):
                    async with connect("127.0.0.1", port, configuration=config):
                        ready = True
                        break
            except:
                await asyncio.sleep(0.5)
        
        if not ready:
            proc.kill()
            raise RuntimeError("Server failed to start")
            
        yield port, priv, db_dir
    finally:
        proc.terminate()
        proc.wait()
        os.chdir(orig_cwd)

@pytest.mark.asyncio
async def test_multi_db_access(multi_db_server):
    port, priv, db_dir = multi_db_server
    
    client = RemoteNanaSQLite(host="127.0.0.1", port=port, verify_ssl=False)
    client.private_key = priv
    
    try:
        await client.connect(account_name="tester")
        
        # Access DB1
        await client.__getattr__("__setitem__")("key1", "val1", db="db1.sqlite")
        assert await client.__getattr__("__getitem__")("key1", db="db1.sqlite") == "val1"
        
        # Access DB2
        await client.__getattr__("__setitem__")("key2", "val2", db="db2.sqlite")
        assert await client.__getattr__("__getitem__")("key2", db="db2.sqlite") == "val2"
        
        # Verify they are separate files
        assert os.path.exists(db_dir / "db1.sqlite")
        assert os.path.exists(db_dir / "db2.sqlite")
        
        # Access Subdir DB
        await client.__getattr__("__setitem__")("key3", "val3", db="subdir/db3.sqlite")
        assert await client.__getattr__("__getitem__")("key3", db="subdir/db3.sqlite") == "val3"
        assert os.path.exists(db_dir / "subdir" / "db3.sqlite")
        
        # Unauthorized DB access
        with pytest.raises(Exception) as exc:
            await client.__getattr__("__getitem__")("key", db="secret.sqlite")
        assert "not allowed" in str(exc.value).lower()
        
        # Traversal attempt
        with pytest.raises(Exception) as exc:
            await client.__getattr__("__getitem__")("key", db="../config.json")
        # Depending on error message from server
        assert "detected" in str(exc.value).lower() or "invalid" in str(exc.value).lower()

    finally:
        await client.close()
