import pytest
import asyncio
import os
import json
import socket
import logging
from aioquic.asyncio import serve
from aioquic.quic.configuration import QuicConfiguration
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from nanasqlite_server.server import NanaRpcProtocol, ServerConfig, AccountManager
from nanasqlite_server.client import RemoteNanaSQLite

def get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Bind only to the loopback interface to avoid exposing on all interfaces
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

@pytest.fixture(scope="session")
def certs(tmp_path_factory):
    """Generate self-signed cert and Ed25519 keys for testing."""
    tmp_path = tmp_path_factory.mktemp("certs")

    # Generate Ed25519 keys (PKCS8 format for load_pem_private_key)
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    priv_path = tmp_path / "test_private.pem"
    pub_path = tmp_path / "test_public.pub"

    with open(priv_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(pub_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH
        ))

    # Auto-generate TLS certs if not present
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"

    # Mock cert generation if tools not available, but usually we have openssl
    os.system(f"openssl req -newkey rsa:2048 -nodes -keyout {key_path} -x509 -days 1 -out {cert_path} -subj '/CN=localhost'")

    return {
        "priv": str(priv_path),
        "pub": str(pub_path),
        "cert": str(cert_path),
        "key": str(key_path)
    }

@pytest.fixture
async def server_factory(certs, tmp_path):
    """Factory to create and start a server instance with custom accounts."""
    servers = []

    async def _create_server(accounts=None, config_overrides=None):
        port = get_free_port()
        db_dir = tmp_path / f"db_{port}"
        acc_path = tmp_path / f"acc_{port}.json"

        if accounts is None:
            accounts = {
                "admin": {"role": "admin", "public_key": certs["pub"]},
                "guest": {"role": "readonly", "public_key": certs["pub"]}
            }

        with open(acc_path, "w") as f:
            json.dump(accounts, f)

        config = ServerConfig()
        config.port = port
        config.db_dir = str(db_dir)
        config.accounts_path = str(acc_path)
        config.cert_path = certs["cert"]
        config.key_path = certs["key"]

        if config_overrides:
            for k, v in config_overrides.items():
                setattr(config, k, v)

        account_manager = AccountManager(config.accounts_path)
        quic_config = QuicConfiguration(is_client=False)
        quic_config.load_cert_chain(config.cert_path, config.key_path)

        server_task = asyncio.create_task(serve(
            config.host, config.port, configuration=quic_config,
            create_protocol=lambda *args, **kwargs: NanaRpcProtocol(
                config, account_manager, *args, **kwargs
            )
        ))

        await asyncio.sleep(0.5)
        servers.append(server_task)
        return config

    yield _create_server

    for s in servers:
        s.cancel()
        try:
            await s
        except asyncio.CancelledError:
            logging.getLogger(__name__).debug("Server task cancelled during teardown")

@pytest.fixture
async def client_factory(certs):
    clients = []

    async def _create_client(config, username="admin", db="test"):
        client = RemoteNanaSQLite(
            host=config.host,
            port=config.port,
            ca_cert_path=config.cert_path,
            private_key_path=certs["priv"],
            verify_ssl=False
        )
        await client.connect(username=username, db=db)
        clients.append(client)
        return client

    yield _create_client

    for c in clients:
        await c.close()
