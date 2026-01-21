import pytest
<<<<<<< HEAD
import asyncio
import json
import socket
import logging
from aioquic.asyncio import serve
from aioquic.quic.configuration import QuicConfiguration
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from nanasqlite_server.server import NanaRpcProtocol, ServerConfig, AccountManager
from nanasqlite_server.client import RemoteNanaSQLite
=======
from filelock import FileLock

>>>>>>> 8fab70075150ba75fbca55ecd3edb53f56c4aa53

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

<<<<<<< HEAD
    with open(pub_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH
        ))

    # Auto-generate TLS certs if not present
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"

    # Generate self-signed certificate using cryptography library (cross-platform)
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    import datetime
=======
    - 必要な証明書/鍵がない場合は自動生成
    - セッション終了時に安全に停止
    """
    # 必要な鍵/証明書の準備 (FileLockで排他制御)
    with FileLock("keys.lock"):
        if not os.path.exists("cert.pem") or not os.path.exists("key.pem"):
            from nanasqlite_server.cert_gen import generate_certificate
            generate_certificate()
        if not os.path.exists("nana_public.pub") or not os.path.exists("nana_private.pem"):
            from nanasqlite_server.key_gen import generate_keys
            generate_keys()

    # ポート番号の決定 (xdistワーカーIDに基づく)
    worker_id = os.environ.get("PYTEST_XDIST_WORKER", "gw0")
    try:
        worker_num = int(worker_id.replace("gw", ""))
    except ValueError:
        worker_num = 0
    
    port = 4433 + worker_num
    
    # テストコード側にポート番号を伝える環境変数を設定
    os.environ["NANASQLITE_TEST_PORT"] = str(port)

    # サーバープロセスを起動
    env = os.environ.copy()
    env["NANASQLITE_DISABLE_BAN"] = "1"
    
    # PYTHONPATHを明示的に設定 (カレントプロセスのsys.pathを使用)
    python_path = os.pathsep.join(sys.path)
    env["PYTHONPATH"] = python_path
    
    cmd = [sys.executable, "-m", "nanasqlite_server.server", "--port", str(port)]
    proc = subprocess.Popen(cmd, env=env)  # noqa: S603


    # アクティブな起動確認 (ヘルスチェック)
    # 実際にQUIC接続を試みて、サーバーが応答するか確認する
    async def wait_for_server():
        from aioquic.asyncio import connect
        from aioquic.quic.configuration import QuicConfiguration
        import ssl
        
        config = QuicConfiguration(is_client=True, verify_mode=ssl.CERT_NONE)
        start_wait = time.time()
        
        while time.time() - start_wait < 30.0:  # 最大30秒待機
            if proc.poll() is not None:
                return False  # プロセス終了
                
            try:
                # 接続試行 (タイムアウト短め)
                async with connect("127.0.0.1", port, configuration=config) as _:
                    # 接続できればOK
                    return True
            except Exception:
                # 接続失敗なら少し待って再試行
                await asyncio.sleep(1.0)
        return False

    # イベントループを持ってきて実行
    import asyncio
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        if not loop.run_until_complete(wait_for_server()):
            if proc.poll() is not None:
                stdout, stderr = proc.communicate()
                raise RuntimeError(f"Test server process died. Code: {proc.returncode}\nStderr: {stderr}")
            else:
                proc.kill()
                raise RuntimeError("Timed out waiting for server to start accepting connections.")
    finally:
        loop.close()
>>>>>>> 8fab70075150ba75fbca55ecd3edb53f56c4aa53

    # Generate key
    tls_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Generate certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        tls_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=1)
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(u"localhost"),
        ]),
        critical=False,
    ).sign(tls_key, hashes.SHA256())
    
    # Write key
    with open(key_path, "wb") as f:
        f.write(tls_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Write cert
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

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
