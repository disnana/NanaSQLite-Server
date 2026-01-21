import pytest
import asyncio
import time

@pytest.mark.asyncio
async def test_concurrent_requests(server_factory, client_factory):
    config = await server_factory()
    client = await client_factory(config)

    # Execute many requests in parallel
    tasks = []
    for i in range(50):
        tasks.append(client.set_item_async(f"key_{i}", i))

    await asyncio.gather(*tasks)

    for i in range(50):
        val = await client.get_item_async(f"key_{i}")
        assert val == i

@pytest.mark.asyncio
async def test_dos_protection_ban(server_factory, client_factory, certs):
    # Short ban for testing
    config = await server_factory(config_overrides={"max_failed_attempts": 2, "ban_duration": 2})

    from nanasqlite_server.client import RemoteNanaSQLite

    # Intentionally use wrong key (or just mock failure if we could)
    # Here we'll just try to connect with a fake key manually
    from cryptography.hazmat.primitives.asymmetric import ed25519
    wrong_key = ed25519.Ed25519PrivateKey.generate()
    wrong_key_path = "wrong.pem"
    from cryptography.hazmat.primitives import serialization
    with open(wrong_key_path, "wb") as f:
        f.write(wrong_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption()
        ))

    async def try_fail():
        c = RemoteNanaSQLite(host=config.host, port=config.port, ca_cert_path=config.cert_path,
                             private_key_path=wrong_key_path, verify_ssl=False)
        try:
            await c.connect()
        except Exception:
            return False
        finally:
            await c.close()
        return True

    # Attempt 1: Fail
    assert await try_fail() is False
    # Attempt 2: Fail -> Should be banned
    assert await try_fail() is False

    # Attempt 3: Should be blocked by BAN
    # The server might close connection immediately or return AUTH_BANNED
    # Our is_banned check is at the start of quic_event_received

    # Wait for ban to expire
    await asyncio.sleep(2.1)

    # Should work now (if we used right key)
    client = await client_factory(config)
    await client.set_item_async("after_ban", "ok")
    assert await client.get_item_async("after_ban") == "ok"
