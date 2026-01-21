import pytest
import asyncio

@pytest.mark.asyncio
async def test_rbac_admin_vs_readonly(server_factory, client_factory):
    config = await server_factory()

    admin = await client_factory(config, username="admin")
    guest = await client_factory(config, username="guest")

    # Admin can write
    await admin.set_item_async("key1", "value1")
    assert await admin.get_item_async("key1") == "value1"

    # Guest can read
    assert await guest.get_item_async("key1") == "value1"

    # Guest cannot write
    with pytest.raises(PermissionError) as exc:
        await guest.set_item_async("key2", "value2")
    assert "lacks permission" in str(exc.value)

@pytest.mark.asyncio
async def test_forbidden_methods(server_factory, client_factory):
    config = await server_factory()
    client = await client_factory(config)

    # Calling a forbidden method like 'execute'
    with pytest.raises(PermissionError) as exc:
        await client.execute("SELECT 1")
    assert "globally forbidden" in str(exc.value)

@pytest.mark.asyncio
async def test_path_traversal_protection(server_factory, client_factory):
    config = await server_factory()

    # Attempting to access a DB outside the data dir
    # Note: client.connect raises PermissionError('Auth failed (Phase 2): AUTH_FAILED')
    # because get_db raises ValueError which causes AUTH_FAILED in handle_request
    with pytest.raises(PermissionError) as exc:
        await client_factory(config, db="../secret")
    assert "Auth failed" in str(exc.value)

@pytest.mark.asyncio
async def test_multi_db_isolation(server_factory, client_factory):
    config = await server_factory()

    db1 = await client_factory(config, db="db1")
    db2 = await client_factory(config, db="db2")

    await db1.set_item_async("shared", "from_db1")
    await db2.set_item_async("shared", "from_db2")

    assert await db1.get_item_async("shared") == "from_db1"
    assert await db2.get_item_async("shared") == "from_db2"
