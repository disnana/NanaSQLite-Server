import pytest
import os
from nanasqlite_server.client import RemoteNanaSQLite

PORT = int(os.environ.get("NANASQLITE_TEST_PORT", 4433))

@pytest.mark.asyncio
async def test_admin_permissions():
    """管理者はほとんどの操作が可能"""
    client = RemoteNanaSQLite(host="127.0.0.1", port=PORT, verify_ssl=False, private_key_path="nana_private.pem")
    await client.connect()
    try:
        await client.set_item_async("admin_test", "value")
        val = await client.get_item_async("admin_test")
        assert val == "value"

        with pytest.raises(Exception) as excinfo:
            await client.__getattr__("close")()
        assert "forbidden" in str(excinfo.value).lower()
    finally:
        await client.close()

@pytest.mark.asyncio
async def test_readonly_permissions():
    """閲覧専用ユーザーは書き込みが拒否される"""
    client = RemoteNanaSQLite(host="127.0.0.1", port=PORT, verify_ssl=False, private_key_path="user_private.pem")
    await client.connect()
    try:
        await client.keys()
        with pytest.raises(Exception) as excinfo:
            await client.set_item_async("readonly_test", "should_fail")
        assert "forbidden" in str(excinfo.value).lower() or "not allowed" in str(excinfo.value).lower()

    finally:
        await client.close()
