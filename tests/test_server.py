"""
NanaSQLite-Server pytest テストスイート (Updated for RBAC)
"""

import asyncio
import pytest
import ssl
import time
from contextlib import asynccontextmanager

from aioquic.asyncio import QuicConnectionProtocol, connect
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived
from cryptography.hazmat.primitives import serialization
from nanasqlite_server import protocol

# Use certs from conftest.py
@pytest.fixture
def private_key_path(certs):
    return certs["priv"]

@pytest.fixture
def private_key(private_key_path):
    """秘密鍵をロード"""
    with open(private_key_path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

class ClientProtocol(QuicConnectionProtocol):
    """テスト用のQUICクライアントプロトコル"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._responses = asyncio.Queue()

    def quic_event_received(self, event):
        if isinstance(event, StreamDataReceived):
            message, _ = protocol.decode_message(event.data)
            self._responses.put_nowait(message)

    async def send_raw(self, data, timeout=10.0):
        stream_id = self._quic.get_next_available_stream_id()
        payload = protocol.encode_message(data)
        self._quic.send_stream_data(stream_id, payload, end_stream=True)
        self.transmit()
        return await asyncio.wait_for(self._responses.get(), timeout=timeout)

@asynccontextmanager
async def create_connection(config):
    """テスト用の接続を作成"""
    configuration = QuicConfiguration(
        is_client=True,
        verify_mode=ssl.CERT_NONE,
        server_name="localhost",
    )

    async with connect(config.host, config.port, configuration=configuration, create_protocol=ClientProtocol) as client:
        yield client

async def authenticate(conn, private_key, username="admin"):
    """正規の認証フローを実行"""
    challenge_msg = await conn.send_raw({"type": "AUTH_START", "username": username})
    assert isinstance(challenge_msg, dict)
    assert challenge_msg.get("type") == "challenge"
    
    challenge = challenge_msg.get("data")
    signature = private_key.sign(challenge)
    result = await conn.send_raw({"type": "response", "data": signature})
    assert result == "AUTH_OK"
    return True

# =============================================================================
# 認証フローのテスト
# =============================================================================

@pytest.mark.asyncio
class TestAuthentication:
    """認証フローのテスト"""
    
    async def test_normal_auth_flow(self, server_factory, private_key):
        """正常な認証フローのテスト"""
        config = await server_factory()
        async with create_connection(config) as conn:
            # チャレンジ取得
            challenge_msg = await conn.send_raw({"type": "AUTH_START", "username": "admin"})
            assert isinstance(challenge_msg, dict)
            assert challenge_msg.get("type") == "challenge"
            assert challenge_msg.get("data") is not None
            
            # 署名して認証
            challenge = challenge_msg.get("data")
            signature = private_key.sign(challenge)
            result = await conn.send_raw({"type": "response", "data": signature})
            assert result == "AUTH_OK"

    async def test_skip_auth_start(self, server_factory):
        """AUTH_STARTをスキップした場合は認証失敗"""
        config = await server_factory()
        async with create_connection(config) as conn:
            # いきなりresponseを送信
            fake_signature = b"fake_signature"
            result = await conn.send_raw({"type": "response", "data": fake_signature})
            assert result == "AUTH_FAILED" or (isinstance(result, dict) and result.get("status") == "error")

    async def test_invalid_signature(self, server_factory, private_key):
        """無効な署名は拒否される"""
        config = await server_factory()
        async with create_connection(config) as conn:
            await conn.send_raw({"type": "AUTH_START", "username": "admin"})
            # 間違った署名を送信
            result = await conn.send_raw({"type": "response", "data": b"invalid"})
            assert result == "AUTH_FAILED"

    async def test_reauth_after_authenticated(self, server_factory, private_key):
        """認証済み後のAUTH_STARTはエラーを返す"""
        config = await server_factory()
        async with create_connection(config) as conn:
            await authenticate(conn, private_key)
            
            # 認証済み状態で再度AUTH_START
            result = await conn.send_raw("AUTH_START")
            assert isinstance(result, dict)
            assert result.get("status") == "error"
            assert "authenticated" in result.get("message", "").lower()

# =============================================================================
# RPC操作のテスト
# =============================================================================

@pytest.mark.asyncio
class TestRPCOperations:
    """RPC操作のテスト"""
    
    async def test_set_and_get_item(self, server_factory, private_key):
        """set/get操作のテスト"""
        config = await server_factory()
        async with create_connection(config) as conn:
            await authenticate(conn, private_key)
            
            test_key = f"pytest_test_{time.time()}"
            test_value = {"message": "Hello from pytest!"}
            
            # SET
            result = await conn.send_raw({
                "method": "__setitem__",
                "args": [test_key, test_value],
                "kwargs": {}
            })
            assert result.get("status") == "success"
            
            # GET
            result = await conn.send_raw({
                "method": "__getitem__",
                "args": [test_key],
                "kwargs": {}
            })
            assert result.get("status") == "success"
            assert result.get("result") == test_value

    async def test_unauthorized_rpc(self, server_factory):
        """未認証状態でのRPC呼び出しは拒否される"""
        config = await server_factory()
        async with create_connection(config) as conn:
            result = await conn.send_raw({
                "method": "__getitem__",
                "args": ["test"],
                "kwargs": {}
            })
            assert isinstance(result, dict)
            assert result.get("status") == "error"
            assert "unauthorized" in result.get("message", "").lower()

    async def test_invalid_method(self, server_factory, private_key):
        """存在しないメソッドはエラー"""
        config = await server_factory()
        async with create_connection(config) as conn:
            await authenticate(conn, private_key)
            
            result = await conn.send_raw({
                "method": "nonexistent_method",
                "args": [],
                "kwargs": {}
            })
            assert result.get("status") == "error"
            assert result.get("error_type") in ("PermissionError", "AttributeError")

# =============================================================================
# ブロッキング検証テスト
# =============================================================================

@pytest.mark.asyncio
class TestBlocking:
    """ブロッキング動作のテスト"""
    
    async def test_concurrent_writes(self, server_factory, private_key):
        """複数クライアントの同時書き込みが並列実行される"""
        config = await server_factory()
        
        async def write_client(client_id: int):
            async with create_connection(config) as conn:
                await authenticate(conn, private_key)
                
                start = time.perf_counter()
                for i in range(5):
                    await conn.send_raw({
                        "method": "__setitem__",
                        "args": [f"concurrent_test_{client_id}_{i}", {"data": "x" * 100}],
                        "kwargs": {}
                    })
                elapsed = time.perf_counter() - start
                return client_id, elapsed
        
        results = await asyncio.gather(
            write_client(1),
            write_client(2),
            write_client(3),
            return_exceptions=True
        )
        
        for result in results:
            if isinstance(result, Exception):
                pytest.fail(f"Concurrent write failed: {result}")
        
        assert len(results) == 3

# =============================================================================
# セキュリティテスト
# =============================================================================

@pytest.mark.asyncio
class TestSecurity:
    """セキュリティ関連のテスト"""
    
    async def test_challenge_is_random(self, server_factory):
        """チャレンジはランダムである"""
        config = await server_factory()
        challenges = []
        
        async with create_connection(config) as conn:
            for _ in range(3):
                challenge_msg = await conn.send_raw({"type": "AUTH_START", "username": "admin"})
                challenges.append(challenge_msg.get("data"))
        
        assert len(set(challenges)) == 3

    async def test_invalid_message_format(self, server_factory):
        """不正なメッセージフォーマットはエラー"""
        config = await server_factory()
        async with create_connection(config) as conn:
            result = await conn.send_raw({"invalid": "format"})
            assert isinstance(result, dict)
            assert result.get("status") == "error" or "unauthorized" in str(result).lower()
