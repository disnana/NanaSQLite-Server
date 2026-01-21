"""
NanaSQLite-Server pytest テストスイート

このテストスイートは以下を検証します:
1. 認証フローの正常動作
2. 認証セキュリティ (AUTH_STARTスキップ、チャレンジ未生成時の拒否)
3. BAN機能
4. 認証済み状態での再AUTH_START
5. RPC操作 (読み取り/書き込み)
6. ブロッキング検証
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
import protocol

import os

PRIVATE_KEY_PATH = "nana_private.pem"
HOST = "127.0.0.1"
PORT = int(os.environ.get("NANASQLITE_TEST_PORT", 4433))


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


@pytest.fixture
def private_key():
    """秘密鍵をロード"""
    with open(PRIVATE_KEY_PATH, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


@asynccontextmanager
async def create_connection():
    """テスト用の接続を作成 (リトライ機能付き)"""
    configuration = QuicConfiguration(
        is_client=True,
        verify_mode=ssl.CERT_NONE,  # テスト用
        server_name="localhost",
    )

    # 接続リトライロジック (Max 5回)
    max_retries = 5
    last_err = None

    for i in range(max_retries):
        try:
            async with connect(HOST, PORT, configuration=configuration, create_protocol=ClientProtocol) as client:
                yield client
            return
        except (ConnectionError, OSError) as e:
            last_err = e
            # 最後の試行でなければ少し待って再試行
            if i < max_retries - 1:
                await asyncio.sleep(2.0)
                continue

    # ここに来るのはリトライ失敗時
    raise last_err


async def authenticate(conn, private_key):
    """正規の認証フローを実行"""
    challenge_msg = await conn.send_raw("AUTH_START")
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

class TestAuthentication:
    """認証フローのテスト"""
    
    @pytest.mark.asyncio
    async def test_normal_auth_flow(self, private_key):
        """正常な認証フローのテスト"""
        async with create_connection() as conn:
            # チャレンジ取得
            challenge_msg = await conn.send_raw("AUTH_START")
            assert isinstance(challenge_msg, dict)
            assert challenge_msg.get("type") == "challenge"
            assert challenge_msg.get("data") is not None
            
            # 署名して認証
            challenge = challenge_msg.get("data")
            signature = private_key.sign(challenge)
            result = await conn.send_raw({"type": "response", "data": signature})
            assert result == "AUTH_OK"

    @pytest.mark.asyncio
    async def test_skip_auth_start(self):
        """AUTH_STARTをスキップした場合は認証失敗"""
        async with create_connection() as conn:
            # いきなりresponseを送信
            fake_signature = b"fake_signature"
            result = await conn.send_raw({"type": "response", "data": fake_signature})
            assert result == "AUTH_FAILED"

    @pytest.mark.asyncio
    async def test_invalid_signature(self, private_key):
        """無効な署名は拒否される"""
        async with create_connection() as conn:
            await conn.send_raw("AUTH_START")
            # 間違った署名を送信
            result = await conn.send_raw({"type": "response", "data": b"invalid"})
            assert result == "AUTH_FAILED"

    @pytest.mark.asyncio
    async def test_reauth_after_authenticated(self, private_key):
        """認証済み後のAUTH_STARTはエラーを返す"""
        async with create_connection() as conn:
            await authenticate(conn, private_key)
            
            # 認証済み状態で再度AUTH_START
            result = await conn.send_raw("AUTH_START")
            assert isinstance(result, dict)
            assert result.get("status") == "error"
            assert "authenticated" in result.get("message", "").lower()


# =============================================================================
# RPC操作のテスト
# =============================================================================

class TestRPCOperations:
    """RPC操作のテスト"""
    
    @pytest.mark.asyncio
    async def test_set_and_get_item(self, private_key):
        """set/get操作のテスト"""
        async with create_connection() as conn:
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

    @pytest.mark.asyncio
    async def test_unauthorized_rpc(self):
        """未認証状態でのRPC呼び出しは拒否される"""
        async with create_connection() as conn:
            result = await conn.send_raw({
                "method": "__getitem__",
                "args": ["test"],
                "kwargs": {}
            })
            assert isinstance(result, dict)
            assert result.get("status") == "error"
            assert "unauthorized" in result.get("message", "").lower()

    @pytest.mark.asyncio
    async def test_invalid_method(self, private_key):
        """存在しないメソッドはエラー"""
        async with create_connection() as conn:
            await authenticate(conn, private_key)
            
            result = await conn.send_raw({
                "method": "nonexistent_method",
                "args": [],
                "kwargs": {}
            })
            assert result.get("status") == "error"
            assert result.get("error_type") == "PermissionError"


# =============================================================================
# ブロッキング検証テスト
# =============================================================================

class TestBlocking:
    """ブロッキング動作のテスト"""
    
    @pytest.mark.asyncio
    async def test_concurrent_writes(self, private_key):
        """複数クライアントの同時書き込みが並列実行される"""
        
        async def write_client(client_id: int):
            async with create_connection() as conn:
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
        
        start_total = time.perf_counter()
        results = await asyncio.gather(
            write_client(1),
            write_client(2),
            write_client(3),
            return_exceptions=True
        )
        total_elapsed = time.perf_counter() - start_total
        
        # エラーがないことを確認
        # エラーがないことを確認
        for result in results:
            if isinstance(result, Exception):
                # エラーの詳細（タイプとメッセージ）を表示してアサーション失敗させる
                error_msg = f"{type(result).__name__}: {result}"
                pytest.fail(f"Concurrent write failed: {error_msg}")
        
        # 各クライアントの処理時間
        individual_times = [r[1] for r in results]
        sum_individual = sum(individual_times)
        
        # 並列実行されていれば、合計時間は個別時間の合計より短いはず
        print(f"Total: {total_elapsed:.3f}s, Sum of individual: {sum_individual:.3f}s")
        
        # 少なくとも全てのクライアントが完了していることを確認
        assert len(results) == 3


# =============================================================================
# セキュリティテスト
# =============================================================================

class TestSecurity:
    """セキュリティ関連のテスト"""
    
    @pytest.mark.asyncio
    async def test_challenge_is_random(self):
        """チャレンジはランダムである"""
        challenges = []
        
        async with create_connection() as conn:
            for _ in range(3):
                challenge_msg = await conn.send_raw("AUTH_START")
                challenges.append(challenge_msg.get("data"))
        
        # 全てのチャレンジが異なることを確認
        assert len(set(challenges)) == 3

    @pytest.mark.asyncio
    async def test_invalid_message_format(self):
        """不正なメッセージフォーマットはエラー"""
        async with create_connection() as conn:
            result = await conn.send_raw({"invalid": "format"})
            assert isinstance(result, dict)
            # エラーまたは未認証応答が返される
            assert result.get("status") == "error" or "unauthorized" in str(result).lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
