"""
PQC セキュリティ回帰テスト

コミット 59c77da で修正された3つのセキュリティ脆弱性のリグレッションテスト。
これらのテストは liboqs-python なしで実行できます。

修正された脆弱性:
1. サーバー: pqc_session_key が有効な状態でのサイレント復号ドロップ
   → エラーレスポンスを送信して接続を閉じるよう修正
2. サーバー: 不正な暗号文で KEM デカプセル化を失敗させることによる
   KEM 必須チェック迂回攻撃 → 失敗時に接続を閉じるよう修正
3. クライアント: session_key が有効な状態での None レスポンスのキューイング
   → エラー dict をキューに入れて接続を閉じるよう修正
"""

import asyncio
import os
from unittest.mock import MagicMock, patch

import pytest

from nanasqlite_server import protocol


# ---------------------------------------------------------------------------
# Mock QUIC 接続ヘルパー
# ---------------------------------------------------------------------------


def _make_mock_quic():
    """send_stream_data / close の呼び出しを記録するモック QUIC オブジェクトを作成"""
    quic = MagicMock()
    quic.send_stream_data = MagicMock()
    quic.close = MagicMock()
    quic.get_next_available_stream_id = MagicMock(return_value=0)
    return quic


def _make_server_protocol(pqc_kem_algorithm=None):
    """実際の QUIC 接続なしにテスト用の NanaRpcProtocol インスタンスを生成する"""
    from nanasqlite_server.server import NanaRpcProtocol

    mock_quic = _make_mock_quic()
    mock_account_manager = MagicMock()

    # QuicConnectionProtocol.__init__ を迂回して直接インスタンス化する
    with patch("aioquic.asyncio.QuicConnectionProtocol.__init__", return_value=None):
        proto = NanaRpcProtocol.__new__(NanaRpcProtocol)
        # QuicConnectionProtocol が設定するはずのインスタンス変数を手動で初期化
        proto._quic = mock_quic
        proto._ping_waiter = None
        proto._transmit_task = None
        # NanaRpcProtocol.__init__ が使う変数を手動設定
        from collections import defaultdict
        proto.db = None
        proto.authenticated = True  # デフォルトで認証済み
        proto.account = MagicMock()
        proto.challenge = None
        proto.client_ip = "127.0.0.1"
        proto.stream_buffers = defaultdict(bytearray)
        proto.total_buffer_size = 0
        proto.account_manager = mock_account_manager
        proto.default_allowed_methods = None
        proto.default_forbidden_methods = None
        proto.last_db_name = None
        proto._background_tasks = set()
        proto._pqc_kem_algorithm = pqc_kem_algorithm
        proto._kem_instance = None
        proto.pqc_session_key = None

    return proto


def _make_client_protocol():
    """実際の QUIC 接続なしにテスト用の NanaRpcClientProtocol インスタンスを生成する"""
    from nanasqlite_server.client import NanaRpcClientProtocol

    mock_quic = _make_mock_quic()

    with patch("aioquic.asyncio.QuicConnectionProtocol.__init__", return_value=None):
        proto = NanaRpcClientProtocol.__new__(NanaRpcClientProtocol)
        proto._quic = mock_quic
        proto._ping_waiter = None
        proto._transmit_task = None
        proto._responses = asyncio.Queue()
        proto.session_key = None
        proto._stream_buffers = {}

    return proto


# ---------------------------------------------------------------------------
# テストクラス 1: サーバー側 PQC 復号失敗の処理
# ---------------------------------------------------------------------------


class TestServerPqcDecryptFailure:
    """
    サーバーで pqc_session_key が有効なときに復号が失敗した場合の挙動をテスト。

    修正前の問題: メッセージが None になっても何もしないでリターン (サイレントドロップ)。
    修正後の挙動: エラーレスポンスを送信し、接続を閉じる。
    """

    @pytest.fixture
    def proto(self):
        return _make_server_protocol()

    @pytest.mark.asyncio
    async def test_decrypt_failure_sends_error_response(self, proto):
        """復号失敗時に 'Invalid encrypted request' エラーが送信されることを確認"""
        session_key = os.urandom(32)
        proto.pqc_session_key = session_key

        # 正しい鍵で暗号化し、内容を改ざんして復号不能にする
        valid_encrypted = bytearray(protocol.encrypt_message({"test": 1}, session_key))
        valid_encrypted[-1] ^= 0xFF  # 改ざん
        bad_data = bytes(valid_encrypted)

        with patch.object(proto, "transmit"):
            await proto.handle_request(0, bad_data)

        # _quic.send_stream_data が呼ばれていることを確認
        assert proto._quic.send_stream_data.called, "サーバーはエラーレスポンスを送信すべき"
        # _send_response は pqc_session_key が有効なのでエラーレスポンスも暗号化して送る
        sent_payload = proto._quic.send_stream_data.call_args[0][1]
        decoded_msg, _ = protocol.decrypt_message(sent_payload, session_key)
        assert decoded_msg is not None
        assert decoded_msg.get("status") == "error"
        assert "Invalid encrypted request" in decoded_msg.get("message", "")

    @pytest.mark.asyncio
    async def test_decrypt_failure_closes_connection(self, proto):
        """復号失敗時に接続が閉じられることを確認"""
        session_key = os.urandom(32)
        proto.pqc_session_key = session_key

        bad_data = b"\x00\x00\x00\x10" + b"\xFF" * 16  # 不正な暗号文

        with patch.object(proto, "transmit"):
            await proto.handle_request(0, bad_data)

        proto._quic.close.assert_called()

    @pytest.mark.asyncio
    async def test_no_session_key_none_data_does_not_close(self, proto):
        """pqc_session_key がない場合、None データはエラーや close を引き起こさない"""
        proto.pqc_session_key = None  # セッション鍵なし

        bad_data = b"\x00"  # decode_message が None を返す不正なデータ

        with patch.object(proto, "transmit"):
            await proto.handle_request(0, bad_data)

        # セッション鍵がない場合は close を呼んではならない
        proto._quic.close.assert_not_called()

    @pytest.mark.asyncio
    async def test_valid_encrypted_message_processes_normally(self, proto):
        """正しく暗号化されたメッセージが通常通り処理されることを確認"""
        session_key = os.urandom(32)
        proto.pqc_session_key = session_key

        # AUTH_START は認証済み状態で無視されるが、処理自体は進む
        valid_data = protocol.encrypt_message("AUTH_START", session_key)

        with patch.object(proto, "transmit"):
            await proto.handle_request(0, valid_data)

        # 復号は成功するので close は呼ばれない
        proto._quic.close.assert_not_called()


# ---------------------------------------------------------------------------
# テストクラス 2: サーバー側 KEM デカプセル化失敗によるバイパス防止
# ---------------------------------------------------------------------------


class TestServerKemDecapsulationFailure:
    """
    KEM デカプセル化が失敗した場合に接続を切断してバイパスを防止するテスト。

    修正前の問題: _kem_instance を None にして return するだけだったため、
    攻撃者は不正な暗号文を1回送ることで _kem_instance を None に戻し、
    KEM 必須チェックを迂回して RPC を実行できた。
    修正後の挙動: デカプセル化失敗時に接続を閉じる。
    """

    @pytest.fixture
    def proto_with_kem(self):
        proto = _make_server_protocol(pqc_kem_algorithm="Kyber512")
        # 失敗するモック KEM インスタンスを設定
        mock_kem = MagicMock()
        mock_kem.decap_secret.side_effect = Exception("KEM decap failed (simulated)")
        proto._kem_instance = mock_kem
        return proto

    @pytest.mark.asyncio
    async def test_kem_decap_failure_closes_connection(self, proto_with_kem):
        """KEM デカプセル化失敗時に接続が閉じられることを確認"""
        proto = proto_with_kem

        kem_response = protocol.encode_message(
            {"type": "kem_response", "ciphertext": b"\xFF" * 32}
        )

        with patch.object(proto, "transmit"):
            await proto.handle_request(0, kem_response)

        proto._quic.close.assert_called()

    @pytest.mark.asyncio
    async def test_kem_decap_failure_sends_error_response(self, proto_with_kem):
        """KEM デカプセル化失敗時にエラーレスポンスが送信されることを確認"""
        proto = proto_with_kem

        kem_response = protocol.encode_message(
            {"type": "kem_response", "ciphertext": b"\xFF" * 32}
        )

        with patch.object(proto, "transmit"):
            await proto.handle_request(0, kem_response)

        assert proto._quic.send_stream_data.called
        sent_payload = proto._quic.send_stream_data.call_args[0][1]
        decoded_msg, _ = protocol.decode_message(sent_payload)
        assert decoded_msg is not None
        assert decoded_msg.get("status") == "error"

    @pytest.mark.asyncio
    async def test_kem_decap_failure_prevents_rpc_bypass(self, proto_with_kem):
        """
        KEM デカプセル化失敗後に RPC が実行できないことを確認 (バイパス防止)。
        修正前は _kem_instance が None になった後に RPC リクエストを送ると処理されていた。
        修正後は接続が閉じられるためそもそも後続リクエストが来ない。
        """
        proto = proto_with_kem

        # Step 1: 不正な KEM レスポンスを送って失敗させる
        bad_kem = protocol.encode_message(
            {"type": "kem_response", "ciphertext": b"\xFF" * 32}
        )
        with patch.object(proto, "transmit"):
            await proto.handle_request(0, bad_kem)

        # KEM 失敗後、_kem_instance は None になっているはずだが接続は閉じられている
        assert proto._kem_instance is None
        proto._quic.close.assert_called()

    @pytest.mark.asyncio
    async def test_kem_instance_freed_on_failure(self, proto_with_kem):
        """KEM デカプセル化失敗時に KEM インスタンスのリソースが解放されることを確認"""
        proto = proto_with_kem
        mock_kem = proto._kem_instance

        kem_response = protocol.encode_message(
            {"type": "kem_response", "ciphertext": b"\xFF" * 32}
        )

        with patch.object(proto, "transmit"):
            await proto.handle_request(0, kem_response)

        # free() が呼ばれ _kem_instance が None になっていることを確認
        mock_kem.free.assert_called()
        assert proto._kem_instance is None


# ---------------------------------------------------------------------------
# テストクラス 3: クライアント側 PQC 復号失敗の処理
# ---------------------------------------------------------------------------


class TestClientPqcDecryptFailure:
    """
    クライアントで session_key が有効なときに復号が失敗した場合の挙動をテスト。

    修正前の問題: 復号失敗で message が None になっても None をキューに入れていた。
    修正後の挙動: エラー dict をキューに入れて接続を閉じる。
    """

    @pytest.fixture
    def client_proto(self):
        return _make_client_protocol()

    def test_decrypt_failure_enqueues_error_dict(self, client_proto):
        """session_key 有効時に復号失敗するとエラー dict がキューに入ることを確認"""
        from aioquic.quic.events import StreamDataReceived

        session_key = os.urandom(32)
        client_proto.session_key = session_key

        # 不正な暗号化データ (改ざん済み)
        valid_encrypted = bytearray(protocol.encrypt_message({"response": "ok"}, session_key))
        valid_encrypted[-1] ^= 0xFF
        bad_data = bytes(valid_encrypted)

        event = StreamDataReceived(stream_id=0, data=bad_data, end_stream=True)

        with patch.object(client_proto, "close"):
            client_proto.quic_event_received(event)

        # キューにエラー dict が入っていることを確認
        assert not client_proto._responses.empty()
        response = client_proto._responses.get_nowait()
        assert isinstance(response, dict), "None ではなく dict が返されるべき"
        assert response.get("status") == "error"

    def test_decrypt_failure_closes_connection(self, client_proto):
        """session_key 有効時に復号失敗すると接続が閉じられることを確認"""
        from aioquic.quic.events import StreamDataReceived

        session_key = os.urandom(32)
        client_proto.session_key = session_key

        bad_data = b"\x00\x00\x00\x10" + b"\xFF" * 16

        event = StreamDataReceived(stream_id=0, data=bad_data, end_stream=True)

        with patch.object(client_proto, "close") as mock_close:
            client_proto.quic_event_received(event)

        mock_close.assert_called()

    def test_decrypt_failure_does_not_enqueue_none(self, client_proto):
        """session_key 有効時に復号失敗しても None がキューに入らないことを確認"""
        from aioquic.quic.events import StreamDataReceived

        session_key = os.urandom(32)
        client_proto.session_key = session_key

        bad_data = b"\x00\x00\x00\x04\xFF\xFF\xFF\xFF"

        event = StreamDataReceived(stream_id=0, data=bad_data, end_stream=True)

        with patch.object(client_proto, "close"):
            client_proto.quic_event_received(event)

        # None がキューに入っていないことを確認
        if not client_proto._responses.empty():
            response = client_proto._responses.get_nowait()
            assert response is not None, "None がキューに入ってはならない"

    def test_no_session_key_uses_decode_message(self, client_proto):
        """session_key がない場合は通常の decode_message が使われることを確認"""
        from aioquic.quic.events import StreamDataReceived

        # セッション鍵なし - 通常の encode/decode を使う
        client_proto.session_key = None
        data = {"status": "success", "result": "hello"}
        valid_encoded = protocol.encode_message(data)

        event = StreamDataReceived(stream_id=0, data=valid_encoded, end_stream=True)
        client_proto.quic_event_received(event)

        assert not client_proto._responses.empty()
        response = client_proto._responses.get_nowait()
        assert response == data

    def test_valid_encrypted_message_decodes_correctly(self, client_proto):
        """session_key 有効時に正常な暗号化メッセージが正しく復号されることを確認"""
        from aioquic.quic.events import StreamDataReceived

        session_key = os.urandom(32)
        client_proto.session_key = session_key

        expected = {"status": "success", "result": 42}
        encrypted = protocol.encrypt_message(expected, session_key)

        event = StreamDataReceived(stream_id=0, data=encrypted, end_stream=True)
        client_proto.quic_event_received(event)

        assert not client_proto._responses.empty()
        response = client_proto._responses.get_nowait()
        assert response == expected


# ---------------------------------------------------------------------------
# テストクラス 4: クライアント側ストリームバッファリング (Windows断片化対応)
# ---------------------------------------------------------------------------


class TestClientStreamBuffering:
    """
    クライアントが断片化されたストリームデータを正しく処理することを検証するテスト。

    Windowsなど一部の環境では、サーバーからの大きなレスポンス (例: auth_ok に含まれる
    ML-KEM-768 公開鍵 ~1200バイト) が複数の StreamDataReceived イベントに分割される。
    修正前: 最初のフラグメントで decode_message が None を返し、None がキューに入る
           → "Authentication failed: None" エラーが発生
    修正後: end_stream=True まで全フラグメントをバッファリングし、完全なメッセージを処理
    """

    @pytest.fixture
    def client_proto(self):
        return _make_client_protocol()

    def test_fragmented_response_buffered_until_end_stream(self, client_proto):
        """フラグメント化されたレスポンスが end_stream=True まで処理されないことを確認"""
        from aioquic.quic.events import StreamDataReceived

        data = protocol.encode_message("AUTH_OK")
        mid = len(data) // 2
        part1, part2 = data[:mid], data[mid:]

        # 最初のフラグメント (end_stream=False) - まだキューに入らない
        event1 = StreamDataReceived(stream_id=0, data=part1, end_stream=False)
        client_proto.quic_event_received(event1)
        assert client_proto._responses.qsize() == 0, "フラグメント受信中はキューに入ってはならない"

        # 最後のフラグメント (end_stream=True) - 完全なメッセージをキューに入れる
        event2 = StreamDataReceived(stream_id=0, data=part2, end_stream=True)
        client_proto.quic_event_received(event2)
        assert client_proto._responses.qsize() == 1, "ストリーム完了後にキューに入るべき"
        assert client_proto._responses.get_nowait() == "AUTH_OK"

    def test_fragmented_response_does_not_enqueue_none(self, client_proto):
        """断片化されたレスポンスで None がキューに入らないことを確認 (Windows回帰テスト)"""
        from aioquic.quic.events import StreamDataReceived

        # サーバーの auth_ok レスポンスを模倣 (KEM公開鍵を含む大きなメッセージ)
        large_response = {
            "type": "auth_ok",
            "kem": {
                "algorithm": "ML-KEM-768",
                "public_key": os.urandom(1184),  # ML-KEM-768 公開鍵サイズ
            },
        }
        data = protocol.encode_message(large_response)

        # 3つのフラグメントに分割 (Windows等で起こりうる断片化を模倣)
        third = len(data) // 3
        parts = [data[:third], data[third:2 * third], data[2 * third:]]

        for i, part in enumerate(parts):
            is_last = i == len(parts) - 1
            event = StreamDataReceived(stream_id=0, data=part, end_stream=is_last)
            client_proto.quic_event_received(event)
            if not is_last:
                assert client_proto._responses.qsize() == 0

        # 最終的にキューに入った値が None でないことを確認
        assert client_proto._responses.qsize() == 1
        response = client_proto._responses.get_nowait()
        assert response is not None, "断片化されたレスポンスで None がキューに入ってはならない"
        assert response == large_response

    def test_single_packet_response_still_works(self, client_proto):
        """断片化されていない通常のレスポンスが引き続き正しく処理されることを確認"""
        from aioquic.quic.events import StreamDataReceived

        data = protocol.encode_message({"type": "challenge", "data": b"x" * 32})
        event = StreamDataReceived(stream_id=0, data=data, end_stream=True)
        client_proto.quic_event_received(event)

        assert client_proto._responses.qsize() == 1
        response = client_proto._responses.get_nowait()
        assert response == {"type": "challenge", "data": b"x" * 32}

    def test_multiple_streams_buffered_independently(self, client_proto):
        """複数のストリームのバッファが独立して管理されることを確認"""
        from aioquic.quic.events import StreamDataReceived

        data0 = protocol.encode_message("STREAM_0")
        data1 = protocol.encode_message("STREAM_1")
        mid0, mid1 = len(data0) // 2, len(data1) // 2

        # ストリーム 0 の最初のフラグメント
        client_proto.quic_event_received(
            StreamDataReceived(stream_id=0, data=data0[:mid0], end_stream=False)
        )
        # ストリーム 1 の最初のフラグメント
        client_proto.quic_event_received(
            StreamDataReceived(stream_id=1, data=data1[:mid1], end_stream=False)
        )
        assert client_proto._responses.qsize() == 0

        # ストリーム 1 を先に完了
        client_proto.quic_event_received(
            StreamDataReceived(stream_id=1, data=data1[mid1:], end_stream=True)
        )
        assert client_proto._responses.qsize() == 1
        assert client_proto._responses.get_nowait() == "STREAM_1"

        # ストリーム 0 を完了
        client_proto.quic_event_received(
            StreamDataReceived(stream_id=0, data=data0[mid0:], end_stream=True)
        )
        assert client_proto._responses.qsize() == 1
        assert client_proto._responses.get_nowait() == "STREAM_0"

    def test_stream_buffer_cleared_after_end_stream(self, client_proto):
        """end_stream=True の後にストリームバッファが解放されることを確認 (メモリリーク防止)"""
        from aioquic.quic.events import StreamDataReceived

        data = protocol.encode_message("TEST")
        event = StreamDataReceived(stream_id=42, data=data, end_stream=True)
        client_proto.quic_event_received(event)

        # バッファが解放されていることを確認
        assert 42 not in client_proto._stream_buffers

    def test_fragmented_encrypted_response_decrypts_correctly(self, client_proto):
        """断片化された暗号化レスポンスが正しく復号されることを確認"""
        from aioquic.quic.events import StreamDataReceived

        session_key = os.urandom(32)
        client_proto.session_key = session_key

        expected = {"status": "success", "result": "encrypted_value"}
        encrypted = protocol.encrypt_message(expected, session_key)
        mid = len(encrypted) // 2
        part1, part2 = encrypted[:mid], encrypted[mid:]

        # 1つ目のフラグメント
        event1 = StreamDataReceived(stream_id=0, data=part1, end_stream=False)
        client_proto.quic_event_received(event1)
        assert client_proto._responses.qsize() == 0

        # 2つ目のフラグメント (最終)
        event2 = StreamDataReceived(stream_id=0, data=part2, end_stream=True)
        with patch.object(client_proto, "close"):
            client_proto.quic_event_received(event2)

        assert client_proto._responses.qsize() == 1
        response = client_proto._responses.get_nowait()
        assert response == expected
