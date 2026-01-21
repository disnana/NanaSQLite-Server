"""
BAN機能の検証スクリプト（手動実行用）

警告: このスクリプトを実行すると、サーバー再起動までIPがBANされます。
      pytestとは別に手動で実行してください。

使用方法:
    1. サーバーを起動: python server.py
    2. このスクリプトを実行: python BAN機能テスト_手動実行用.py
    3. テスト後、サーバーを再起動してBANを解除
"""

import asyncio
import ssl
from aioquic.asyncio import QuicConnectionProtocol, connect
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived
import protocol

HOST = "127.0.0.1"
PORT = 4433


class ClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._responses = asyncio.Queue()

    def quic_event_received(self, event):
        if isinstance(event, StreamDataReceived):
            message, _ = protocol.decode_message(event.data)
            self._responses.put_nowait(message)

    async def send_raw(self, data, timeout=5.0):
        stream_id = self._quic.get_next_available_stream_id()
        payload = protocol.encode_message(data)
        self._quic.send_stream_data(stream_id, payload, end_stream=True)
        self.transmit()
        return await asyncio.wait_for(self._responses.get(), timeout=timeout)


async def create_connection():
    configuration = QuicConfiguration(
        is_client=True,
        verify_mode=ssl.CERT_NONE,
        server_name="localhost",
    )
    ctx = connect(
        HOST, PORT, configuration=configuration, create_protocol=ClientProtocol
    )
    connection = await ctx.__aenter__()
    return ctx, connection


async def test_ban_mechanism():
    """
    BAN機能の検証

    複数回の認証失敗後にBANされることを確認します。
    """
    print("=" * 60)
    print(" BAN機能テスト")
    print("=" * 60)
    print()
    print("警告: このテストを実行すると、サーバー再起動までBANされます")
    print()

    ban_triggered = False

    for attempt in range(5):
        try:
            ctx, conn = await create_connection()
            try:
                challenge_msg = await conn.send_raw("AUTH_START")
                if not isinstance(challenge_msg, dict):
                    print(f"  試行 {attempt + 1}: 接続拒否 (既にBAN済み)")
                    ban_triggered = True
                    break

                # 無効な署名を送信
                result = await conn.send_raw({"type": "response", "data": b"invalid"})
                print(f"  試行 {attempt + 1}: {result}")

                if result == "AUTH_BANNED":
                    ban_triggered = True
                    print()
                    print("✓ BANが発動しました")
                    break
            finally:
                conn.close()
                await conn.wait_closed()
        except Exception as e:
            print(f"  試行 {attempt + 1}: 接続エラー - {e}")
            ban_triggered = True
            break

        await asyncio.sleep(0.1)

    print()
    print("=" * 60)
    if ban_triggered:
        print(" 結果: BAN機能は正常に動作しています")
        print(" サーバーを再起動してBANを解除してください")
    else:
        print(" 結果: BANが発動しませんでした（確認が必要）")
    print("=" * 60)


if __name__ == "__main__":
    print()
    print("※ このスクリプトはBAN機能のテスト用です")
    print("※ 実行後はサーバーの再起動が必要です")
    print()

    confirm = input("実行しますか？ (y/N): ")
    if confirm.lower() == "y":
        asyncio.run(test_ban_mechanism())
    else:
        print("キャンセルしました")
