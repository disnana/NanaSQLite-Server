import asyncio
import logging
import os
from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived
from nanasqlite import NanaSQLite
import protocol

# 認証トークン（本番環境では環境変数などから取得）
AUTH_TOKEN = "nana-secret-key-2026"

class NanaRpcProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.db = None
        self.authenticated = False

    def quic_event_received(self, event):
        if isinstance(event, StreamDataReceived):
            asyncio.create_task(self.handle_request(event.stream_id, event.data))

    async def handle_request(self, stream_id, data):
        try:
            message, _ = protocol.decode_message(data)
            if message is None:
                return

            # 初回メッセージは認証トークンである必要がある
            if not self.authenticated:
                if message == AUTH_TOKEN:
                    self.authenticated = True
                    self.db = NanaSQLite("server_db.sqlite")
                    response = "AUTH_OK"
                else:
                    response = "AUTH_FAILED"
                self._send_response(stream_id, response)
                return

            # RPC実行
            method_name = message.get("method")
            args = message.get("args", [])
            kwargs = message.get("kwargs", {})

            if hasattr(self.db, method_name):
                method = getattr(self.db, method_name)
                # 非同期メソッドか同期メソッドか判定して実行
                if asyncio.iscoroutinefunction(method):
                    result = await method(*args, **kwargs)
                else:
                    result = method(*args, **kwargs)
                response = {"status": "success", "result": result}
            else:
                response = {"status": "error", "message": f"Method {method_name} not found"}

        except Exception as e:
            response = {"status": "error", "message": str(e)}

        self._send_response(stream_id, response)

    def _send_response(self, stream_id, data):
        payload = protocol.encode_message(data)
        self._quic.send_stream_data(stream_id, payload, end_stream=True)
        self.transmit()

async def main():
    configuration = QuicConfiguration(is_client=False)
    # 1.2.0+ では load_cert_chain を使用する
    configuration.load_cert_chain("cert.pem", "key.pem")

    print("NanaSQLite QUIC Server starting on localhost:4433")
    await serve(
        "localhost",
        4433,
        configuration=configuration,
        create_protocol=NanaRpcProtocol,
    )
    await asyncio.Future()  # run forever

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
