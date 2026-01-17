import asyncio
import logging
import os
import secrets
import time
from collections import defaultdict
from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from nanasqlite import NanaSQLite
import protocol

# 設定
PUBLIC_KEY_PATH = "nana_public.pub"
MAX_FAILED_ATTEMPTS = 3
BAN_DURATION = 900  # 15分 (秒)

# BAN・失敗回数管理
failed_attempts = defaultdict(int)  # {ip: count}
ban_list = {}  # {ip: unban_time}

def is_banned(ip):
    """IPがBANされているか確認"""
    if ip in ban_list:
        if time.time() < ban_list[ip]:
            return True
        else:
            del ban_list[ip]
            failed_attempts[ip] = 0
    return False

class NanaRpcProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.db = None
        self.authenticated = False
        self.challenge = None
        self.client_ip = None
        
        # 公開鍵のロード
        try:
            with open(PUBLIC_KEY_PATH, "rb") as f:
                self.public_key = serialization.load_ssh_public_key(f.read())
        except Exception as e:
            print(f"Error loading public key: {e}")
            self.public_key = None

    def connection_made(self, transport):
        super().connection_made(transport)
        # aioquicではtransport.get_extra_info("peername")がNoneを返すことがあるため
        # _quicオブジェクトからリモートアドレスを取得
        try:
            addr = self._quic._peer_cid.host_addr if hasattr(self._quic, '_peer_cid') else None
            if not addr:
                # フォールバック: transportから取得を試みる
                peername = transport.get_extra_info("peername")
                addr = peername[0] if peername else "unknown"
        except Exception:
            addr = "unknown"
        self.client_ip = addr
        print(f"New connection from: {self.client_ip}")


    def quic_event_received(self, event):
        if is_banned(self.client_ip):
            print(f"Blocked connection from banned IP: {self.client_ip}")
            self.close()
            return

        if isinstance(event, StreamDataReceived):
            asyncio.create_task(self.handle_request(event.stream_id, event.data))

    async def handle_request(self, stream_id, data):
        try:
            message, _ = protocol.decode_message(data)
            if message is None:
                return

            # 1. チャレンジ・レスポンス認証 (パスキー方式)
            if not self.authenticated:
                # 認証フェーズ1: クライアントからの認証開始要求
                if message == "AUTH_START":
                    self.challenge = secrets.token_bytes(32)
                    self._send_response(stream_id, {"type": "challenge", "data": self.challenge})
                    return
                
                # 認証フェーズ2: 署名の検証
                if isinstance(message, dict) and message.get("type") == "response":
                    signature = message.get("data")
                    try:
                        self.public_key.verify(signature, self.challenge)
                        self.authenticated = True
                        self.db = NanaSQLite("server_db.sqlite")
                        failed_attempts[self.client_ip] = 0
                        response = "AUTH_OK"
                        print(f"Authentication successful for {self.client_ip}")
                    except Exception:
                        failed_attempts[self.client_ip] += 1
                        print(f"Auth failed for {self.client_ip}. Attempt: {failed_attempts[self.client_ip]}")
                        
                        if failed_attempts[self.client_ip] >= MAX_FAILED_ATTEMPTS:
                            ban_list[self.client_ip] = time.time() + BAN_DURATION
                            print(f"IP {self.client_ip} has been BANNED for {BAN_DURATION}s")
                            response = "AUTH_BANNED"
                        else:
                            response = "AUTH_FAILED"
                    
                    self._send_response(stream_id, response)
                    return

            # 2. RPC実行 (認証済みの場合)
            if self.authenticated:
                result = await self.execute_rpc(message)
                self._send_response(stream_id, result)
            else:
                self._send_response(stream_id, {"status": "error", "message": "Unauthorized"})

        except Exception as e:
            self._send_response(stream_id, {"status": "error", "message": str(e)})

    async def execute_rpc(self, message):
        method_name = message.get("method")
        args = message.get("args", [])
        kwargs = message.get("kwargs", {})

        if hasattr(self.db, method_name):
            method = getattr(self.db, method_name)
            if asyncio.iscoroutinefunction(method):
                result = await method(*args, **kwargs)
            else:
                result = method(*args, **kwargs)
            return {"status": "success", "result": result}
        else:
            return {"status": "error", "message": f"Method {method_name} not found"}

    def _send_response(self, stream_id, data):
        payload = protocol.encode_message(data)
        self._quic.send_stream_data(stream_id, payload, end_stream=True)
        self.transmit()

async def main():
    configuration = QuicConfiguration(is_client=False)
    configuration.load_cert_chain("cert.pem", "key.pem")

    print(f"NanaSQLite QUIC Server starting on 127.0.0.1:4433")
    print(f"Auth mode: Ed25519 Passkey (Challenge-Response)")

    await serve(
        "127.0.0.1",
        4433,
        configuration=configuration,
        create_protocol=NanaRpcProtocol,
    )
    await asyncio.Future()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
