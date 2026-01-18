import ormsgpack
import struct

def encode_message(data):
    """データをシリアライズし、サイズヘッダーを付けて返す"""
    payload = ormsgpack.packb(data)
    header = struct.pack("!I", len(payload))
    return header + payload

def decode_message(data):
    """シリアライズされたデータを復元する"""
    if len(data) < 4:
        return None, data
    
    length = struct.unpack("!I", data[:4])[0]
    if len(data) < 4 + length:
        return None, data
    
    payload = data[4:4+length]
    rest = data[4+length:]
    return ormsgpack.unpackb(payload), rest
