import msgpack
import struct

def encode_message(data):
    """データをシリアライズし、サイズヘッダーを付けて返す"""
    payload = msgpack.packb(data, use_bin_type=True)
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
    # raw=False: strはstrとして、bytesはbytesとして復元
    return msgpack.unpackb(payload, raw=False), rest
