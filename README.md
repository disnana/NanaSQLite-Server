# NanaSQLite-Server

A secure, high-performance, QUIC-based RPC server for [NanaSQLite](https://github.com/NanaSQLite/nanasqlite).

## Features

- **QUIC Protocol**: Built on top of HTTP/3 technology for low latency and high reliability.
- **Ed25519 Passkey Authentication**: Secure challenge-response authentication using Ed25519 signatures.
- **Dynamic Protection**: Automatically adapts to NanaSQLite updates while strictly controlling method access via blacklists and class-member verification.
- **Cross-Platform**: Optimized for Windows, Linux, and macOS.
- **Non-Blocking IO**: All database operations run in a thread pool to keep the async event loop responsive.
- **Security Hardened**: Protected against fragmentation attacks, memory-exhaustion (DoS), and information leakage.

## Installation

```bash
pip install nanasqlite-server
```

## Quick Start

### 1. Generate Certificates and Keys

First, generate the TLS certificate for QUIC and the Ed25519 key pair for authentication:

```bash
# Generate TLS cert (cert.pem and key.pem)
nanasqlite-cert-gen

# Generate Ed25519 keys (nana_private.pem and nana_public.pub)
nanasqlite-key-gen
```

### 2. Start the Server

```bash
nanasqlite-server
```

The server will look for `cert.pem`, `key.pem`, and `nana_public.pub` in the current directory.

### 3. Connect from Client

```python
import asyncio
from nanasqlite_server.client import RemoteNanaSQLite

async def main():
    # client expects nana_private.pem in the current directory for authentication
    db = RemoteNanaSQLite(host="127.0.0.1", port=4433)
    await db.connect()

    # Use it like a normal NanaSQLite instance or a dict
    await db.set_item_async("hello", "world")
    print(await db.get_item_async("hello"))

    await db.close()

asyncio.run(main())
```

## Security Design

NanaSQLite-Server implements several layers of security:

1.  **Authentication**: Every connection must prove ownership of the private key corresponding to the server's registered public key.
2.  **Method Filtering**: Only safe, public methods defined in the `NanaSQLite` class and specific special methods (`__getitem__`, etc.) are allowed. Internal methods and raw SQL execution are blacklisted.
3.  **Resource Management**: Stream buffers are limited to 10MB, and connection failure tracking (BAN mechanism) is capped to prevent memory exhaustion.
4.  **Error Sanitization**: Internal server errors are masked to prevent leaking database structure or environment details.

## License

MIT License
