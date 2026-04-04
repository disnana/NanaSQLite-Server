"""
NanaSQLite-Server v1.3.4 テスト

IP アドレスフィルタリング (allow/block リスト) の検証

- parse_ip_networks(): 文字列リストを Network オブジェクトに変換
- is_ip_allowed(): allow/block リストに基づくアクセス判定
- 統合テスト: --allow-ips / --block-ips オプションで実際にサーバーが接続を拒否するか
"""

import asyncio
import json
import os
import signal
import ssl
import subprocess
import sys
import time

import ipaddress
import pytest

from aioquic.asyncio import connect, QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from nanasqlite_server import protocol as proto
from nanasqlite_server.cert_gen import generate_certificate
from nanasqlite_server.key_gen import generate_keys
import nanasqlite_server.server as _srv_module


# ---------------------------------------------------------------------------
# ユニットテスト: parse_ip_networks
# ---------------------------------------------------------------------------


class TestParseIpNetworks:
    """parse_ip_networks のユニットテスト"""

    def _fn(self, entries):
        return _srv_module.parse_ip_networks(entries)

    def test_empty_list(self):
        assert self._fn([]) == []

    def test_single_ipv4_address(self):
        result = self._fn(["192.168.1.1"])
        assert len(result) == 1
        assert ipaddress.ip_address("192.168.1.1") in result[0]

    def test_cidr_range(self):
        result = self._fn(["192.168.1.0/24"])
        assert len(result) == 1
        assert ipaddress.ip_address("192.168.1.100") in result[0]
        assert ipaddress.ip_address("192.168.2.1") not in result[0]

    def test_multiple_entries(self):
        result = self._fn(["10.0.0.1", "172.16.0.0/12"])
        assert len(result) == 2

    def test_invalid_entry_is_skipped(self):
        # 不正なエントリはスキップし、有効なものは通す
        result = self._fn(["not-an-ip", "127.0.0.1"])
        assert len(result) == 1
        assert ipaddress.ip_address("127.0.0.1") in result[0]

    def test_empty_string_is_skipped(self):
        result = self._fn(["", "  ", "10.0.0.1"])
        assert len(result) == 1

    def test_ipv4_with_host_bits(self):
        # strict=False で host bits 付きの CIDR も受け付ける
        result = self._fn(["192.168.1.100/24"])
        assert len(result) == 1
        assert ipaddress.ip_address("192.168.1.50") in result[0]

    def test_loopback_address(self):
        result = self._fn(["127.0.0.1"])
        assert len(result) == 1
        assert ipaddress.ip_address("127.0.0.1") in result[0]
        assert ipaddress.ip_address("127.0.0.2") not in result[0]

    def test_loopback_cidr(self):
        result = self._fn(["127.0.0.0/8"])
        assert len(result) == 1
        assert ipaddress.ip_address("127.0.0.1") in result[0]
        assert ipaddress.ip_address("127.1.2.3") in result[0]


# ---------------------------------------------------------------------------
# ユニットテスト: is_ip_allowed
# ---------------------------------------------------------------------------


class TestIsIpAllowed:
    """is_ip_allowed のユニットテスト"""

    def _call(self, ip_str, allow_list=None, block_list=None):
        # グローバルをテスト用に差し替える
        orig_allow = _srv_module._ip_allow_list
        orig_block = _srv_module._ip_block_list
        try:
            _srv_module._ip_allow_list = _srv_module.parse_ip_networks(allow_list or [])
            _srv_module._ip_block_list = _srv_module.parse_ip_networks(block_list or [])
            return _srv_module.is_ip_allowed(ip_str)
        finally:
            _srv_module._ip_allow_list = orig_allow
            _srv_module._ip_block_list = orig_block

    # --- フィルタなし (デフォルト) ---
    def test_no_filter_allows_all(self):
        assert self._call("192.168.1.1") is True

    def test_no_filter_allows_any_ip(self):
        assert self._call("10.0.0.1") is True

    # --- allow リストのみ ---
    def test_allow_list_permits_matching_ip(self):
        assert self._call("192.168.1.1", allow_list=["192.168.1.0/24"]) is True

    def test_allow_list_blocks_non_matching_ip(self):
        assert self._call("10.0.0.1", allow_list=["192.168.1.0/24"]) is False

    def test_allow_list_exact_ip(self):
        assert self._call("127.0.0.1", allow_list=["127.0.0.1"]) is True
        assert self._call("127.0.0.2", allow_list=["127.0.0.1"]) is False

    def test_allow_list_multiple_entries(self):
        assert self._call("10.0.0.5", allow_list=["10.0.0.0/8", "192.168.1.0/24"]) is True
        assert self._call("192.168.1.10", allow_list=["10.0.0.0/8", "192.168.1.0/24"]) is True
        assert self._call("172.16.0.1", allow_list=["10.0.0.0/8", "192.168.1.0/24"]) is False

    # --- block リストのみ ---
    def test_block_list_blocks_matching_ip(self):
        assert self._call("192.168.1.5", block_list=["192.168.1.0/24"]) is False

    def test_block_list_allows_non_matching_ip(self):
        assert self._call("10.0.0.1", block_list=["192.168.1.0/24"]) is True

    def test_block_list_exact_ip(self):
        assert self._call("10.0.0.1", block_list=["10.0.0.1"]) is False
        assert self._call("10.0.0.2", block_list=["10.0.0.1"]) is True

    # --- allow + block の組み合わせ ---
    def test_block_takes_precedence_over_allow(self):
        # allow に含まれていても block に含まれていれば拒否
        assert self._call(
            "192.168.1.5",
            allow_list=["192.168.1.0/24"],
            block_list=["192.168.1.5"],
        ) is False

    def test_allow_without_block_excludes_others(self):
        assert self._call(
            "192.168.2.1",
            allow_list=["192.168.1.0/24"],
            block_list=[],
        ) is False

    # --- 特殊ケース ---
    def test_unknown_ip_no_filter(self):
        # IP不明かつフィルタなし → 許可
        assert self._call("unknown") is True

    def test_unknown_ip_with_allow_list(self):
        # IP不明かつ allow リストあり → 許可 (QUIC/UDP では peername が取得できないケースがある)
        # IP フィルタをスキップして認証に委ねる
        assert self._call("unknown", allow_list=["127.0.0.1"]) is True

    def test_unknown_ip_with_block_list(self):
        # IP不明かつ block リストあり → 許可 (フィルタをスキップ、認証に委ねる)
        assert self._call("unknown", block_list=["192.168.1.0/24"]) is True


# ---------------------------------------------------------------------------
# 統合テスト: サーバーへの実接続で IP フィルタリングを確認
# ---------------------------------------------------------------------------


def _make_ed25519_pub(priv_key) -> str:
    return (
        priv_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH,
        )
        .decode()
    )


@pytest.fixture(scope="module")
def ip_filter_server_allow(tmp_path_factory):
    """--allow-ips 127.0.0.1 のサーバー (127.0.0.1 のみ許可)"""
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = _make_ed25519_pub(priv)
    tmp_path = tmp_path_factory.mktemp("ip_allow")
    orig_cwd = os.getcwd()
    os.chdir(tmp_path)
    proc = None
    log_file = None
    try:
        generate_certificate()
        generate_keys()
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()

        config_path = tmp_path / "accounts.json"
        with open(config_path, "w") as f:
            json.dump(
                {"db_dir": str(tmp_path), "accounts": [{"name": "u", "public_key": pub}]}, f
            )

        env = os.environ.copy()
        env["PYTHONPATH"] = orig_cwd + os.pathsep + os.path.join(orig_cwd, "src")
        env["NANASQLITE_FORCE_POLLING"] = "1"
        env["NANASQLITE_DISABLE_BAN"] = "1"

        cmd = [
            sys.executable, "-m", "nanasqlite_server.server",
            "--port", str(port),
            "--accounts", str(config_path),
            "--db", str(tmp_path / "test.sqlite"),
            "--allow-ips", "127.0.0.1",
        ]
        log_file = open(tmp_path / "server.log", "w", encoding="utf-8")
        kwargs = {}
        if sys.platform == "win32":
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        proc = subprocess.Popen(cmd, env=env, stdout=log_file, stderr=subprocess.STDOUT, **kwargs)

        # 起動待ち
        quic_config = QuicConfiguration(is_client=True, verify_mode=ssl.CERT_NONE)
        loop = asyncio.new_event_loop()
        server_ready = False
        start = time.time()
        try:
            while time.time() - start < 60.0:
                if proc.poll() is not None:
                    break
                async def _chk():
                    try:
                        async with connect("127.0.0.1", port, configuration=quic_config):
                            return True
                    except Exception:
                        return False
                if loop.run_until_complete(_chk()):
                    server_ready = True
                    break
                time.sleep(0.5)
        finally:
            loop.close()

        if not server_ready:
            raise RuntimeError("ip_filter_server_allow failed to start")

        yield port, priv
    finally:
        if proc and proc.poll() is None:
            try:
                if sys.platform == "win32":
                    os.kill(proc.pid, signal.CTRL_BREAK_EVENT)
                else:
                    proc.send_signal(signal.SIGINT)
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
            except Exception:
                if proc:
                    proc.kill()
        if log_file:
            log_file.close()
        os.chdir(orig_cwd)


@pytest.fixture(scope="module")
def ip_filter_server_block(tmp_path_factory):
    """--block-ips 192.0.2.0/24 のサーバー (テスト用アドレス範囲のみブロック)"""
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = _make_ed25519_pub(priv)
    tmp_path = tmp_path_factory.mktemp("ip_block")
    orig_cwd = os.getcwd()
    os.chdir(tmp_path)
    proc = None
    log_file = None
    try:
        generate_certificate()
        generate_keys()
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()

        config_path = tmp_path / "accounts.json"
        with open(config_path, "w") as f:
            json.dump(
                {"db_dir": str(tmp_path), "accounts": [{"name": "u", "public_key": pub}]}, f
            )

        env = os.environ.copy()
        env["PYTHONPATH"] = orig_cwd + os.pathsep + os.path.join(orig_cwd, "src")
        env["NANASQLITE_FORCE_POLLING"] = "1"
        env["NANASQLITE_DISABLE_BAN"] = "1"

        # 127.0.0.1 は含まないアドレスをブロック（127.0.0.1 からの接続は通る）
        cmd = [
            sys.executable, "-m", "nanasqlite_server.server",
            "--port", str(port),
            "--accounts", str(config_path),
            "--db", str(tmp_path / "test.sqlite"),
            "--block-ips", "192.0.2.0/24",
        ]
        log_file = open(tmp_path / "server.log", "w", encoding="utf-8")
        kwargs = {}
        if sys.platform == "win32":
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        proc = subprocess.Popen(cmd, env=env, stdout=log_file, stderr=subprocess.STDOUT, **kwargs)

        quic_config = QuicConfiguration(is_client=True, verify_mode=ssl.CERT_NONE)
        loop = asyncio.new_event_loop()
        server_ready = False
        start = time.time()
        try:
            while time.time() - start < 60.0:
                if proc.poll() is not None:
                    break
                async def _chk():
                    try:
                        async with connect("127.0.0.1", port, configuration=quic_config):
                            return True
                    except Exception:
                        return False
                if loop.run_until_complete(_chk()):
                    server_ready = True
                    break
                time.sleep(0.5)
        finally:
            loop.close()

        if not server_ready:
            raise RuntimeError("ip_filter_server_block failed to start")

        yield port, priv
    finally:
        if proc and proc.poll() is None:
            try:
                if sys.platform == "win32":
                    os.kill(proc.pid, signal.CTRL_BREAK_EVENT)
                else:
                    proc.send_signal(signal.SIGINT)
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
            except Exception:
                if proc:
                    proc.kill()
        if log_file:
            log_file.close()
        os.chdir(orig_cwd)


@pytest.mark.asyncio
async def test_allow_list_permits_local_connection(ip_filter_server_allow):
    """--allow-ips 127.0.0.1 → 127.0.0.1 からの接続は AUTH_START まで到達できる"""
    port, priv = ip_filter_server_allow
    config = QuicConfiguration(is_client=True, verify_mode=ssl.CERT_NONE)

    class MinimalClient(QuicConnectionProtocol):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            self._q = asyncio.Queue()

        def quic_event_received(self, event):
            if isinstance(event, StreamDataReceived):
                msg, _ = proto.decode_message(event.data)
                self._q.put_nowait(msg)

        async def send(self, data):
            sid = self._quic.get_next_available_stream_id()
            self._quic.send_stream_data(sid, proto.encode_message(data), end_stream=True)
            self.transmit()
            return await asyncio.wait_for(self._q.get(), timeout=5.0)

    async with connect("127.0.0.1", port, configuration=config, create_protocol=MinimalClient) as client:
        resp = await client.send("AUTH_START")
        assert isinstance(resp, dict)
        assert resp.get("type") == "challenge"


@pytest.mark.asyncio
async def test_block_list_does_not_affect_non_blocked_ip(ip_filter_server_block):
    """--block-ips 192.0.2.0/24 → 127.0.0.1 からは接続・認証できる"""
    port, priv = ip_filter_server_block
    config = QuicConfiguration(is_client=True, verify_mode=ssl.CERT_NONE)

    class MinimalClient(QuicConnectionProtocol):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            self._q = asyncio.Queue()

        def quic_event_received(self, event):
            if isinstance(event, StreamDataReceived):
                msg, _ = proto.decode_message(event.data)
                self._q.put_nowait(msg)

        async def send(self, data):
            sid = self._quic.get_next_available_stream_id()
            self._quic.send_stream_data(sid, proto.encode_message(data), end_stream=True)
            self.transmit()
            return await asyncio.wait_for(self._q.get(), timeout=5.0)

    async with connect("127.0.0.1", port, configuration=config, create_protocol=MinimalClient) as client:
        resp = await client.send("AUTH_START")
        assert isinstance(resp, dict)
        assert resp.get("type") == "challenge"

        challenge = resp["data"]
        sig = priv.sign(challenge)
        result = await client.send({"type": "response", "data": sig})
        assert result == "AUTH_OK"

# ---------------------------------------------------------------------------
# ユニットテスト: Account.is_ip_allowed (アカウントレベルの IP フィルター)
# ---------------------------------------------------------------------------


class TestAccountIpFilter:
    """Account.is_ip_allowed のユニットテスト"""

    def _make_account(self, allowed_ips=None, blocked_ips=None):
        from nanasqlite_server.accounts import Account
        from cryptography.hazmat.primitives.asymmetric import ed25519
        priv = ed25519.Ed25519PrivateKey.generate()
        pub = (
            priv.public_key()
            .public_bytes(
                encoding=serialization.Encoding.OpenSSH,
                format=serialization.PublicFormat.OpenSSH,
            )
            .decode()
        )
        return Account("test", pub, allowed_ips=allowed_ips, blocked_ips=blocked_ips)

    # --- フィルターなし ---

    def test_no_filter_allows_all(self):
        acc = self._make_account()
        assert acc.is_ip_allowed("192.168.1.1") is True

    def test_no_filter_allows_unknown(self):
        acc = self._make_account()
        assert acc.is_ip_allowed("unknown") is True

    # --- blocked_ips ---

    def test_blocked_ip_rejects(self):
        acc = self._make_account(blocked_ips=["10.0.0.1"])
        assert acc.is_ip_allowed("10.0.0.1") is False

    def test_blocked_cidr_rejects(self):
        acc = self._make_account(blocked_ips=["10.0.0.0/8"])
        assert acc.is_ip_allowed("10.1.2.3") is False

    def test_blocked_cidr_allows_outside(self):
        acc = self._make_account(blocked_ips=["10.0.0.0/8"])
        assert acc.is_ip_allowed("192.168.1.1") is True

    def test_blocked_unknown_ip_still_allowed(self):
        acc = self._make_account(blocked_ips=["10.0.0.1"])
        assert acc.is_ip_allowed("unknown") is True

    # --- allowed_ips ---

    def test_allowed_ip_permits(self):
        acc = self._make_account(allowed_ips=["192.168.1.0/24"])
        assert acc.is_ip_allowed("192.168.1.50") is True

    def test_allowed_ip_rejects_outside(self):
        acc = self._make_account(allowed_ips=["192.168.1.0/24"])
        assert acc.is_ip_allowed("10.0.0.1") is False

    def test_allowed_unknown_ip_still_allowed(self):
        acc = self._make_account(allowed_ips=["192.168.1.0/24"])
        assert acc.is_ip_allowed("unknown") is True

    # --- blocked 優先 ---

    def test_block_takes_precedence_over_allow(self):
        acc = self._make_account(
            allowed_ips=["192.168.1.0/24"], blocked_ips=["192.168.1.100"]
        )
        assert acc.is_ip_allowed("192.168.1.100") is False

    def test_allow_not_in_block_permits(self):
        acc = self._make_account(
            allowed_ips=["192.168.1.0/24"], blocked_ips=["192.168.1.100"]
        )
        assert acc.is_ip_allowed("192.168.1.50") is True

    # --- カンマ区切り文字列形式 ---

    def test_comma_separated_allowed_ips(self):
        acc = self._make_account(allowed_ips="10.0.0.1,192.168.1.1")
        assert acc.is_ip_allowed("10.0.0.1") is True
        assert acc.is_ip_allowed("192.168.1.1") is True
        assert acc.is_ip_allowed("172.16.0.1") is False

    def test_comma_separated_blocked_ips(self):
        acc = self._make_account(blocked_ips="10.0.0.1,10.0.0.2")
        assert acc.is_ip_allowed("10.0.0.1") is False
        assert acc.is_ip_allowed("10.0.0.2") is False
        assert acc.is_ip_allowed("10.0.0.3") is True
