import asyncio
import time
import pytest
import os
from nanasqlite_server.client import RemoteNanaSQLite

PORT = int(os.environ.get("NANASQLITE_TEST_PORT", 4433))

@pytest.mark.asyncio
async def test_concurrent_connections_performance():
    """多数の同時接続によるパフォーマンス測定"""
    num_clients = 10 # 減らして安定させる
    requests_per_client = 5

    async def run_client(id):
        client = RemoteNanaSQLite(host="127.0.0.1", port=PORT, verify_ssl=False, private_key_path="nana_private.pem")
        await client.connect()
        start = time.perf_counter()
        for i in range(requests_per_client):
            await client.set_item_async(f"perf_{id}_{i}", "data" * 100)
            await client.get_item_async(f"perf_{id}_{i}")
        elapsed = time.perf_counter() - start
        await client.close()
        return elapsed

    start_total = time.perf_counter()
    results = await asyncio.gather(*(run_client(i) for i in range(num_clients)))
    total_elapsed = time.perf_counter() - start_total

    avg_client_time = sum(results) / num_clients
    rps = (num_clients * requests_per_client * 2) / total_elapsed

    print(f"\n[Performance] {num_clients} clients, {num_clients*requests_per_client*2} total requests")
    print(f"[Performance] Total time: {total_elapsed:.3f}s")
    print(f"[Performance] Avg time per client: {avg_client_time:.3f}s")
    print(f"[Performance] Requests per second: {rps:.2f}")

    # 最低限の閾値
    assert rps > 1
