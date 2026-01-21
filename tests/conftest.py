"""
pytest 設定ファイル

テストディレクトリからプロジェクトルート/ソースをインポートできるようにし、
テスト実行中にサーバーをバックグラウンドで起動する。
"""
import sys
import os
import time
import subprocess
import signal
import pytest
from filelock import FileLock


# プロジェクトルートをパスに追加
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# src とパッケージディレクトリもパスに追加（tests の "import protocol" 対応）
src_dir = os.path.join(project_root, "src")
pkg_dir = os.path.join(src_dir, "nanasqlite_server")
for p in (src_dir, pkg_dir):
    if p not in sys.path:
        sys.path.insert(0, p)

# 作業ディレクトリもプロジェクトルートに変更 (private keyのパス解決のため)
os.chdir(project_root)


@pytest.fixture(scope="session", autouse=True)
def ensure_test_server():
    """テスト用QUICサーバーをバックグラウンドで起動する。

    - 必要な証明書/鍵がない場合は自動生成
    - セッション終了時に安全に停止
    """
    # 必要な鍵/証明書の準備 (FileLockで排他制御)
    with FileLock("keys.lock"):
        if not os.path.exists("cert.pem") or not os.path.exists("key.pem"):
            from nanasqlite_server.cert_gen import generate_certificate
            generate_certificate()
        if not os.path.exists("nana_public.pub") or not os.path.exists("nana_private.pem"):
            from nanasqlite_server.key_gen import generate_keys
            generate_keys()

    # ポート番号の決定 (xdistワーカーIDに基づく)
    worker_id = os.environ.get("PYTEST_XDIST_WORKER", "gw0")
    try:
        worker_num = int(worker_id.replace("gw", ""))
    except ValueError:
        worker_num = 0
    
    port = 4433 + worker_num
    
    # テストコード側にポート番号を伝える環境変数を設定
    os.environ["NANASQLITE_TEST_PORT"] = str(port)

    # サーバープロセスを起動
    env = os.environ.copy()
    env["NANASQLITE_DISABLE_BAN"] = "1"
    env["NANASQLITE_TEST_MODE"] = "1"
    env["PYTHONUNBUFFERED"] = "1"
    env["NANASQLITE_FORCE_POLLING"] = "1"
    
    # PYTHONPATHを明示的に設定 (カレントプロセスのsys.pathを使用)
    python_path = os.pathsep.join(sys.path)
    env["PYTHONPATH"] = python_path
    
    db_path = f"server_db_{worker_id}.sqlite"
    cmd = [sys.executable, "-m", "nanasqlite_server.server", "--port", str(port), "--db", db_path]

    # パイプ詰まりによるハングアップを防ぐため、出力をファイルにリダイレクト
    log_file = open(f"server_log_{worker_id}.log", "w", encoding="utf-8")

    # Windows では新しいプロセスグループを作成してシグナルを送りやすくする
    kwargs = {}
    if sys.platform == "win32":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP

    proc = subprocess.Popen(cmd, env=env, stdout=log_file, stderr=subprocess.STDOUT, text=True, **kwargs)  # noqa: S603

    # アクティブな起動確認 (ヘルスチェック)
    # 実際にQUIC接続を試みて、サーバーが応答するか確認する
    async def wait_for_server():
        from aioquic.asyncio import connect
        from aioquic.quic.configuration import QuicConfiguration
        import ssl
        
        config = QuicConfiguration(is_client=True, verify_mode=ssl.CERT_NONE)
        start_wait = time.time()
        
        while time.time() - start_wait < 60.0:  # 最大60秒待機 (CI環境向けに延長)
            if proc.poll() is not None:
                return False  # プロセス終了
                
            try:
                # 接続試行
                async with connect("127.0.0.1", port, configuration=config):
                    return True
            except Exception:
                await asyncio.sleep(1.0)
        return False

    # 起動を待機
    import asyncio
    try:
        # 新しいイベントループを作成して実行 (既存のループとの干渉を避ける)
        loop = asyncio.new_event_loop()
        success = loop.run_until_complete(wait_for_server())
        loop.close()

        if not success:
            if proc.poll() is not None:
                log_file.close()
                with open(f"server_log_{worker_id}.log", "r", encoding="utf-8") as f:
                    log_content = f.read()
                raise RuntimeError(f"Test server process died. Code: {proc.returncode}\nLog:\n{log_content}")
            else:
                proc.kill()
                raise RuntimeError("Timed out waiting for server to start accepting connections.")
    except Exception as e:
        proc.kill()
        raise e

    try:
        yield
    finally:
        # 優雅に終了を試みる
        if proc.poll() is None:
            try:
                if sys.platform == "win32":
                    # Windows では CTRL_BREAK_EVENT を送る
                    os.kill(proc.pid, signal.CTRL_BREAK_EVENT)
                else:
                    proc.send_signal(signal.SIGINT)

                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    # 終わらなければ強制終了
                    proc.kill()
                    proc.wait()
            except Exception:
                proc.kill()
                proc.wait()

        # プロセス終了後にログファイルを閉じる
        log_file.close()
