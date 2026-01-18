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
    # 必要な鍵/証明書の準備
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
    
    # PYTHONPATHを明示的に設定 (カレントプロセスのsys.pathを使用)
    python_path = os.pathsep.join(sys.path)
    env["PYTHONPATH"] = python_path
    
    cmd = [sys.executable, "-m", "nanasqlite_server.server", "--port", str(port)]
    proc = subprocess.Popen(cmd, env=env)  # noqa: S603

    # 起動待機 (MacOS等での遅延を考慮して少し長めに)
    time.sleep(5.0)

    try:
        yield
    finally:
        # 優雅に終了を試みる
        if proc.poll() is None:
            try:
                proc.send_signal(signal.SIGINT)
                try:
                    proc.wait(timeout=5)
                except Exception:
                    proc.terminate()
            except Exception:
                proc.kill()
