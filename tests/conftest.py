"""
pytest 設定ファイル

テストディレクトリからプロジェクトルートのモジュールをインポートできるようにする
"""
import sys
import os

# プロジェクトルートをパスに追加
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# 作業ディレクトリもプロジェクトルートに変更 (private keyのパス解決のため)
os.chdir(project_root)
