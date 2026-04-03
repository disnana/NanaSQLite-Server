"""
データベースディレクトリ自動作成のテスト

accounts.json に指定された db_dir が存在しない場合、
AccountManager が自動で作成することを検証します。
"""

import json
import os


class TestDbDirAutoCreation:
    """db_dir の自動作成テスト"""

    def test_existing_db_dir_is_used_as_is(self, tmp_path):
        """存在する db_dir はそのまま使用されることを確認"""
        from nanasqlite_server.accounts import AccountManager

        db_dir = tmp_path / "existing_dbs"
        db_dir.mkdir()
        config_path = tmp_path / "accounts.json"
        with open(config_path, "w") as f:
            json.dump({"db_dir": str(db_dir), "accounts": []}, f)

        manager = AccountManager(str(config_path))
        assert manager.db_dir == str(db_dir)
        assert os.path.isdir(db_dir), "既存ディレクトリは変更されるべきではない"

    def test_nonexistent_db_dir_is_created(self, tmp_path):
        """存在しない db_dir が自動作成されることを確認"""
        from nanasqlite_server.accounts import AccountManager

        db_dir = tmp_path / "new_dbs"
        assert not db_dir.exists(), "テスト前にディレクトリが存在しないことを確認"

        config_path = tmp_path / "accounts.json"
        with open(config_path, "w") as f:
            json.dump({"db_dir": str(db_dir), "accounts": []}, f)

        manager = AccountManager(str(config_path))
        assert manager.db_dir == str(db_dir)
        assert os.path.isdir(db_dir), "db_dir が自動作成されるべき"

    def test_nested_nonexistent_db_dir_is_created(self, tmp_path):
        """ネストした存在しない db_dir が自動作成されることを確認"""
        from nanasqlite_server.accounts import AccountManager

        db_dir = tmp_path / "level1" / "level2" / "dbs"
        assert not db_dir.exists()

        config_path = tmp_path / "accounts.json"
        with open(config_path, "w") as f:
            json.dump({"db_dir": str(db_dir), "accounts": []}, f)

        AccountManager(str(config_path))
        assert os.path.isdir(db_dir), "ネストした db_dir が自動作成されるべき"

    def test_default_db_dir_dot_is_not_created(self, tmp_path, monkeypatch):
        """db_dir が指定されない場合はデフォルト '.' が使われることを確認"""
        from nanasqlite_server.accounts import AccountManager

        monkeypatch.chdir(tmp_path)
        config_path = tmp_path / "accounts.json"
        with open(config_path, "w") as f:
            json.dump({"accounts": []}, f)

        manager = AccountManager(str(config_path))
        assert manager.db_dir == ".", "デフォルトは '.' であるべき"

    def test_reload_with_new_nonexistent_db_dir(self, tmp_path):
        """設定ファイルの再読み込み時に新しい db_dir が存在しなければ作成されることを確認"""
        from nanasqlite_server.accounts import AccountManager

        db_dir1 = tmp_path / "dbs_v1"
        db_dir1.mkdir()
        config_path = tmp_path / "accounts.json"
        with open(config_path, "w") as f:
            json.dump({"db_dir": str(db_dir1), "accounts": []}, f)

        manager = AccountManager(str(config_path))
        assert manager.db_dir == str(db_dir1)

        # 設定を更新して、存在しない db_dir に変更
        db_dir2 = tmp_path / "dbs_v2"
        assert not db_dir2.exists()
        with open(config_path, "w") as f:
            json.dump({"db_dir": str(db_dir2), "accounts": []}, f)

        # 手動で再読み込み
        manager._do_load()
        assert manager.db_dir == str(db_dir2)
        assert os.path.isdir(db_dir2), "再読み込み時の新 db_dir も自動作成されるべき"
