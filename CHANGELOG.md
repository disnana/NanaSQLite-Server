# 更新履歴 (CHANGELOG)

## [1.2.1] - 2026-04-01

### nanasqlite v1.5.0dev2 対応 & バグ修正

#### セキュリティ修正 (Security Fixes)
- **`add_hook` のブロック**: nanasqlite v1.5.0dev2 で追加された `add_hook()` を `FORBIDDEN_METHODS` に追加。任意の Python オブジェクト（フック）をサーバー側 DB インスタンスに注入できるため、RPC 経由では安全に検証できず、サーバー上で任意コードが実行される可能性がある。

#### 新機能 (New Features)
- **v1.5.0dev2 新メソッドのサポート**:
  - `clear_dlq()`: v2 DLQ のクリア（安全なv2管理メソッドとして許可）。
  - `get_v2_metrics()`: v2エンジンのメトリクス取得（安全な読み取り専用メソッドとして許可）。
- **`--enable-metrics` フラグ**: `--v2` と組み合わせてv2メトリクス収集を有効化（`get_v2_metrics()` が実際のデータを返すようになる）。
- **後方互換**: v1.5.0dev2 では `NanaSQLite` コンストラクタのv2パラメータが `**kwargs` 経由でも受け付けられるため、v1.4.0 との完全な互換性を維持。

#### バグ修正 (Bug Fixes)
- **ruff F841**: `tests/test_v14_compatibility.py` の `test_upsert` における未使用変数 `result` を削除。



### nanasqlite v1.4.0 対応 & v2エンジンサポート

#### セキュリティ修正 (Security Fixes)
- **新規危険メソッドのブロック**: nanasqlite v1.4.0 で追加された以下のメソッドを `FORBIDDEN_METHODS` に追加し、リモートから悪用されるのを防止:
  - `backup` / `restore`: クライアントから任意のファイルパスを指定できるため、**ディレクトリトラバーサル・任意ファイル読み書きの脆弱性**となる。
  - `fetch_all` / `fetch_one`: 内部で `execute()` を呼び出す生SQL実行メソッド。既存の `execute` 禁止と同様の理由で禁止。
  - `create_table` / `alter_table_add_column` / `drop_table`: 任意DDL操作によるスキーマ破壊を防止。
  - `drop_index` / `create_index`: 破壊的なインデックス操作・DoSを防止。

#### 新機能 (New Features)
- **v2エンジンサポート**: nanasqlite v1.4.0 の新アーキテクチャ（バックグラウンド非同期書き込み）に対応。
  - `--v2` フラグでv2エンジンを有効化。
  - `--flush-mode` (immediate/count/time/manual): フラッシュ戦略の設定。
  - `--flush-interval`: timeモード時のフラッシュ間隔（秒）。
  - `--flush-count`: countモード時の書き込み閾値。
  - `--v2-chunk-size`: フラッシュ時のトランザクション最大件数。
  - v2モードでは `flush()`, `get_dlq()`, `retry_dlq()` をRPC経由で呼び出し可能。
- **v1.4.0 新メソッドの全面サポート**: `batch_get`, `batch_delete`, `batch_update`, `batch_update_partial`, `upsert`, `count`, `exists`, `get_db_size`, `query_with_pagination`, `table_exists`, `export_table_to_dict`, `import_from_dict_list`, `to_dict`, `get_fresh`, `in_transaction`, `get_last_insert_rowid`, `is_cached`, `list_indexes`, `get_table_schema`, `flush`, `get_dlq`, `retry_dlq` がRPC経由で利用可能。
- **`__main__` ブロックの整理**: `if __name__ == "__main__"` ブロックを `main_sync()` に統一し、二重実装を解消。

## [1.1.1] - 2026-01-27

### 改善
- **デフォルトDBフォールバック**: クライアントがDB名を指定せず、かつアカウントに特定のDB制限がない場合、サーバー起動時に `--db` で指定されたデータベースを自動的に使用するように改善。
- **パフォーマンス向上**: メッセージのシリアライズに `ormsgpack` を採用し、通信のオーバーヘッドを削減。
- **Python 3.13 対応**: スレッドおよび非同期タスクの参照管理を強化し、Python 3.13+ における GC（ガベージコレクション）によるタスクの早期終了を防止。
- **IP解決の信頼性向上**: クライアント IP 取得ロジックを強化し、異なるOSやネットワーク環境間での信頼性を向上。
- **サンプルの安定性向上**: `example/accounts.json` に推奨される `allowed_dbs` 設定を追加し、サンプルクライアントの動作を安定化。

### ドキュメント
- **README 更新**: クライアントの使用例を最新の非同期 `RemoteNanaSQLite` 仕様に更新し、マルチDB環境での挙動に関する説明を補足。
- **並行処理の仕様**: 同一DBへの同時アクセス時の排他制御（RLock + WAL）に関する設計上の挙動について文書化。



## [1.1.0] - 2025-01-24

### 追加
- **RBAC (Role-Based Access Control) システム**: `accounts.json` による複数ユーザー管理とメソッドレベルの権限制限を実装。
- **リアルタイム設定反映**: `watchfiles` を利用し、サーバー再起動なしでアカウント権限の変更を即座に反映。
- **認証プロトコルの最適化**: 認証時にアカウント名のヒントを送信する機能を追加し、署名検証のCPU負荷を大幅に削減（CPU DoS対策）。

### セキュリティ改善
- **Anti-DoS ガードレールの強化**: 未認証時の同時ストリーム数を最大50、合計接続バッファを最大50MBに制限。
- **即時BANチェック**: リクエストごとにBAN状態を再確認し、不正な通信を即座に遮断。

## [1.0.0] - 2025-01-17

### 追加
- 初回リリース
- 許可・禁止メソッドのカスタマイズ機能の追加（プログラム起動時）
- QUIC プロトコル (aioquic) による RPC サーバーの実装
- Ed25519 パスキー認証の実装
- `nanasqlite-server`, `nanasqlite-cert-gen`, `nanasqlite-key-gen` コンソールコマンドの追加
- マルチプラットフォーム (Windows, Linux, macOS) への対応
- 英語・日本語のバイリンガルドキュメント

### セキュリティ改善
- **動的メソッド保護**: `dir(NanaSQLite)` を使用したメソッド検証と `FORBIDDEN_METHODS` ブラックリストによる二重の保護。
- **フラグメンテーション対策**: QUIC ストリームのバッファリング処理の実装。
- **DoS 対策**: ストリームバッファサイズ制限 (10MB) および BAN リストのメモリ制限の実装。
- **非ブロッキング化**: 全ての DB 操作を `ThreadPoolExecutor` で実行するように変更。
- **エラー情報の秘匿**: サーバー内部例外の隠蔽と、安全な例外 (`NanaSQLiteError` 等) のみのクライアントへの返却。
