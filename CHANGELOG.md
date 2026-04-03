# 更新履歴 (CHANGELOG)

## [1.3.0] - 2026-04-03

### 耐量子暗号 (PQC) 認証・セッション暗号化の追加

#### 新機能 (New Features)
- **PQC 認証**: `--pqc-auth` フラグで CRYSTALS-Dilithium / ML-DSA などの耐量子デジタル署名による認証を有効化。
  - `key_gen.py` で PQC 鍵ペア（秘密鍵 JSON + 公開鍵 JSON）を生成。
  - サーバーは Ed25519 公開鍵と OQS 公開鍵の両方を同一アカウントで受け付ける。
- **PQC KEM セッション鍵交換・暗号化**: `--pqc-kem <ALGORITHM>` フラグで認証後に KEM（Key Encapsulation Mechanism）を実施し、導出した AES-256-GCM セッション鍵で以降のすべての RPC 通信を暗号化。
  - サポートアルゴリズム例: `Kyber512`, `Kyber768`, `Kyber1024`, `ML-KEM-768` など liboqs がサポートするすべての KEM。
  - プロトコルフロー: 認証完了 → サーバーが KEM 公開鍵を送信 → クライアントがカプセル化して `kem_response` を返送 → 双方で同一セッション鍵を確立 → `KEM_OK` の後すべての通信が AES-256-GCM で暗号化。
  - クライアント側でも `--pqc-kem` を使う場合は `liboqs-python` が必要。
- **セッション鍵導出**: HKDF-SHA256 (`protocol.derive_session_key()`) で KEM 共有秘密から 256 ビット AES セッション鍵を導出。
- **AES-256-GCM メッセージ暗号化**: `protocol.encrypt_message()` / `protocol.decrypt_message()` で全 RPC メッセージを透過的に暗号化・復号。

#### セキュリティ修正 (Security Fixes)
- **サイレント復号ドロップの修正**: `pqc_session_key` が有効な状態で復号が失敗した場合、以前はリクエストを無音でドロップしていた。現在はクライアントに `{"status": "error", "message": "Invalid encrypted request"}` を返送し、接続を閉じる（改ざんの可能性をすぐに通知）。
- **KEM バイパス攻撃の防止**: KEM デカプセル化が失敗した場合（不正な暗号文を意図的に送ることで `_kem_instance` を `None` にして KEM 必須チェックを迂回できた問題）、接続を即座に切断するよう修正。
- **クライアント側 None レスポンスの修正**: `session_key` が有効な状態で復号失敗時に `None` をレスポンスキューに入れていた問題を修正。現在は明確なエラー dict をキューに入れ、接続を閉じる（`call_rpc` が `RuntimeError` を受け取れるようになった）。
- **KEM インスタンスのリソースリーク防止**: `KeyEncapsulation()` 生成・`generate_keypair()` 呼び出しを `try/finally` で囲み、例外発生時もネイティブリソースが確実に解放されるよう修正。
- **liboqs なし時のフェイルファスト**: サーバーが KEM を提示したがクライアントに `liboqs-python` がない場合、続行せず即座に `RuntimeError` を発生させ接続を閉じる。

#### テスト (Tests)
- `tests/test_protocol_crypto.py`: HKDF セッション鍵導出・AES-256-GCM 暗号化復号のユニットテスト 16 件（`liboqs-python` 不要）。
- `tests/test_pqc.py`: PQC 鍵生成・アカウント検証・KEM 鍵交換の統合テスト（`liboqs-python` がある場合に実行）。
- `tests/test_pqc_security.py`: セキュリティ修正のリグレッションテスト 13 件（`liboqs-python` 不要）:
  - サーバー PQC 復号失敗時にエラー送信・接続切断を検証。
  - KEM デカプセル化失敗によるバイパス攻撃が不可能なことを検証。
  - クライアント側復号失敗時に `None` でなくエラー dict がキューに入ることを検証。

#### ドキュメント (Documentation)
- `docs/pqc.md`: KEM アルゴリズム対応表、プロトコルフロー図、セキュリティ注記、日英両対応。
  - クライアント側も `--pqc-kem` 利用時は `liboqs-python` 必須と明記（従来の誤記を修正）。

#### コード品質 (Code Quality)
- ruff: 全チェック通過。
- CodeQL: アラート 0 件。
- `except (ImportError, SystemExit)` で `import oqs` の失敗を正しく捕捉するよう全ファイル修正。

---

## [1.2.2] - 2026-04-01

### nanasqlite v1.5.0dev1 Asyncモード対応

#### 新機能 (New Features)
- **`--async-mode` フラグ**: `AsyncNanaSQLite` を使用した非ブロッキングなデータベース操作を有効化。
  - nanasqlite v1.5.0dev1 以降で利用可能（ASYNC-01: AsyncNanaSQLite への V2 非同期メソッド追加、QUAL-04: イベントループ外インスタンス化の修正）。
  - `AsyncNanaSQLite` はネイティブな非同期メソッドを持つため、`ThreadPoolExecutor` での実行を回避できる。
  - 特殊メソッド (`__getitem__`, `__setitem__`, `__delitem__`, `__contains__`, `__len__`) を対応する非同期メソッド (`aget`, `aset`, `adelete`, `acontains`, `alen`) に自動マッピング。
  - `batch_get` など `AsyncNanaSQLite` に同名メソッドが存在しない場合は `a` プレフィックス版 (`abatch_get`) へ自動フォールバック。
  - 既存の `FORBIDDEN_METHODS` によるセキュリティ制限は Asyncモードでも完全に適用される。
- **シャットダウン時の `AsyncNanaSQLite` クリーンアップ**: サーバー終了時に全 `AsyncNanaSQLite` インスタンスを適切に `await close()` で閉じるようにした。


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
