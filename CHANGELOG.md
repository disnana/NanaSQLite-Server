# 更新履歴 (CHANGELOG)

## [1.3.4] - 2026-04-04

### アカウント名の厳格検証・認証バイパス修正・IP フィルタリング機能

#### セキュリティ修正 (Security Fixes)

- **アカウント名ヒントの厳格化** (`find_account_by_signature` strict mode):
  `accounts.py` の `find_account_by_signature()` が `account_name_hint` を指定されているにもかかわらず、
  指定アカウントの署名検証失敗後に全アカウントを線形探索していた問題を修正しました。

  **修正前の動作 (脆弱)**:
  ```
  攻撃者が account_name="admin" を指定し、"user1" の秘密鍵で署名した場合:
  1. "admin" の公開鍵で署名検証 → 失敗
  2. 線形探索へフォールバック → "user1" の公開鍵で署名検証 → 成功
  3. "user1" として認証されてしまう (account_name の指定が無意味)
  ```

  **修正後の動作 (安全)**:
  ```
  account_name_hint が指定された場合:
  - 指定されたアカウントが存在しない → 即座に認証失敗
  - 指定されたアカウントの署名検証が失敗 → 即座に認証失敗 (フォールバックなし)
  account_name_hint が未指定の場合は従来通り線形探索 (後方互換性を維持)
  ```

#### 新機能 (New Features)

- **IP アドレスフィルタリング** (`--allow-ips` / `--block-ips` オプション):
  サーバー起動時に接続元 IP アドレスを CIDR 範囲で許可 or ブロックするオプションを追加しました。
  **単一 IP アドレス**（`192.168.1.100`）と **IPv6**（`2001:db8::1`, `2001:db8::/32`, `::1`）にも対応しています。

  ```sh
  # 192.168.1.0/24 からの接続のみ許可
  nanasqlite-server --allow-ips "192.168.1.0/24"

  # 単一 IP アドレスを許可（範囲なし）
  nanasqlite-server --allow-ips "192.168.1.50"

  # 10.0.0.0/8 からの接続を拒否
  nanasqlite-server --block-ips "10.0.0.0/8"

  # IPv6 の特定アドレスを許可
  nanasqlite-server --allow-ips "2001:db8::1"

  # IPv6 CIDR 範囲を許可
  nanasqlite-server --allow-ips "2001:db8::/32"

  # 複数指定: カンマ区切り
  nanasqlite-server --allow-ips "192.168.1.0/24,10.0.0.1" --block-ips "192.168.1.100"
  ```

  **判定ルール** (優先順位順):
  1. IP が取得できない場合 (`unknown`) はフィルタをスキップして認証に委ねる
  2. `--block-ips` に含まれる IP は拒否
  3. `--allow-ips` が設定されている場合、リストに含まれない IP は拒否
  4. その他は許可

  詳細: `docs/ip-filter.md`

- **アカウントごとの IP 制限** (`allowed_ips` / `blocked_ips` アカウントフィールド):
  `accounts.json` の各アカウントに個別の IP 制限を設定できます。サーバーレベルの IP フィルタリングとは独立して動作し、認証成功後にチェックされます。

  ```json
  {
    "db_dir": ".",
    "accounts": [
      {
        "name": "admin",
        "public_key": "ssh-ed25519 AAAA...",
        "allowed_ips": ["192.168.1.0/24"]
      },
      {
        "name": "readonly_user",
        "public_key": "ssh-ed25519 AAAA...",
        "blocked_ips": ["10.0.0.0/8"]
      }
    ]
  }
  ```

  アカウントの IP ルールに違反した場合は `AUTH_FAILED` が返されます。

#### PoC (概念実証)

- `poc_vulnerabilities/poc_account_name_bypass.py` を追加:
  - 修正前の脆弱な動作を再現し、修正後に認証失敗となることを検証するスクリプト。

#### テスト (Tests)

- `tests/test_v134_auth_account_name.py` を追加 (計10件):
  - ユニットテスト (`TestFindAccountBySignatureStrictMode`, 6件):
    - 誤ったアカウント名ヒント + 有効な署名 → 認証失敗
    - 正しいアカウント名ヒント + 有効な署名 → 認証成功
    - 存在しないアカウント名ヒント → 認証失敗 (フォールバックなし)
    - ヒントなし → 線形探索で認証成功 (後方互換性)
    - ヒントアカウント存在・署名不一致 → 他アカウントへフォールバックしない
    - 正しいヒント + 無効な署名バイト列 → 認証失敗
  - 統合テスト (4件):
    - 正しいアカウント名で実サーバーへの認証成功
    - 誤ったアカウント名で実サーバーへの認証失敗
    - 存在しないアカウント名で実サーバーへの認証失敗
    - account_name 未指定で実サーバーへの認証成功 (後方互換性)

- `tests/test_ip_filter.py` を追加 (計50件):
  - ユニットテスト `TestParseIpNetworks` (13件): 空リスト、単一 IP、CIDR、複数エントリ、不正エントリなど
  - ユニットテスト `TestIsIpAllowed` (18件): フィルタなし、allow のみ、block のみ、allow+block、unknown IP など
  - ユニットテスト `TestAccountIpFilter` (17件): アカウントごとの IP 制限 (blocked/allowed CIDR、カンマ区切り文字列など)
  - 統合テスト (2件): `--allow-ips` / `--block-ips` オプションを実際のサーバーで検証

---

## [1.3.3] - 2026-04-04

### RBAC 強化・エラー情報の隠蔽・CI 修正

#### 新機能 (New Features)

- **一括 Read-Only 設定** (`read_only` フラグ):
  `accounts.json` のアカウント設定に `"read_only": true` を追加するだけで、データを変更・削除する全メソッド (`__setitem__`, `__delitem__`, `set`, `delete`, `batch_update`, `batch_update_partial`, `batch_delete`, `clear`, `upsert`, `import_from_dict_list`, `flush`, `retry_dlq`, `clear_dlq`) を一括で禁止できます。
  `WRITE_METHODS` 定数として `server.py` に定義しており、`PermissionError` を返します。
  例:
  ```json
  {
    "name": "viewer",
    "public_key": "ssh-ed25519 ...",
    "read_only": true
  }
  ```

- **DB 名に紐づくテーブル名の動的制限** (拡張 `allowed_dbs`):
  `allowed_dbs` に辞書形式を指定することで、DB ごとにアクセス可能なテーブルを制限できます。
  後方互換として、従来通りのリスト形式 (`["db.sqlite"]`) も引き続きサポートします（内部で自動変換）。
  例:
  ```json
  {
    "name": "limited_user",
    "public_key": "ssh-ed25519 ...",
    "allowed_dbs": {
      "logs.sqlite": null,
      "data.sqlite": ["public_info", "stats"]
    }
  }
  ```

#### セキュリティ修正 (Security Fixes)

- **エラー情報の隠蔽強化**: `handle_request` のエラーハンドリングを改修。
  - クライアント起因の正当なエラー (`ValueError`, `PermissionError`, `RuntimeError`, `KeyError`, `NanaSQLiteError`) はそのままクライアントに返します。
  - サーバー内部のエラー (`AttributeError`, `TypeError`) は汎用メッセージ (`"Internal Server Error"`) に置き換え、詳細はサーバーログにのみ記録します。これにより、不正なメソッド呼び出しによる内部実装の漏洩を防ぎます。

#### バグ修正 (Bug Fixes)

- **CI 修正**: テスト実行コマンドに `--cov` / `-n auto` フラグを使用しているにもかかわらず `pytest-cov` / `pytest-xdist` がインストールされていなかった問題を修正。`pyproject.toml` の `[dev]` 依存に `pytest-cov` と `pytest-xdist` を追加しました。

#### テスト (Tests)

- `tests/test_v133_features.py` を追加:
  - `Account` / `AccountManager` の `read_only` / `allowed_dbs` 変換のユニットテスト (14 件)。
  - `WRITE_METHODS` 定数の検証テスト (2 件)。
  - `read_only` アカウントが書き込みを拒否し読み取りは許可する統合テスト (2 件)。
  - `allowed_dbs` 辞書形式によるテーブル制限の統合テスト (2 件)。
  - `allowed_dbs` リスト形式の後方互換性テスト (1 件)。

---

## [1.3.2] - 2026-04-04
### 耐量子暗号 (PQC) 認証失敗の修正
耐量子暗号 (PQC) 認証におけるロジックの修正
前バージョンの修正において残存していた認証エラーの根本原因を特定し、修正を完了しました。開発環境で動作確認を行い、現在は正常に認証が完了することを確認済みです。

## [1.3.1] - 2026-04-03

### Windows での耐量子暗号 (PQC) 認証失敗の修正

#### バグ修正 (Bug Fixes)
- **Windows での PQC 認証失敗の修正** ([#issue]): Windows（および一部の環境）では、サーバーの `auth_ok` レスポンス（ML-KEM-768 公開鍵 ~1200 バイトを含む）が QUIC の複数の `StreamDataReceived` イベントに断片化されて届く場合がある。クライアントは各イベントを即座に処理しようとしていたため、最初のフラグメントで `decode_message()` が `None` を返し、`None` がレスポンスキューに積まれて `Authentication failed: None` エラーが発生していた。サーバー側にはすでに同等のバッファリング実装（`stream_buffers`）があったが、クライアントには不足していた。
  - `NanaRpcClientProtocol` に `_stream_buffers` ディクショナリを追加。
  - `quic_event_received` がストリームデータを `end_stream=True` まで蓄積し、完全なメッセージをまとめてデコード/復号するよう修正。サーバーの実装と対称。

#### セキュリティ修正 (Security Fixes)
- **クライアント側ストリームバッファのサイズ制限追加**: 新しいバッファリングにサイズ上限（`MAX_STREAM_BUFFER_SIZE = 10 MB`）を設けた。上限を超えるデータを受信した場合はバッファを破棄してエラーをキューに入れ、接続を閉じる。これにより、異常なサーバーや通信障害によってクライアントのメモリが無制限に消費されるのを防止する（サーバー側のDoS対策と同等）。

#### テスト (Tests)
- `tests/test_pqc_security.py` に `TestClientStreamBuffering` クラス（8件）を追加:
  - `end_stream=True` まで処理されないことの検証。
  - Windows での ML-KEM-768 断片化シナリオの回帰テスト。
  - 通常（非断片化）レスポンスが引き続き正しく処理されることの確認。
  - 複数ストリームの独立したバッファ管理の検証。
  - `end_stream=True` 後のバッファ解放の確認（メモリリーク防止）。
  - 断片化された暗号化レスポンスの正常復号の確認。
  - バッファ上限超過時のエラー応答・接続切断・バッファクリアの確認。

---

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
