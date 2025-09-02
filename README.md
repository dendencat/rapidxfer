rapidxfer
===

超高速・暗号化・改ざん防止機能付きのファイル転送ツール。
Rust 製であり、XChaCha20-Poly1305 (AEAD) による暗号化と改ざん検知、さらに GPG 署名による正当性検証に対応しています。

## 目次
- [特徴](#特徴)
- [インストール](#インストール)
- [使い方](#使い方)
    - [送信](#送信)
    - [受信](#受信)
- [オプション](#オプション)
- [セキュリティ設計](#セキュリティ設計)
- [依存関係](#依存関係)
- [今後の拡張予定](#今後の拡張予定)

## 特徴

**高速転送**: Tokio による非同期 I/O、大きめチャンク転送、Nagle 無効化。

**暗号化**: XChaCha20-Poly1305 による認証付き暗号。改ざんは即検知。

**パスフレーズからの鍵導出**: Argon2id で強固に派生。

**正当性検証**: GPG のデタッチ署名を同梱し、受信側で検証可能。

**クロスプラットフォーム**: Linux, macOS, Windows (WSL2 含む)。

## インストール
```
git clone https://github.com/yourname/rapidxfer.git
cd rapidxfer
cargo build --release
# 実行ファイル: target/release/rapidxfer
```

## 使い方
### 送信
```
rapidxfer send \
  --host 203.0.113.10:9000 \
  --file ./big.iso \
  --chunk-size 4MiB \
  --sign
```

`--sign` を付けると、送信ファイルに対して `gpg --detach-sign --armor` を実行し、署名を同梱します。

パスフレーズはプロンプトで安全に入力します（履歴に残りません）。

### 受信
```
rapidxfer recv \
  --listen 0.0.0.0:9000 \
  --output-dir ./inbox \
  --gpg-verify
```

`--gpg-verify` を付けると、同梱された署名を `gpg --verify` によって検証します。

事前に送信者の公開鍵を `gpg --import` しておく必要があります。

## オプション
|サブコマンド	| オプション	| 説明 |
| --- | --- | --- |
|send	| `--host <addr:port>`	|接続先ホスト|
|send	| `--file <path>`	|送信ファイル|
|send	| `--chunk-size <MiB>`	|チャンクサイズ (例: 1MiB, 4MiB, 16MiB)|
|send	| `--sign`	|GPG 署名を作成・同梱|
|recv	| `--listen <addr:port>`	|受信待ちアドレス|
|recv	| `--output-dir <dir>`	|保存先ディレクトリ|
|recv	| `--gpg-verify`	|GPG 検証を有効化|

## セキュリティ設計
**暗号化**: 各チャンクごとに認証付き暗号化。改ざんを検知すると即座にエラー終了。
**鍵導出**: Argon2id によりパスフレーズから 32byte 鍵を生成。16byte ランダム salt を使用。
**ノンス管理**: 24byte の XChaCha20-Poly1305 Nonce を採用。先頭16byte乱数 + 末尾8byteカウンタ。
**整合性確認**: SHA-256 により受信ファイルと送信時のハッシュを比較。
**正当性検証**: 署名ファイル (.asc) を同梱し、受信側で GPG 検証。

## 依存関係
* Rust 1.75+ 推奨
* 外部コマンド: gpg

## 今後の拡張予定
* ヘッダの暗号化（メタデータ秘匿）
* 並列チャンク転送による更なる高速化
* 公開鍵暗号（age 互換）による鍵共有
* QUIC (TLS1.3) 対応