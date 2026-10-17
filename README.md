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

### リリース版をダウンロード

このリポジトリの GitHub の **Releases** から、同じタグのアーカイブと `SHA256SUMS` を同じフォルダーにダウンロードしてください。v0.1.1 のファイル名は次のとおりです（別のバージョンではタグ部分を置き換えます）。

| OS | CPU | アーカイブ |
| --- | --- | --- |
| macOS | Apple Silicon | `rapidxfer-v0.1.1-macos-aarch64.tar.gz` |
| macOS | Intel | `rapidxfer-v0.1.1-macos-x86_64.tar.gz` |
| Linux (GNU/glibc) | x86_64 | `rapidxfer-v0.1.1-linux-x86_64.tar.gz` |
| Linux (GNU/glibc) | ARM64 | `rapidxfer-v0.1.1-linux-aarch64.tar.gz` |
| Windows | x86_64 | `rapidxfer-v0.1.1-windows-x86_64.zip` |

各アーカイブには実行ファイルと `README.md` が入っています。展開前に、以下の手順で選択したアーカイブの SHA-256 が `SHA256SUMS` と一致することを確認してください。不一致ならインストールを中止してください。

### macOS

ダウンロード先でターミナルを開きます。Intel Mac では `archive` を表の Intel 用ファイル名に変更してください。

```sh
archive=rapidxfer-v0.1.1-macos-aarch64.tar.gz
grep -F "  $archive" SHA256SUMS | shasum -a 256 -c - || exit 1
mkdir -p rapidxfer-v0.1.1
tar -xzf "$archive" -C rapidxfer-v0.1.1
mkdir -p "$HOME/.local/bin"
cp rapidxfer-v0.1.1/rapidxfer "$HOME/.local/bin/"
chmod +x "$HOME/.local/bin/rapidxfer"
export PATH="$HOME/.local/bin:$PATH"
rapidxfer --help
```

`export PATH="$HOME/.local/bin:$PATH"` を `~/.zshrc` にも追加すると、次回以降のターミナルでも使えます。

### Linux

ダウンロード先でシェルを開きます。ARM64 では `archive` を表の ARM64 用ファイル名に変更してください。

```sh
archive=rapidxfer-v0.1.1-linux-x86_64.tar.gz
grep -F "  $archive" SHA256SUMS | sha256sum --check - || exit 1
mkdir -p rapidxfer-v0.1.1
tar -xzf "$archive" -C rapidxfer-v0.1.1
mkdir -p "$HOME/.local/bin"
cp rapidxfer-v0.1.1/rapidxfer "$HOME/.local/bin/"
chmod +x "$HOME/.local/bin/rapidxfer"
export PATH="$HOME/.local/bin:$PATH"
rapidxfer --help
```

`export PATH="$HOME/.local/bin:$PATH"` を `~/.bashrc` など利用中のシェルの設定ファイルにも追加してください。Linux 版は Ubuntu 24.04 上でビルドするため、同等以降の glibc 環境が必要です。古い環境や musl 環境ではソースからビルドしてください。

### Windows (PowerShell)

ダウンロード先で PowerShell を開きます。`Get-FileHash` の値を `SHA256SUMS` の該当行と比較し、一致した場合だけ展開します。

```powershell
$archive = 'rapidxfer-v0.1.1-windows-x86_64.zip'
$entry = @(Get-Content .\SHA256SUMS | Where-Object { $_ -match ('^[0-9a-fA-F]{64}  ' + [regex]::Escape($archive) + '$') })
if ($entry.Count -ne 1) { throw 'SHA256SUMS に該当する行がありません' }
$expected = ($entry[0] -split '  ', 2)[0]
$actual = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash
if ($actual -ne $expected) { throw 'SHA-256 が一致しません' }
Expand-Archive -LiteralPath $archive -DestinationPath .\rapidxfer-v0.1.1
$bin = Join-Path $env:LOCALAPPDATA 'rapidxfer\bin'
New-Item -ItemType Directory -Path $bin -Force | Out-Null
Copy-Item .\rapidxfer-v0.1.1\rapidxfer.exe $bin
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (($userPath -split ';') -notcontains $bin) {
    [Environment]::SetEnvironmentVariable('Path', "$bin;$userPath", 'User')
}
$env:Path = "$bin;$env:Path"
rapidxfer --help
```

Windows のパス区切りは `\`、PATH の区切りは `;` です。空白を含むパスは引用符で囲んでください。転送するファイル名には `CON`・`NUL` などの予約名、`<>:"/\|?*`、制御文字、末尾の空白やピリオドを使えません（他の OS でも互換性のため同じ制限があります）。

### ソースからビルド

Rust と Cargo を用意して、次を実行します。

```sh
git clone https://github.com/yourname/rapidxfer.git
cd rapidxfer
cargo build --locked --release
# 実行ファイル: target/release/rapidxfer
# Windows: target\release\rapidxfer.exe
```

実行ファイルを上記と同じ PATH 上のフォルダーに置いてください。GPG 署名の作成・検証を使う場合は、別途 `gpg` をインストールし、PATH に追加する必要があります。

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
* **暗号化**: 各チャンクごとに認証付き暗号化。改ざんを検知すると即座にエラー終了。
* **鍵導出**: Argon2id によりパスフレーズから 32byte 鍵を生成。16byte ランダム salt を使用。
* **ノンス管理**: 24byte の XChaCha20-Poly1305 Nonce を採用。先頭16byte乱数 + 末尾8byteカウンタ。
* **整合性確認**: SHA-256 により受信ファイルと送信時のハッシュを比較。
* **正当性検証**: 署名ファイル (.asc) を同梱し、受信側で GPG 検証。

## 依存関係
* Rust 1.75+ 推奨
* 外部コマンド: gpg

## 今後の拡張予定
* ヘッダの暗号化（メタデータ秘匿）
* 並列チャンク転送による更なる高速化
* 公開鍵暗号（age 互換）による鍵共有
* QUIC (TLS1.3) 対応
