use anyhow::{anyhow, bail, Context, Result};
use argon2::Argon2;
use bincode::Options;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use clap::{Parser, Subcommand};
use rand::{rngs::OsRng, RngCore};
use rpassword::prompt_password;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter},
    net::{TcpListener, TcpStream},
};

const TAG_SIZE: usize = 16; // Poly1305 tag
const SALT_LEN: usize = 16; // Argon2id salt
const NONCE_LEN: usize = 24; // XChaCha20 nonce
const HDR_MAGIC: &[u8; 8] = b"RXF-HDR2";

// Limits (receiver side)
const MAX_HDR_LEN: usize = 4 * 1024;
const MIN_CHUNK: usize = 4 * 1024;
const MAX_CHUNK: usize = 16 * 1024 * 1024;
const MAX_META_LEN: usize = 1024 * 1024; // filename + signature
const MAX_NAME_LEN: usize = 255;
const READ_TIMEOUT: Duration = Duration::from_secs(60);

const FLAG_FINAL: u8 = 1;

#[derive(Parser, Debug)]
#[command(name = "rapidxfer", version, about = "Fast encrypted file xfer with AEAD + GPG verify")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Receive files (server)
    Recv {
        #[arg(long, default_value = "127.0.0.1:9000")]
        listen: String,
        #[arg(long, default_value = ".")]
        output_dir: PathBuf,
        /// Verify GPG signature if present
        #[arg(long)]
        gpg_verify: bool,
        /// Deprecated: visible in process list / shell history. Prompt is used by default.
        #[arg(long, hide = true)]
        passphrase: Option<String>,
    },
    /// Send a file (client)
    Send {
        #[arg(long)]
        host: String,
        #[arg(long)]
        file: PathBuf,
        /// Chunk size like 1MiB, 4MiB (default 4MiB, 4KiB..16MiB)
        #[arg(long, default_value = "4MiB")]
        chunk_size: String,
        /// Create detached signature via gpg and embed (.asc)
        #[arg(long)]
        sign: bool,
        /// Deprecated: visible in process list / shell history. Prompt is used by default.
        #[arg(long, hide = true)]
        passphrase: Option<String>,
    },
}

/// Sent in clear; authenticated via AAD of every record.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
struct PublicHeader {
    chunk_size: u32,
    salt: [u8; SALT_LEN],
    base_nonce: [u8; NONCE_LEN],
}

/// Sent encrypted as record 0.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
struct Meta {
    filename: String,
    filesize: u64,
    sha256: [u8; 32],
    gpg_sig_armored: Option<Vec<u8>>,
}

fn bopts(limit: u64) -> impl bincode::Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_little_endian()
        .reject_trailing_bytes()
        .with_limit(limit)
}

fn parse_chunk_size(s: &str) -> Result<usize> {
    let s = s.trim().to_ascii_lowercase();
    let digits = s.chars().take_while(|c| c.is_ascii_digit()).count();
    let (num, suffix) = s.split_at(digits);
    let n: usize = num.parse().context("invalid chunk size number")?;
    let mult: usize = match suffix.trim() {
        "" | "b" => 1,
        "k" | "kb" | "kib" => 1024,
        "m" | "mb" | "mib" => 1024 * 1024,
        "g" | "gb" | "gib" => 1024 * 1024 * 1024,
        _ => bail!("invalid chunk size suffix"),
    };
    let v = n.checked_mul(mult).ok_or_else(|| anyhow!("chunk size overflow"))?;
    if !(MIN_CHUNK..=MAX_CHUNK).contains(&v) {
        bail!("chunk size must be between 4KiB and 16MiB");
    }
    Ok(v)
}

/// Accept only a single filename that is safe on every supported OS.
fn validate_filename(name: &str) -> Result<&str> {
    if name.is_empty() {
        bail!("invalid filename {name:?}: invalid filename length");
    }
    if name.len() > MAX_NAME_LEN {
        let preview: String = name.chars().flat_map(char::escape_default).take(64).collect();
        bail!("rejected \"{preview}…\" ({} bytes): name too long (max {MAX_NAME_LEN})", name.len());
    }
    if name.chars().any(|c| c.is_control()) {
        bail!("invalid filename {name:?}: control characters are not allowed");
    }
    if name.contains(['/', '\\']) || matches!(name, "." | "..") {
        bail!("invalid filename {name:?}: filename must be a single path element");
    }
    if let Some(c) = name.chars().find(|c| matches!(c, ':' | '<' | '>' | '"' | '|' | '?' | '*')) {
        bail!("invalid filename {name:?}: invalid character {c:?}");
    }
    if name.ends_with(['.', ' ']) {
        bail!("invalid filename {name:?}: trailing space or '.' is not allowed");
    }
    let stem = name.split('.').next().unwrap_or_default();
    let reserved = ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"]
        .iter()
        .any(|reserved| stem.eq_ignore_ascii_case(reserved))
        || (stem.len() == 4
            && (stem.as_bytes()[..3].eq_ignore_ascii_case(b"COM") || stem.as_bytes()[..3].eq_ignore_ascii_case(b"LPT"))
            && matches!(stem.as_bytes()[3], b'1'..=b'9'));
    if reserved {
        bail!("invalid filename {name:?}: reserved filename");
    }
    if name.starts_with('.') {
        bail!("invalid filename {name:?}: hidden filenames are not accepted");
    }
    Ok(name)
}

fn sha256_file(path: &Path) -> Result<[u8; 32]> {
    let mut f = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().into())
}

fn derive_key(passphrase: &str, salt: &[u8; SALT_LEN]) -> Result<Key> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow!("argon2 error: {e}"))?;
    Ok(*Key::from_slice(&key))
}

fn nonce_with_counter(base: &[u8; NONCE_LEN], counter: u64) -> XNonce {
    let mut n = *base;
    n[16..24].copy_from_slice(&counter.to_le_bytes());
    *XNonce::from_slice(&n)
}

fn record_aad(hdr_hash: &[u8; 32], counter: u64, plain_len: u32, flags: u8) -> [u8; 45] {
    let mut a = [0u8; 45];
    a[..32].copy_from_slice(hdr_hash);
    a[32..40].copy_from_slice(&counter.to_le_bytes());
    a[40..44].copy_from_slice(&plain_len.to_le_bytes());
    a[44] = flags;
    a
}

async fn timed<T, F: std::future::Future<Output = std::io::Result<T>>>(f: F) -> Result<T> {
    Ok(tokio::time::timeout(READ_TIMEOUT, f)
        .await
        .map_err(|_| anyhow!("read timed out"))??)
}

struct Sealer {
    cipher: XChaCha20Poly1305,
    base_nonce: [u8; NONCE_LEN],
    hdr_hash: [u8; 32],
    counter: u64,
}

impl Sealer {
    async fn write_record<W: AsyncWrite + Unpin>(&mut self, w: &mut W, pt: &[u8], flags: u8) -> Result<()> {
        let len = u32::try_from(pt.len())?;
        let aad = record_aad(&self.hdr_hash, self.counter, len, flags);
        let ct = self
            .cipher
            .encrypt(&nonce_with_counter(&self.base_nonce, self.counter), Payload { msg: pt, aad: &aad })
            .map_err(|_| anyhow!("encrypt failed"))?;
        w.write_u32_le(len).await?;
        w.write_u8(flags).await?;
        w.write_all(&ct).await?;
        self.counter = self.counter.checked_add(1).ok_or_else(|| anyhow!("nonce counter overflow"))?;
        Ok(())
    }

    /// Returns (plaintext, flags). `max_len` bounds the declared length before allocation.
    async fn read_record<R: AsyncRead + Unpin>(&mut self, r: &mut R, max_len: usize, buf: &mut Vec<u8>) -> Result<(Vec<u8>, u8)> {
        let len = timed(r.read_u32_le()).await?;
        let flags = timed(r.read_u8()).await?;
        if len as usize > max_len {
            bail!("record too large");
        }
        if flags & !FLAG_FINAL != 0 {
            bail!("unknown record flags");
        }
        let ct_len = len as usize + TAG_SIZE;
        if buf.len() < ct_len {
            buf.resize(ct_len, 0);
        }
        timed(r.read_exact(&mut buf[..ct_len])).await?;
        let aad = record_aad(&self.hdr_hash, self.counter, len, flags);
        let pt = self
            .cipher
            .decrypt(&nonce_with_counter(&self.base_nonce, self.counter), Payload { msg: &buf[..ct_len], aad: &aad })
            .map_err(|_| anyhow!("authentication failed (wrong passphrase or tampered data)"))?;
        self.counter = self.counter.checked_add(1).ok_or_else(|| anyhow!("nonce counter overflow"))?;
        Ok((pt, flags))
    }
}

async fn send_stream<W: AsyncWrite + Unpin>(w: W, file: &Path, chunk_size: usize, sign: bool, passphrase: &str) -> Result<u64> {
    let mut writer = BufWriter::new(w);

    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let mut base_nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut base_nonce);
    let key = derive_key(passphrase, &salt)?;

    let filename = file
        .file_name()
        .ok_or_else(|| anyhow!("invalid filename"))?
        .to_string_lossy()
        .to_string();
    validate_filename(&filename).context("this filename would be rejected by the receiver")?;
    let filesize = fs::metadata(file)?.len();
    let sha256 = sha256_file(file)?;
    let gpg_sig_armored = if sign { Some(gpg_sign(file)?) } else { None };

    let hdr = PublicHeader { chunk_size: chunk_size as u32, salt, base_nonce };
    let hdr_bytes = bopts(MAX_HDR_LEN as u64).serialize(&hdr)?;
    let hdr_hash: [u8; 32] = Sha256::digest(&hdr_bytes).into();
    writer.write_all(HDR_MAGIC).await?;
    writer.write_u32_le(hdr_bytes.len() as u32).await?;
    writer.write_all(&hdr_bytes).await?;

    let mut sealer = Sealer { cipher: XChaCha20Poly1305::new(&key), base_nonce, hdr_hash, counter: 0 };

    let meta = Meta { filename, filesize, sha256, gpg_sig_armored };
    let meta_bytes = bopts(MAX_META_LEN as u64).serialize(&meta).context("metadata too large")?;
    sealer.write_record(&mut writer, &meta_bytes, 0).await?;

    let mut f = tokio::fs::File::open(file).await?;
    let mut buf = vec![0u8; chunk_size];
    let mut sent: u64 = 0;
    loop {
        // fill the chunk fully so that a short read only happens at EOF
        let mut n = 0;
        while n < chunk_size {
            let r = f.read(&mut buf[n..]).await?;
            if r == 0 {
                break;
            }
            n += r;
        }
        sent += n as u64;
        let last = n < chunk_size || sent >= filesize;
        sealer.write_record(&mut writer, &buf[..n], if last { FLAG_FINAL } else { 0 }).await?;
        if last {
            break;
        }
    }
    if sent != filesize {
        bail!("file changed while sending");
    }
    writer.flush().await?;
    writer.shutdown().await.ok();
    Ok(sent)
}

fn gpg_sign(file: &Path) -> Result<Vec<u8>> {
    let out = Command::new("gpg")
        .args(["--batch", "--yes", "--armor", "--detach-sign", "--output", "-"])
        .arg(file)
        .output()
        .context("gpg sign failed to spawn")?;
    if !out.status.success() {
        bail!("gpg sign failed (is your key configured?)");
    }
    Ok(out.stdout)
}

/// Removes the temp file on drop unless disarmed.
struct TempGuard(Option<PathBuf>);
impl Drop for TempGuard {
    fn drop(&mut self) {
        if let Some(p) = self.0.take() {
            let _ = fs::remove_file(p);
        }
    }
}

fn temp_path(outdir: &Path) -> PathBuf {
    let mut r = [0u8; 8];
    OsRng.fill_bytes(&mut r);
    let hex: String = r.iter().map(|b| format!("{b:02x}")).collect();
    outdir.join(format!(".rapidxfer-{hex}.part"))
}

/// Publish without following symlinks or overwriting: hard_link fails if target exists.
fn publish(tmp: &Path, target: &Path) -> Result<()> {
    fs::hard_link(tmp, target).with_context(|| format!("refusing to overwrite existing {}", target.display()))?;
    let _ = fs::remove_file(tmp);
    Ok(())
}

#[derive(Debug)]
struct Received {
    path: PathBuf,
    bytes: u64,
    gpg_verified: bool,
}

async fn recv_stream<R: AsyncRead + Unpin>(r: R, outdir: &Path, gpg_verify: bool, passphrase: &str) -> Result<Received> {
    let mut reader = BufReader::new(r);
    let mut magic = [0u8; 8];
    timed(reader.read_exact(&mut magic)).await?;
    if &magic == b"RXF-HDR1" {
        bail!("相手の rapidxfer が旧版（RXF-HDR1）の可能性があります。両側を更新してください");
    }
    if &magic != HDR_MAGIC {
        bail!("peer is not rapidxfer v2 (wrong port or incompatible version)");
    }
    let hdr_len = timed(reader.read_u32_le()).await? as usize;
    if hdr_len > MAX_HDR_LEN {
        bail!("header too large");
    }
    let mut hdr_bytes = vec![0u8; hdr_len];
    timed(reader.read_exact(&mut hdr_bytes)).await?;
    let hdr: PublicHeader = bopts(MAX_HDR_LEN as u64).deserialize(&hdr_bytes).context("malformed header")?;
    let chunk_size = hdr.chunk_size as usize;
    if !(MIN_CHUNK..=MAX_CHUNK).contains(&chunk_size) {
        bail!("chunk size out of range");
    }
    let hdr_hash: [u8; 32] = Sha256::digest(&hdr_bytes).into();

    let key = derive_key(passphrase, &hdr.salt)?;
    let mut sealer = Sealer { cipher: XChaCha20Poly1305::new(&key), base_nonce: hdr.base_nonce, hdr_hash, counter: 0 };
    let mut buf = Vec::new();

    // Record 0: authenticated metadata. Nothing touches disk before this succeeds.
    let (meta_bytes, flags) = sealer.read_record(&mut reader, MAX_META_LEN, &mut buf).await?;
    if flags != 0 {
        bail!("unexpected final flag on metadata");
    }
    let meta: Meta = bopts(MAX_META_LEN as u64).deserialize(&meta_bytes).context("malformed metadata")?;
    let name = validate_filename(&meta.filename)?.to_string();

    fs::create_dir_all(outdir)?;
    let target = outdir.join(&name);
    if fs::symlink_metadata(&target).is_ok() {
        bail!("refusing to overwrite existing {}", target.display());
    }
    let tmp = temp_path(outdir);
    let mut guard = TempGuard(Some(tmp.clone()));
    let mut out = tokio::fs::OpenOptions::new().write(true).create_new(true).open(&tmp).await?;

    let mut written: u64 = 0;
    let mut hasher = Sha256::new();
    loop {
        let (pt, flags) = sealer.read_record(&mut reader, chunk_size, &mut buf).await?;
        written = written.checked_add(pt.len() as u64).ok_or_else(|| anyhow!("size overflow"))?;
        if written > meta.filesize {
            bail!("more data than announced");
        }
        hasher.update(&pt);
        out.write_all(&pt).await?;
        if flags & FLAG_FINAL != 0 {
            break;
        }
        if pt.len() != chunk_size {
            bail!("short non-final chunk");
        }
    }
    if written != meta.filesize {
        bail!("transfer truncated");
    }
    out.flush().await?;
    out.sync_all().await?;
    drop(out);

    let calc: [u8; 32] = hasher.finalize().into();
    if calc != meta.sha256 {
        bail!("sha256 mismatch (corruption detected)");
    }

    let mut asc_guard = TempGuard(None);
    let mut gpg_verified = false;
    let asc_target = outdir.join(format!("{name}.asc"));
    if gpg_verify {
        if let Some(sig) = meta.gpg_sig_armored.as_ref() {
            let asc_tmp = temp_path(outdir);
            asc_guard.0 = Some(asc_tmp.clone());
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&asc_tmp)
                .and_then(|mut f| std::io::Write::write_all(&mut f, sig))?;
            let status = Command::new("gpg")
                .arg("--verify")
                .arg(&asc_tmp)
                .arg(&tmp)
                .status()
                .context("failed to spawn gpg for verify")?;
            if !status.success() {
                bail!("gpg verify failed (unknown signer or bad signature)");
            }
            gpg_verified = true;
        } else {
            eprintln!("Note: no signature embedded; skipping gpg verify.");
        }
    }

    publish(&tmp, &target)?;
    guard.0 = None;
    if let Some(asc_tmp) = asc_guard.0.clone() {
        publish(&asc_tmp, &asc_target)?;
        asc_guard.0 = None;
    }
    Ok(Received { path: target, bytes: written, gpg_verified })
}

fn get_passphrase(arg: Option<String>) -> Result<String> {
    match arg {
        Some(p) => {
            eprintln!("Warning: --passphrase is deprecated (visible in process list and shell history).");
            Ok(p)
        }
        None => Ok(prompt_password("Transfer passphrase: ")?),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Send { host, file, chunk_size, sign, passphrase } => {
            if !file.is_file() {
                bail!("file not found");
            }
            let chunk_size = parse_chunk_size(&chunk_size)?;
            let passphrase = get_passphrase(passphrase)?;
            let stream = TcpStream::connect(&host).await?;
            stream.set_nodelay(true)?;
            let sent = send_stream(stream, &file, chunk_size, sign, &passphrase).await?;
            println!("OK: sent {} ({} bytes).", file.display(), sent);
            Ok(())
        }
        Cmd::Recv { listen, output_dir, gpg_verify, passphrase } => {
            let passphrase = get_passphrase(passphrase)?;
            let listener = TcpListener::bind(&listen).await?;
            eprintln!("Listening on {listen}");
            let (stream, _addr) = listener.accept().await?;
            stream.set_nodelay(true)?;
            let r = recv_stream(stream, &output_dir, gpg_verify, &passphrase).await?;
            println!("OK: wrote {} ({} bytes). Integrity & hash verified.", r.path.display(), r.bytes);
            if r.gpg_verified {
                println!("OK: GPG signature verified.");
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("rxf-test-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn chunk_size_parsing() {
        assert_eq!(parse_chunk_size("4MiB").unwrap(), 4 * 1024 * 1024);
        assert_eq!(parse_chunk_size("1mb").unwrap(), 1024 * 1024);
        assert_eq!(parse_chunk_size("64KiB").unwrap(), 64 * 1024);
        assert!(parse_chunk_size("4").is_err());
        assert!(parse_chunk_size("1GiB").is_err());
        assert!(parse_chunk_size("4xb").is_err());
    }

    #[test]
    fn filename_validation() {
        for ok in ["a.txt", "report 2026.pdf", "日本語.md", "aあ", "a..b", "COM0", "COM10.txt", "LPT0", "LPT10.txt", "CONSOLE.txt"] {
            assert!(validate_filename(ok).is_ok(), "{ok}");
        }
        for bad in [
            "", ".", "..", "../x", "..\\x", "a/b", "/etc/passwd", "a\\b", "C:", "C:\\x", "\\\\server\\x", ".ssh",
            "a:b", "a<b", "a>b", "a\"b", "a|b", "a?b", "a*b", "a.", "a ",
        ] {
            assert!(validate_filename(bad).is_err(), "{bad:?}");
        }
        for c in ('\x00'..='\x1f').chain(std::iter::once('\x7f')) {
            let bad = format!("a{c}b");
            assert!(validate_filename(&bad).is_err(), "{bad:?}");
        }
        let mut reserved: Vec<String> = ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"].map(str::to_string).into();
        for n in 1..=9 {
            reserved.extend([format!("COM{n}"), format!("LPT{n}")]);
        }
        for name in reserved {
            for bad in [name.clone(), name.to_ascii_lowercase(), format!("{name}.txt"), format!("{}.txt", name.to_ascii_lowercase())] {
                let err = validate_filename(&bad).unwrap_err().to_string();
                assert!(err.contains("reserved filename"), "{err}");
            }
        }
        assert!(validate_filename(&"a".repeat(256)).is_err());
    }

    #[test]
    fn filename_error_escapes_control_characters() {
        let err = validate_filename("bad\nname.txt").unwrap_err().to_string();
        assert_eq!(err, "invalid filename \"bad\\nname.txt\": control characters are not allowed");
        assert!(!err.chars().any(|c| c.is_control()));
    }

    #[test]
    fn long_filename_error_is_bounded() {
        for (name, preview) in [
            ("a".repeat(12345), "a".repeat(64)),
            ("\n".repeat(12345), r"\n".repeat(32)),
            ("\"".repeat(12345), r#"\""#.repeat(32)),
            ("あ".repeat(12345), r"\u{3042}".repeat(8)),
            ("🦀".repeat(12345), format!("{}\\", r"\u{1f980}".repeat(7))),
        ] {
            let err = validate_filename(&name).unwrap_err().to_string();
            assert_eq!(err, format!("rejected \"{preview}…\" ({} bytes): name too long (max 255)", name.len()));
            assert!(err.len() <= 200, "error is {} bytes", err.len());
            assert!(!err.chars().any(|c| c.is_control()));
        }
    }

    #[tokio::test]
    async fn recv_rejects_filename_without_writing_outside_output_dir() {
        let root = tmpdir("invalid-filename");
        let dst = root.join("received");
        fs::create_dir(&dst).unwrap();
        let hdr = PublicHeader { chunk_size: MIN_CHUNK as u32, salt: [0; SALT_LEN], base_nonce: [0; NONCE_LEN] };
        let hdr_bytes = bopts(MAX_HDR_LEN as u64).serialize(&hdr).unwrap();
        let key = derive_key("pw", &hdr.salt).unwrap();
        let mut sealer = Sealer {
            cipher: XChaCha20Poly1305::new(&key),
            base_nonce: hdr.base_nonce,
            hdr_hash: Sha256::digest(&hdr_bytes).into(),
            counter: 0,
        };
        let data = b"file contents";
        let meta = Meta {
            filename: "../outside.txt".to_string(),
            filesize: data.len() as u64,
            sha256: Sha256::digest(data).into(),
            gpg_sig_armored: None,
        };
        let mut stream = Vec::new();
        stream.extend_from_slice(HDR_MAGIC);
        stream.extend_from_slice(&(hdr_bytes.len() as u32).to_le_bytes());
        stream.extend_from_slice(&hdr_bytes);
        let meta_bytes = bopts(MAX_META_LEN as u64).serialize(&meta).unwrap();
        sealer.write_record(&mut stream, &meta_bytes, 0).await.unwrap();
        sealer.write_record(&mut stream, data, FLAG_FINAL).await.unwrap();

        let err = recv_stream(&stream[..], &dst, false, "pw").await.unwrap_err();
        assert_eq!(err.to_string(), "invalid filename \"../outside.txt\": filename must be a single path element");
        assert_eq!(fs::read_dir(&dst).unwrap().count(), 0);
        let entries: Vec<_> = fs::read_dir(&root).unwrap().map(|entry| entry.unwrap().path()).collect();
        assert_eq!(entries, [dst], "nothing may be written outside the output directory");
    }

    async fn roundtrip(size: usize, chunk: usize, tag: &str) -> Result<Received> {
        let src = tmpdir(&format!("{tag}-src"));
        let dst = tmpdir(&format!("{tag}-dst"));
        let file = src.join("data.bin");
        let data: Vec<u8> = (0..size).map(|i| (i * 31 % 251) as u8).collect();
        fs::write(&file, &data).unwrap();
        let (a, b) = tokio::io::duplex(64 * 1024);
        let f2 = file.clone();
        let s = tokio::spawn(async move { send_stream(a, &f2, chunk, false, "pw").await });
        let r = recv_stream(b, &dst, false, "pw").await;
        let _ = s.await;
        if let Ok(rx) = &r {
            assert_eq!(fs::read(&rx.path).unwrap(), data);
        }
        r
    }

    #[tokio::test]
    async fn roundtrip_sizes() {
        for (i, size) in [0usize, 1, 4096, 4097, 3 * 4096, 100_000].into_iter().enumerate() {
            let r = roundtrip(size, 4096, &format!("rt{i}")).await.unwrap();
            assert_eq!(r.bytes, size as u64);
        }
    }

    #[tokio::test]
    async fn wrong_passphrase_writes_nothing() {
        let src = tmpdir("wp-src");
        let dst = tmpdir("wp-dst");
        let file = src.join("x.bin");
        fs::write(&file, b"hello").unwrap();
        let (a, b) = tokio::io::duplex(64 * 1024);
        let f2 = file.clone();
        tokio::spawn(async move { send_stream(a, &f2, 4096, false, "right").await });
        assert!(recv_stream(b, &dst, false, "wrong").await.is_err());
        assert_eq!(fs::read_dir(&dst).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn refuses_overwrite() {
        let src = tmpdir("ow-src");
        let dst = tmpdir("ow-dst");
        let file = src.join("data.bin");
        fs::write(&file, b"new").unwrap();
        fs::write(dst.join("data.bin"), b"old").unwrap();
        let (a, b) = tokio::io::duplex(64 * 1024);
        let f2 = file.clone();
        tokio::spawn(async move { send_stream(a, &f2, 4096, false, "pw").await });
        assert!(recv_stream(b, &dst, false, "pw").await.is_err());
        assert_eq!(fs::read(dst.join("data.bin")).unwrap(), b"old");
        assert_eq!(fs::read_dir(&dst).unwrap().count(), 1);
    }

    /// Capture a valid stream, then mutate it before feeding the receiver.
    async fn capture(size: usize) -> Vec<u8> {
        let src = tmpdir(&format!("cap{size}"));
        let file = src.join("data.bin");
        fs::write(&file, vec![7u8; size]).unwrap();
        let mut out = Vec::new();
        send_stream(&mut out, &file, 4096, false, "pw").await.unwrap();
        out
    }

    async fn feed(bytes: Vec<u8>, tag: &str) -> (Result<Received>, PathBuf) {
        let dst = tmpdir(tag);
        let r = recv_stream(&bytes[..], &dst, false, "pw").await;
        (r, dst)
    }

    #[tokio::test]
    async fn detects_header_tamper() {
        let mut s = capture(10_000).await;
        s[12] ^= 1; // inside public header (chunk_size)
        let (r, dst) = feed(s, "ht").await;
        assert!(r.is_err());
        assert_eq!(fs::read_dir(&dst).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn detects_truncation() {
        let s = capture(3 * 4096).await;
        // drop the final record (4 + 1 + 0 + 16 bytes for an exact multiple? no: last is a full chunk)
        let cut = s.len() - (4 + 1 + 4096 + TAG_SIZE);
        let (r, dst) = feed(s[..cut].to_vec(), "tr").await;
        assert!(r.is_err());
        assert_eq!(fs::read_dir(&dst).unwrap().count(), 0, "temp file must be removed");
    }

    #[tokio::test]
    async fn rejects_huge_lengths() {
        let mut s = Vec::new();
        s.extend_from_slice(HDR_MAGIC);
        s.extend_from_slice(&u32::MAX.to_le_bytes());
        let (r, _) = feed(s, "hl").await;
        assert!(r.unwrap_err().to_string().contains("header too large"));
    }
}
