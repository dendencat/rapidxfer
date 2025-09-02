use anyhow::{anyhow, Context, Result};
use argon2::{password_hash::{PasswordHasher, SaltString}, Argon2};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, Key, XNonce,
};
use clap::{Parser, Subcommand};
use rand::{rngs::OsRng, RngCore};
use rpassword::prompt_password;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs, io::{self, Read}, path::{Path, PathBuf}, process::Command};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter},
    net::{TcpListener, TcpStream},
};

const TAG_SIZE: usize = 16;          // Poly1305 tag
const SALT_LEN: usize = 16;          // Argon2id salt
const NONCE_LEN: usize = 24;         // XChaCha20 nonce
const HDR_MAGIC: &[u8; 8] = b"RXF-HDR1";

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
        #[arg(long, default_value = "0.0.0.0:9000")]
        listen: String,
        #[arg(long, default_value = ".")]
        output_dir: PathBuf,
        /// Verify GPG signature if present
        #[arg(long)]
        gpg-verify: bool,
        /// Optional passphrase via env/arg is discouraged; prompt is default
        #[arg(long)]
        passphrase: Option<String>,
    },
    /// Send a file (client)
    Send {
        #[arg(long)]
        host: String,
        #[arg(long)]
        file: PathBuf,
        /// Chunk size like 1MiB, 4MiB (default 4MiB)
        #[arg(long, default_value = "4MiB")]
        chunk_size: String,
        /// Create detached signature via gpg and embed (.asc)
        #[arg(long)]
        sign: bool,
        /// Optional passphrase via env/arg is discouraged; prompt is default
        #[arg(long)]
        passphrase: Option<String>,
    },
}

#[derive(Serialize, Deserialize, Debug)]
struct Header {
    filename: String,
    filesize: u64,
    chunk_size: u32,
    salt: [u8; SALT_LEN],
    base_nonce: [u8; NONCE_LEN], // first 16B random, last 8B counter base
    sha256: [u8; 32],            // hash of plaintext file
    gpg_sig_armored: Option<Vec<u8>>, // if --sign, detached ascii-armored sig bytes
}

fn parse_chunk_size(s: &str) -> Result<usize> {
    let s = s.trim().to_ascii_lowercase();
    let (num, suffix) = s
        .trim_end_matches("kib").trim_end_matches("kb")
        .trim_end_matches("mib").trim_end_matches("mb")
        .trim_end_matches("gib").trim_end_matches("gb")
        .split_at(s.chars().take_while(|c| c.is_ascii_digit()).count());
    let n: usize = num.parse().context("invalid chunk size number")?;
    let mult = if suffix.ends_with("gib") || suffix.ends_with("gb") {
        1024 * 1024 * 1024
    } else if suffix.ends_with("mib") || suffix.ends_with("mb") {
        1024 * 1024
    } else if suffix.ends_with("kib") || suffix.ends_with("kb") {
        1024
    } else if suffix.is_empty() {
        1
    } else {
        return Err(anyhow!("invalid chunk size suffix"));
    };
    Ok(n * mult)
}

fn sha256_file(path: &Path) -> Result<[u8; 32]> {
    let mut f = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 { break; }
        hasher.update(&buf[..n]);
    }
    let out = hasher.finalize();
    Ok(out.into())
}

fn derive_key(passphrase: &str, salt: &[u8; SALT_LEN]) -> Result<Key> {
    let argon = Argon2::default();
    let salt_str = SaltString::encode_b64(salt).map_err(|_| anyhow!("salt b64"))?;
    let hash = argon
        .hash_password(passphrase.as_bytes(), &salt_str)
        .map_err(|e| anyhow!("argon2 error: {e}"))?;
    let bytes = hash.hash.ok_or_else(|| anyhow!("argon2 no hash"))?;
    // Truncate/expand to 32 bytes
    let mut key = [0u8; 32];
    let take = bytes.len().min(32);
    key[..take].copy_from_slice(&bytes.as_bytes()[..take]);
    Ok(Key::from_slice(&key).clone())
}

// Increment last 8 bytes (LE) of the 24B nonce
fn nonce_with_counter(base: &[u8; NONCE_LEN], counter: u64) -> XNonce {
    let mut n = *base;
    n[16..24].copy_from_slice(&counter.to_le_bytes());
    XNonce::from_slice(&n).clone()
}

async fn send(host: &str, file: &Path, chunk_size_s: &str, sign: bool, pass_in: Option<String>) -> Result<()> {
    let mut stream = TcpStream::connect(host).await?;
    stream.set_nodelay(true)?;
    let mut writer = BufWriter::new(stream);

    // Input password
    let passphrase = match pass_in {
        Some(p) => p,
        None => prompt_password("Transfer passphrase: ")?,
    };

    // Prepare crypto materials
    let mut salt = [0u8; SALT_LEN]; OsRng.fill_bytes(&mut salt);
    let key = derive_key(&passphrase, &salt)?;
    let cipher = XChaCha20Poly1305::new(&key);

    let mut base_nonce = [0u8; NONCE_LEN]; OsRng.fill_bytes(&mut base_nonce);
    // File metadata
    let filename = file.file_name().ok_or_else(|| anyhow!("invalid filename"))?
        .to_string_lossy().to_string();
    let filesize = fs::metadata(file)?.len();
    let sha256 = sha256_file(file)?;

    // Optional GPG detached signature
    let gpg_sig_armored = if sign {
        let out = Command::new("gpg")
            .args(["--batch", "--yes", "--armor", "--detach-sign", file.to_string_lossy().as_ref()])
            .output()
            .context("gpg sign failed to spawn")?;
        if !out.status.success() {
            return Err(anyhow!("gpg sign failed (is your key configured?)"));
        }
        // gpg writes .asc next to the file
        let asc_path = file.with_extension(format!(
            "{}.asc",
            file.extension().map(|e| e.to_string_lossy()).unwrap_or_default()
        ));
        let asc = fs::read(&asc_path).or_else(|_| {
            // fallback: common name is <file>.asc
            fs::read(file.with_extension("asc"))
        })?;
        Some(asc)
    } else {
        None
    };

    let chunk_size = parse_chunk_size(chunk_size_s)? as u32;

    // Header (plaintext)
    let hdr = Header {
        filename, filesize, chunk_size, salt, base_nonce, sha256, gpg_sig_armored
    };
    let hdr_bytes = bincode::serialize(&hdr)?;
    writer.write_all(HDR_MAGIC).await?;
    writer.write_u32_le(hdr_bytes.len() as u32).await?;
    writer.write_all(&hdr_bytes).await?;
    writer.flush().await?;

    // Send encrypted chunks
    let mut f = tokio::fs::File::open(file).await?;
    let mut buf = vec![0u8; chunk_size as usize];
    let mut counter: u64 = 0;
    let mut sent: u64 = 0;

    loop {
        let n = f.read(&mut buf).await?;
        if n == 0 { break; }
        let nonce = nonce_with_counter(&base_nonce, counter);
        let ct = cipher.encrypt(&nonce, Payload { msg: &buf[..n], aad: &[] })
            .map_err(|_| anyhow!("encrypt failed"))?;
        writer.write_u32_le(n as u32).await?; // plaintext length
        writer.write_all(&ct).await?;
        sent += n as u64;
        counter = counter.checked_add(1).ok_or_else(|| anyhow!("nonce counter overflow"))?;
    }

    writer.flush().await?;
    // finalize
    Ok(())
}

async fn recv(listen: &str, outdir: &Path, gpg_verify: bool, pass_in: Option<String>) -> Result<()> {
    let listener = TcpListener::bind(listen).await?;
    let (stream, _addr) = listener.accept().await?;
    stream.set_nodelay(true)?;
    let mut reader = BufReader::new(stream);
    let mut magic = [0u8; 8];
    reader.read_exact(&mut magic).await?;
    if &magic != HDR_MAGIC {
        return Err(anyhow!("bad header magic"));
    }
    let hdr_len = reader.read_u32_le().await? as usize;
    let mut hdr_bytes = vec![0u8; hdr_len];
    reader.read_exact(&mut hdr_bytes).await?;
    let hdr: Header = bincode::deserialize(&hdr_bytes)?;

    // Input password
    let passphrase = match pass_in {
        Some(p) => p,
        None => prompt_password("Transfer passphrase: ")?,
    };
    let key = derive_key(&passphrase, &hdr.salt)?;
    let cipher = XChaCha20Poly1305::new(&key);

    // Prepare output file
    tokio::fs::create_dir_all(outdir).await.ok();
    let outpath = outdir.join(&hdr.filename);
    let mut out = tokio::fs::File::create(&outpath).await?;

    let mut counter: u64 = 0;
    let mut written: u64 = 0u64;
    let mut hasher = Sha256::new();

    let mut ct_buf = vec![0u8; hdr.chunk_size as usize + TAG_SIZE];

    while written < hdr.filesize {
        let plain_len = reader.read_u32_le().await? as usize;
        let ct_len = plain_len + TAG_SIZE;
        if ct_buf.len() < ct_len {
            ct_buf.resize(ct_len, 0);
        }
        reader.read_exact(&mut ct_buf[..ct_len]).await?;
        let nonce = nonce_with_counter(&hdr.base_nonce, counter);
        let pt = cipher.decrypt(&nonce, Payload { msg: &ct_buf[..ct_len], aad: &[] })
            .map_err(|_| anyhow!("decrypt/auth failed (tamper detected)"))?;
        out.write_all(&pt).await?;
        hasher.update(&pt);
        written += plain_len as u64;
        counter = counter.checked_add(1).ok_or_else(|| anyhow!("nonce counter overflow"))?;
    }
    out.flush().await?;

    // SHA-256 check
    let calc: [u8; 32] = hasher.finalize().into();
    if calc != hdr.sha256 {
        return Err(anyhow!("sha256 mismatch (corruption detected)"));
    }

    // Optional GPG verify
    if gpg_verify {
        if let Some(sig) = hdr.gpg_sig_armored.as_ref() {
            // write temp .asc
            let asc_path = outpath.with_extension(format!(
                "{}.asc",
                outpath.extension().and_then(|e| e.to_str()).unwrap_or("")
            ));
            tokio::fs::write(&asc_path, sig).await?;
            let status = Command::new("gpg")
                .args(["--verify", asc_path.to_string_lossy().as_ref(), outpath.to_string_lossy().as_ref()])
                .status()
                .context("failed to spawn gpg for verify")?;
            if !status.success() {
                return Err(anyhow!("gpg verify failed (unknown signer or bad signature)"));
            }
        } else {
            eprintln!("Note: no signature embedded; skipping gpg verify.");
        }
    }

    println!("OK: wrote {} ({} bytes). Integrity & hash verified.", outpath.display(), written);
    if gpg_verify && hdr.gpg_sig_armored.is_some() {
        println!("OK: GPG signature verified.");
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Send { host, file, chunk_size, sign, passphrase } => {
            if !file.exists() { return Err(anyhow!("file not found")); }
            send(&host, &file, &chunk_size, sign, passphrase).await
        }
        Cmd::Recv { listen, output_dir, gpg_verify, passphrase } => {
            recv(&listen, &output_dir, gpg_verify, passphrase).await
        }
    }
}
