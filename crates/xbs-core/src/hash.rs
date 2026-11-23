use crate::{is_cancelled, Cancel, Error, Result};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::Path;

pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex(&h.finalize())
}

pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Streaming full-file SHA-256 with cancellation and byte progress.
pub fn sha256_file(
    path: &Path,
    size: u64,
    cancel: &Cancel,
    progress: &mut dyn FnMut(u64),
) -> Result<String> {
    let mut f = File::open(path)?;
    sha256_open_file(&mut f, size, cancel, progress)
}

/// Hash the same handle that will be used for the subsequent range reads.
pub fn sha256_open_file(
    f: &mut File,
    size: u64,
    cancel: &Cancel,
    progress: &mut dyn FnMut(u64),
) -> Result<String> {
    use std::io::{Seek, SeekFrom};
    let before = f.metadata()?;
    if !before.is_file() || before.len() != size {
        return Err(Error::Format(
            "source size or file type changed before hashing".into(),
        ));
    }
    f.seek(SeekFrom::Start(0))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 4 << 20];
    let mut done = 0u64;
    loop {
        if is_cancelled(cancel) {
            return Err(Error::Cancelled);
        }
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        done += n as u64;
        progress(done);
    }
    let after = f.metadata()?;
    if done != size || after.len() != size || after.modified().ok() != before.modified().ok() {
        return Err(Error::Format(format!(
            "source changed while hashing: read {done} of {size}"
        )));
    }
    Ok(hex(&h.finalize()))
}
