//! "Проверка индексированных диапазонов": verification of an independent list
//! of already-known OPEN ranges inside a source file. The method accounts for
//! ranges; it is not a cipher and does not decrypt protected containers.

pub mod zlib;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use xbs_core::extents::union_bytes;
use xbs_core::{is_cancelled, Cancel, Error, Result};

pub const INDEX_SCHEMA: &str = "xbox-inspector-range-index/1";
pub const REPORT_SCHEMA: &str = "xbox-inspector-range-verification/1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Encoding {
    Raw,
    Zlib,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub id: String,
    pub offset: u64,
    pub stored_len: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_len: Option<u64>,
    /// Expected SHA-256 of the *validated output* (decoded for zlib).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    pub encoding: Encoding,
    #[serde(default)]
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RangeIndex {
    pub schema: String,
    pub source_path: String,
    pub source_size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_sha256: Option<String>,
    pub entries: Vec<Entry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Status {
    VerifiedHash,
    VerifiedStream,
    BoundsOnly,
    FailedBounds,
    TruncatedFile,
    IdentityMismatch,
    SourceChanged,
    FailedZlibHeader,
    DictionaryRequired,
    FailedStream,
    FailedTail,
    FailedLength,
    FailedCap,
    FailedHash,
    Cancelled,
}

impl Status {
    pub fn is_verified(self) -> bool {
        matches!(self, Status::VerifiedHash | Status::VerifiedStream)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct EntryResult {
    pub id: String,
    pub offset: u64,
    pub stored_len: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decoded_len: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    pub status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IdentityCheck {
    pub path: String,
    pub size: u64,
    pub mtime_ns: u128,
    pub size_matches: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256_matches: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IndexReport {
    pub schema: String,
    pub source_path: String,
    pub source_size: u64,
    pub identity: IdentityCheck,
    pub entries: Vec<EntryResult>,
    /// Union of stored intervals with verified contents (no double count).
    pub coverage_bytes: u64,
    pub counts: BTreeMap<String, u64>,
    pub entries_total: usize,
    pub entries_verified: usize,
}

pub struct VerifyOptions {
    pub hash_source: bool,
    pub output_cap: u64,
    pub max_entry_bytes: u64,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self {
            hash_source: false,
            output_cap: 64 << 20,
            max_entry_bytes: 64 << 20,
        }
    }
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    let d = h.finalize();
    let mut s = String::with_capacity(64);
    for b in d {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub fn verify_index(
    index: &RangeIndex,
    path: &Path,
    opts: &VerifyOptions,
    cancel: &Cancel,
    progress: &mut dyn FnMut(usize, usize, u64),
) -> Result<IndexReport> {
    if index.schema != INDEX_SCHEMA {
        return Err(Error::Format(format!(
            "unsupported index schema {}",
            index.schema
        )));
    }
    let mut f = File::open(path)?;
    let md = f.metadata()?;
    if !md.is_file() {
        return Err(Error::Format("indexed source is not a regular file".into()));
    }
    let size = md.len();
    let mtime_ns = md
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let size_matches = size == index.source_size;

    let mut identity = IdentityCheck {
        path: path.to_string_lossy().to_string(),
        size,
        mtime_ns,
        size_matches,
        sha256: None,
        sha256_matches: None,
    };
    if size_matches && (opts.hash_source || index.source_sha256.is_some()) {
        let digest = xbs_core::hash::sha256_open_file(&mut f, size, cancel, &mut |_| {})?;
        identity.sha256_matches = index
            .source_sha256
            .as_ref()
            .map(|expect| expect.eq_ignore_ascii_case(&digest));
        identity.sha256 = Some(digest);
    }
    let identity_ok = size_matches && identity.sha256_matches.unwrap_or(true);

    let mut results = Vec::with_capacity(index.entries.len());
    let mut bytes_read = 0u64;
    let total = index.entries.len();

    for (i, e) in index.entries.iter().enumerate() {
        if is_cancelled(cancel) {
            results.push(EntryResult {
                id: e.id.clone(),
                offset: e.offset,
                stored_len: e.stored_len,
                decoded_len: None,
                sha256: None,
                status: Status::Cancelled,
                detail: None,
            });
            continue;
        }
        let mut res = EntryResult {
            id: e.id.clone(),
            offset: e.offset,
            stored_len: e.stored_len,
            decoded_len: None,
            sha256: None,
            status: Status::BoundsOnly,
            detail: None,
        };
        if !identity_ok {
            res.status = Status::IdentityMismatch;
            res.detail = Some("source identity does not match the index snapshot".into());
            results.push(res);
            continue;
        }
        // Step 2: integer bounds, no read past EOF.
        let end = e.offset.checked_add(e.stored_len);
        match end {
            None => {
                res.status = Status::FailedBounds;
                res.detail = Some("offset+len overflows u64".into());
            }
            Some(_end) if e.stored_len == 0 => {
                res.status = Status::FailedBounds;
                res.detail = Some("zero stored_len".into());
            }
            Some(end) if end > size => {
                res.status = Status::TruncatedFile;
                res.detail = Some(format!("range end {end} beyond file size {size}"));
            }
            Some(_) => {
                if e.stored_len > opts.max_entry_bytes {
                    res.status = Status::FailedCap;
                    res.detail = Some("stored interval exceeds per-entry limit".into());
                } else {
                    let mut buf = vec![0u8; e.stored_len as usize];
                    let read_ok = f
                        .seek(SeekFrom::Start(e.offset))
                        .and_then(|_| f.read_exact(&mut buf))
                        .is_ok();
                    bytes_read += e.stored_len;
                    if !read_ok {
                        res.status = Status::TruncatedFile;
                        res.detail = Some("short read inside declared range".into());
                    } else {
                        match e.encoding {
                            Encoding::Raw => {
                                let digest = sha256_hex(&buf);
                                res.sha256 = Some(digest.clone());
                                res.decoded_len = Some(e.stored_len);
                                match &e.sha256 {
                                    Some(expect) if expect.eq_ignore_ascii_case(&digest) => {
                                        res.status = Status::VerifiedHash;
                                    }
                                    Some(expect) => {
                                        res.status = Status::FailedHash;
                                        res.detail =
                                            Some(format!("expected {expect}, got {digest}"));
                                    }
                                    None => {
                                        res.status = Status::BoundsOnly;
                                        res.detail =
                                            Some("range read; no reference hash supplied".into());
                                    }
                                }
                            }
                            Encoding::Zlib => {
                                let z = zlib::check_with_cancel(
                                    &buf,
                                    e.expected_len,
                                    opts.output_cap,
                                    Some(cancel),
                                );
                                res.detail = z.detail.clone();
                                res.status = match z.status {
                                    zlib::ZStatus::Ok => Status::VerifiedStream,
                                    zlib::ZStatus::HeaderInvalid => Status::FailedZlibHeader,
                                    zlib::ZStatus::DictionaryRequired => Status::DictionaryRequired,
                                    zlib::ZStatus::Truncated => Status::TruncatedFile,
                                    zlib::ZStatus::StreamCorrupt => Status::FailedStream,
                                    zlib::ZStatus::TailAfterStream => Status::FailedTail,
                                    zlib::ZStatus::LengthMismatch => Status::FailedLength,
                                    zlib::ZStatus::OutputCap => Status::FailedCap,
                                    zlib::ZStatus::Cancelled => Status::Cancelled,
                                };
                                if let Some(decoded) = z.decoded {
                                    let digest = sha256_hex(&decoded);
                                    res.decoded_len = Some(decoded.len() as u64);
                                    res.sha256 = Some(digest.clone());
                                    if let Some(expect) = &e.sha256 {
                                        if expect.eq_ignore_ascii_case(&digest) {
                                            res.status = Status::VerifiedHash;
                                        } else {
                                            res.status = Status::FailedHash;
                                            res.detail =
                                                Some(format!("expected {expect}, got {digest}"));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        results.push(res);
        progress(i + 1, total, bytes_read);
    }

    let after = f.metadata()?;
    if after.len() != size || after.modified().ok() != md.modified().ok() {
        for row in &mut results {
            if row.status.is_verified() {
                row.status = Status::SourceChanged;
                row.detail = Some("source changed during verification".into());
            }
        }
    }
    let covered: Vec<_> = results
        .iter()
        .filter(|r| r.status.is_verified())
        .map(|r| (r.offset, r.offset + r.stored_len))
        .collect();
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    for r in &results {
        *counts.entry(format!("{:?}", r.status)).or_insert(0) += 1;
    }
    let entries_verified = results.iter().filter(|r| r.status.is_verified()).count();
    Ok(IndexReport {
        schema: REPORT_SCHEMA.into(),
        source_path: index.source_path.clone(),
        source_size: size,
        identity,
        entries: results,
        coverage_bytes: union_bytes(&covered),
        counts,
        entries_total: total,
        entries_verified,
    })
}

/// Load an index from JSON.
pub fn load_index(path: &Path) -> Result<RangeIndex> {
    let text = xbs_core::safe_path::read_text(path, xbs_core::safe_path::MAX_INDEX_BYTES)?;
    let idx: RangeIndex =
        serde_json::from_str(&text).map_err(|e| Error::Format(format!("index JSON: {e}")))?;
    validate_index_structure(&idx)?;
    Ok(idx)
}

/// Validate index structure BEFORE any source file is opened (spec item 16/19).
pub fn validate_index_structure(idx: &RangeIndex) -> Result<()> {
    if idx.schema != INDEX_SCHEMA {
        return Err(Error::Format(format!(
            "unsupported index schema: {}",
            idx.schema
        )));
    }
    if idx.entries.len() > xbs_core::safe_path::MAX_INDEX_ENTRIES {
        return Err(Error::Format(format!(
            "index too large: {} entries (limit {})",
            idx.entries.len(),
            xbs_core::safe_path::MAX_INDEX_ENTRIES
        )));
    }
    xbs_core::safe_path::relative_index_path(&idx.source_path)?;
    fn valid_hash(hash: &str) -> bool {
        hash.len() == 64 && hash.bytes().all(|c| c.is_ascii_hexdigit())
    }
    if idx.source_sha256.as_deref().is_some_and(|h| !valid_hash(h)) {
        return Err(Error::Format("invalid source SHA-256".into()));
    }
    let mut ids = std::collections::BTreeSet::new();
    for e in &idx.entries {
        if e.id.is_empty() || e.id.len() > 1024 || e.kind.len() > 128 {
            return Err(Error::Format(
                "invalid index entry id or kind length".into(),
            ));
        }
        if e.sha256.as_deref().is_some_and(|h| !valid_hash(h)) {
            return Err(Error::Format(format!("entry {}: invalid SHA-256", e.id)));
        }
        if !ids.insert(&e.id) {
            return Err(Error::Format(format!("duplicate index entry id: {}", e.id)));
        }
        if e.stored_len == 0 {
            return Err(Error::Format(format!("entry {}: zero stored_len", e.id)));
        }
        if e.offset.checked_add(e.stored_len).is_none() {
            return Err(Error::Format(format!(
                "entry {}: offset+len overflow",
                e.id
            )));
        }
        if let Some(exp) = e.expected_len {
            if exp > 64 << 20 {
                return Err(Error::Format(format!(
                    "entry {}: expected_len over cap",
                    e.id
                )));
            }
        }
    }
    Ok(())
}
