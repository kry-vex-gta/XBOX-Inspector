use crate::formats::{catalog_state, classify_prefix, FileKind};
use crate::{is_cancelled, Cancel, Error, Result};
use serde::Serialize;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

#[derive(Debug, Clone, Serialize)]
pub struct InvFile {
    pub rel: String,
    pub size: u64,
    pub mtime_ns: u128,
    pub kind: FileKind,
    pub catalog_state: String,
    pub prefix_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Read-only recursive walk. Symlinks are never followed (they could escape
/// the selected root); they are recorded with a note instead.
pub fn walk(root: &Path, cancel: &Cancel, progress: &mut dyn FnMut(u64)) -> Result<Vec<InvFile>> {
    let root = root
        .canonicalize()
        .map_err(|e| Error::Format(format!("cannot open source root: {e}")))?;
    let mut out: Vec<InvFile> = Vec::new();
    let mut stack: Vec<PathBuf> = vec![root.clone()];
    let mut seen = 0u64;
    while let Some(dir) = stack.pop() {
        if is_cancelled(cancel) {
            return Err(Error::Cancelled);
        }
        let rd = match fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) => {
                return Err(Error::Format(format!("read_dir {}: {e}", dir.display())));
            }
        };
        for entry in rd {
            let entry = entry?;
            let path = entry.path();
            let md = fs::symlink_metadata(&path)?;
            let rel = path
                .strip_prefix(&root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            if crate::safe_path::is_link(&md) {
                out.push(InvFile {
                    rel,
                    size: 0,
                    mtime_ns: mtime_ns(&md),
                    kind: FileKind::Unknown,
                    catalog_state: "SKIPPED_LINK".to_string(),
                    prefix_hex: String::new(),
                    note: Some("link or reparse point skipped".to_string()),
                });
                continue;
            }
            if md.is_dir() {
                stack.push(path);
                continue;
            }
            if !md.is_file() {
                continue;
            }
            let size = md.len();
            let mut prefix = [0u8; 64];
            let n = {
                let mut f = fs::File::open(&path)?;
                let want = if size < 64 { size as usize } else { 64 };
                f.read(&mut prefix[..want])?
            };
            let ext = path
                .extension()
                .map(|e| e.to_string_lossy().to_lowercase())
                .unwrap_or_default();
            let mut kind = classify_prefix(&prefix[..n], &ext);
            if kind == FileKind::PeExecutable {
                kind = crate::pe::quick_classify(&path).unwrap_or(FileKind::PeExecutable);
            }
            out.push(InvFile {
                rel,
                size,
                mtime_ns: mtime_ns(&md),
                kind,
                catalog_state: catalog_state(kind).to_string(),
                prefix_hex: crate::hash::hex(&prefix[..n.min(16)]),
                note: None,
            });
            seen += 1;
            progress(seen);
        }
    }
    out.sort_by(|a, b| a.rel.cmp(&b.rel));
    Ok(out)
}

fn mtime_ns(md: &fs::Metadata) -> u128 {
    md.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

pub fn logical_bytes(files: &[InvFile]) -> u64 {
    files.iter().map(|f| f.size).sum()
}
