//! Path containment for index-driven reads. Every path coming from an index
//! (bundled or user-supplied) must resolve INSIDE the selected source root.
//! Rejects absolute paths, parent traversal, drive/UNC prefixes, ADS colons,
//! and symlinks/junctions that escape the root (canonicalization resolves them).

use crate::{Error, Result};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Maximum entries accepted from a single index file (report size budget).
pub const MAX_INDEX_ENTRIES: usize = 500_000;
pub const MAX_INDEX_BYTES: u64 = 64 << 20;

/// Symlinks and Windows reparse points are skipped in both walkers and index reads.
pub fn is_link(metadata: &Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

pub fn relative_index_path(rel: &str) -> Result<PathBuf> {
    let normalized = rel.replace('\\', "/");
    if normalized.len() > 4096
        || normalized.split('/').any(|part| {
            let stem = part
                .split('.')
                .next()
                .unwrap_or("")
                .trim_end()
                .to_ascii_uppercase();
            let device = matches!(
                stem.as_str(),
                "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
            ) || ["COM", "LPT"].iter().any(|prefix| {
                stem.strip_prefix(prefix)
                    .is_some_and(|n| n.len() == 1 && matches!(n.as_bytes()[0], b'1'..=b'9'))
            });
            part.is_empty()
                || part.ends_with(['.', ' '])
                || part
                    .chars()
                    .any(|c| c.is_control() || matches!(c, ':' | '<' | '>' | '"' | '|' | '?' | '*'))
                || device
        })
    {
        return Err(Error::Format("invalid relative index path".into()));
    }
    Ok(PathBuf::from(normalized))
}

/// Resolve a regular file under the selected root without accepting reparse entries.
pub fn resolve_within(root: &Path, rel: &str) -> Result<PathBuf> {
    let relative = relative_index_path(rel)?;
    let root = root.canonicalize()?;
    let mut path = root.clone();
    for part in relative.components() {
        path.push(part);
        if is_link(&fs::symlink_metadata(&path)?) {
            return Err(Error::Format(
                "indexed path contains a link or reparse point".into(),
            ));
        }
    }
    let path = path.canonicalize()?;
    if !path.starts_with(root) || !path.is_file() {
        return Err(Error::Format(
            "index target is not a regular file within the selected root".into(),
        ));
    }
    Ok(path)
}

/// Read a selected metadata file with a budget independent of its JSON shape.
pub fn read_text(path: &Path, limit: u64) -> Result<String> {
    use std::io::Read;
    let file = File::open(path)?;
    if !file.metadata()?.is_file() || file.metadata()?.len() > limit {
        return Err(Error::Format(
            "metadata file exceeds its byte budget or is not regular".into(),
        ));
    }
    let mut text = String::new();
    file.take(limit + 1).read_to_string(&mut text)?;
    if text.len() as u64 > limit {
        return Err(Error::Format(
            "metadata file exceeds its byte budget".into(),
        ));
    }
    Ok(text)
}

/// Resolve an existing path or a path whose final segments will be created.
pub fn outside_source(source_root: &Path, destination: &Path) -> Result<PathBuf> {
    let root = source_root.canonicalize()?;
    let absolute = std::path::absolute(destination)?;
    let mut existing = absolute.as_path();
    let mut missing = Vec::new();
    let mut resolved = loop {
        match fs::symlink_metadata(existing) {
            Ok(md) if is_link(&md) => {
                return Err(Error::Format(
                    "output destination is a link or reparse point".into(),
                ))
            }
            Ok(_) => break existing.canonicalize()?,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                let name = existing
                    .file_name()
                    .ok_or_else(|| Error::Format("invalid output path".into()))?;
                missing.push(name);
                existing = existing
                    .parent()
                    .ok_or_else(|| Error::Format("invalid output path".into()))?;
            }
            Err(err) => return Err(err.into()),
        }
    };
    if resolved.starts_with(&root) {
        return Err(Error::Format(
            "output must be outside the source folder".into(),
        ));
    }
    for name in missing.into_iter().rev() {
        relative_index_path(&name.to_string_lossy())?;
        resolved.push(name);
    }
    Ok(resolved)
}

/// Write via a new sibling, then replace the destination directory entry. A
/// pre-existing hard link is never written in place.
pub fn write_outside(source_root: &Path, destination: &Path, data: &[u8]) -> Result<()> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = outside_source(source_root, destination)?;
    let parent = path
        .parent()
        .ok_or_else(|| Error::Format("invalid output parent".into()))?;
    let temp = parent.join(format!(
        ".xbs-{}-{}.tmp",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)?;
    let write_result = file.write_all(data).and_then(|()| file.sync_all());
    drop(file);
    let result = write_result.and_then(|()| fs::rename(&temp, &path));
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    Ok(result?)
}

/// Case-insensitive duplicate path detection (Windows semantics).
pub fn find_case_duplicates(paths: &[String]) -> Vec<(String, String)> {
    let mut seen: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    let mut dups = Vec::new();
    for p in paths {
        let key = p.to_lowercase();
        if let Some(prev) = seen.get(&key) {
            if prev != p {
                dups.push((prev.clone(), p.clone()));
            }
        } else {
            seen.insert(key, p.clone());
        }
    }
    dups
}
