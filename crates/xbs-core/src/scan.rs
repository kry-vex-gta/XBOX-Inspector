//! Open ZLIB stream discovery inside RPF9 payloads. Finds RFC1950 streams in
//! allocated ranges, validates them with bounded inflation, hashes the output
//! and classifies the inner resource by its own prefix. This is recovery of
//! *open* data only; it does not decrypt anything.

use crate::hash::sha256_hex;
use crate::{is_cancelled, Cancel, Error, Result};
use serde::Serialize;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};

const CHUNK: u64 = 8 << 20;
pub const MAX_MEMBERS: usize = 200_000;
pub const SESSION_DECODE_LIMIT: u64 = 2 << 30;
pub const STREAM_CAP: u64 = 64 << 20;

#[derive(Debug, Clone, Serialize)]
pub struct ZlibMember {
    pub offset: u64,
    pub stored_len: u64,
    pub decoded_len: u64,
    pub sha256: String,
    pub inner_prefix_hex: String,
    pub inner_kind: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ZlibScan {
    pub members: Vec<ZlibMember>,
    pub rejected_candidates: u64,
    pub scanned_payload_bytes: u64,
    pub decoded_bytes_total: u64,
    pub stopped_reason: Option<String>,
}

fn inner_kind(prefix: &[u8]) -> &'static str {
    if prefix.starts_with(b"RBF0") {
        "RBF"
    } else if prefix.starts_with(b"GFX ") || prefix.starts_with(b"CFX ") {
        "Scaleform"
    } else if prefix.starts_with(b"ABC ") {
        "ActionScript"
    } else if prefix.starts_with(b"DDS ") {
        "DDS"
    } else if prefix.starts_with(&[0x1b, b'L', b'u', b'a']) {
        "Lua"
    } else {
        "unknown"
    }
}

/// Try to inflate a candidate at `offset`; returns (stored_len, decoded) on success.
fn try_stream(f: &mut File, offset: u64, upper: u64, cancel: &Cancel) -> Result<(u64, Vec<u8>)> {
    let avail = upper
        .checked_sub(offset)
        .ok_or_else(|| Error::Format("stream offset outside bounds".into()))?;
    if avail < 6 {
        return Err(Error::Format("too short".into()));
    }
    f.seek(SeekFrom::Start(offset))?;
    let input = BufReader::with_capacity(32 << 10, f.take(avail.min(STREAM_CAP)));
    let result = crate::zlib::decode(input, None, STREAM_CAP, Some(cancel));
    if result.status == crate::zlib::ZStatus::Cancelled {
        return Err(Error::Cancelled);
    }
    result
        .decoded
        .map(|data| (result.consumed, data))
        .ok_or_else(|| Error::Format(result.detail.unwrap_or_default()))
}

pub fn scan(
    f: &mut File,
    extents: &[(u64, u64)],
    cancel: &Cancel,
    progress: &mut dyn FnMut(u64, u64),
) -> Result<ZlibScan> {
    let total: u64 = extents.iter().map(|(a, b)| b - a).sum();
    let mut out = ZlibScan {
        members: Vec::new(),
        rejected_candidates: 0,
        scanned_payload_bytes: 0,
        decoded_bytes_total: 0,
        stopped_reason: None,
    };
    let mut next_free = 0u64;
    let mut buf = vec![0u8; CHUNK as usize];
    'outer: for &(start, end) in extents {
        let mut cursor = start;
        while cursor < end {
            if is_cancelled(cancel) {
                out.stopped_reason = Some("cancelled".into());
                break 'outer;
            }
            let want = (end - cursor).min(CHUNK) as usize;
            f.seek(SeekFrom::Start(cursor))?;
            f.read_exact(&mut buf[..want])?;
            let mut i = 0usize;
            while i + 2 <= want {
                if buf[i] == 0x78 {
                    let flg = buf[i + 1];
                    let cmf = buf[i];
                    if cmf >> 4 <= 7
                        && ((cmf as u16) * 256 + flg as u16) % 31 == 0
                        && flg & 0x20 == 0
                    {
                        let offset = cursor + i as u64;
                        if offset >= next_free {
                            match try_stream(f, offset, end, cancel) {
                                Ok((stored, decoded)) => {
                                    next_free = offset + stored;
                                    let decoded_total =
                                        out.decoded_bytes_total + decoded.len() as u64;
                                    if decoded_total > SESSION_DECODE_LIMIT {
                                        out.stopped_reason = Some("session decode limit".into());
                                        break 'outer;
                                    }
                                    out.decoded_bytes_total = decoded_total;
                                    let prefix = &decoded[..decoded.len().min(8)];
                                    out.members.push(ZlibMember {
                                        offset,
                                        stored_len: stored,
                                        decoded_len: decoded.len() as u64,
                                        sha256: sha256_hex(&decoded),
                                        inner_prefix_hex: crate::hash::hex(prefix),
                                        inner_kind: inner_kind(prefix).into(),
                                    });
                                    if out.members.len() >= MAX_MEMBERS {
                                        out.stopped_reason = Some("member limit".into());
                                        break 'outer;
                                    }
                                    i = (next_free - cursor).min(want as u64) as usize;
                                    continue;
                                }
                                Err(Error::Cancelled) => return Err(Error::Cancelled),
                                Err(_) => {
                                    out.rejected_candidates += 1;
                                }
                            }
                        }
                    }
                }
                i += 1;
            }
            let chunk_end = cursor + want as u64;
            // Retain the last prefix byte across adjacent buffers. A validated
            // stream may also extend beyond this buffer, but never the extent.
            let next_chunk = if chunk_end < end {
                chunk_end - 1
            } else {
                chunk_end
            };
            let next = next_chunk.max(next_free.min(end));
            out.scanned_payload_bytes += next - cursor;
            cursor = next;
            progress(out.scanned_payload_bytes, total);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{write::ZlibEncoder, Compression};
    use std::io::Write;

    #[test]
    fn stream_crossing_a_scan_buffer_keeps_cursor_and_progress_in_bounds() {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(b"owned fixture").unwrap();
        let wire = encoder.finish().unwrap();
        let path = std::env::temp_dir().join(format!("xbs-buffer-boundary-{}", std::process::id()));
        let mut bytes = vec![0; CHUNK as usize - 1];
        bytes.extend_from_slice(&wire);
        bytes.extend_from_slice(&wire);
        std::fs::write(&path, &bytes).unwrap();
        let mut file = File::open(&path).unwrap();
        let end = bytes.len() as u64;
        let report = scan(
            &mut file,
            &[(0, end)],
            &crate::new_cancel(),
            &mut |done, total| {
                assert!(done <= total);
            },
        )
        .unwrap();
        drop(file);
        std::fs::remove_file(path).unwrap();
        assert_eq!(report.scanned_payload_bytes, end);
        assert_eq!(report.members.len(), 2);
        assert_eq!(report.members[0].offset, CHUNK - 1);
        assert_eq!(report.members[1].offset, CHUNK - 1 + wire.len() as u64);
    }
}
