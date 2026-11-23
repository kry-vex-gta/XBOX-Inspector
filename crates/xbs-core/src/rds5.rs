//! Strict read-only RDS5/ETPF analysis. Faithful Rust port of the SimuXBOX
//! 0.1.0 reference `rds5.py` (observed profile 0x16000000).

use crate::extents::{allocated_ranges, Extents};
use crate::hash::{hex, sha256_hex};
use crate::{is_cancelled, Cancel, Error, Result};
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

pub const PROFILE: u32 = 0x1600_0000;
pub const ETPF_VERSION: u32 = 0x27A;
pub const BLOCK_LIMIT: u64 = 64 << 20;
pub const EXPORT_LIMIT: u64 = 2 << 30;
pub const TABLE_LIMIT: u32 = 100_000;
const READ_SIZE: usize = 256 << 10;

pub fn codec_name(id: u32) -> String {
    match id {
        0 => "RAW".into(),
        0x20 => "ZLIB".into(),
        4 => "BCPack/BC1".into(),
        12 => "BCPack/BC3?".into(),
        16 => "BCPack/BC4".into(),
        20 => "BCPack/BC5".into(),
        24 => "BCPack/BC6H".into(),
        28 => "BCPack/BC7".into(),
        other => format!("OTHER/{other:#x}"),
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Boundary {
    pub offset: u64,
    pub address: u64,
    pub codec_id: u32,
    pub padding: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct Rds5Header {
    pub profile: u32,
    pub raw_header_word_16: u32,
    pub raw_header_word_20: u32,
    pub declared_virtual_bytes: u64,
    pub boundary_records: u32,
    pub declared_end: u64,
    pub terminal_virtual: u64,
    pub etpf_offset: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Texture {
    pub texture_id: String,
    pub width: u32,
    pub height: u32,
    pub mip_count: u32,
    pub array_size: u32,
    pub dxgi: u32,
    pub tile_mode: u32,
    pub address: u64,
    pub start_block: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EtpfInfo {
    pub version: u32,
    pub descriptors: u32,
    pub raw_header_word_12: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct BlockRow {
    pub index: usize,
    pub offset: u64,
    pub end: u64,
    #[serde(rename = "virtual")]
    pub virtual_addr: u64,
    pub virtual_bytes: u64,
    pub packed_bytes: u64,
    pub codec_id: u32,
    pub codec: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub missing: Option<[u64; 2]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decoded_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Rds5Report {
    pub schema: String,
    pub rel: String,
    pub file_bytes: u64,
    pub allocated_bytes: u64,
    pub allocation_method: String,
    pub status: String,
    pub header: Rds5Header,
    pub etpf: Option<EtpfInfo>,
    pub metadata_error: Option<String>,
    pub counts: BTreeMap<String, u64>,
    pub verified_bytes: u64,
    pub blocks: Vec<BlockRow>,
    pub textures_total: usize,
    pub textures_sample: Vec<Texture>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub textures: Option<Vec<Texture>>,
}

struct Source {
    file: File,
    extents: Extents,
}

impl Source {
    fn read_at(&mut self, offset: u64, size: usize) -> Result<Vec<u8>> {
        if let Some(gap) = self.extents.first_gap(offset, offset + size as u64) {
            return Err(Error::Format(format!(
                "TRUNCATED_FILE: required range absent [{}, {})",
                gap.0, gap.1
            )));
        }
        self.file.seek(SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; size];
        self.file.read_exact(&mut buf)?;
        Ok(buf)
    }
}

fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn u64le(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

fn parse_table(src: &mut Source) -> Result<(Rds5Header, Vec<Boundary>)> {
    let h = src.read_at(0, 24)?;
    if &h[..4] != b"RDS5" {
        return Err(Error::Format("UNSUPPORTED_FORMAT: RDS5 signature absent".into()));
    }
    let count = u32le(&h, 4);
    let virtual_low = u32le(&h, 8) as u64;
    let profile = u32le(&h, 12);
    let raw_16 = u32le(&h, 16);
    let reserved = u32le(&h, 20);
    if profile & 0xFFFF_FF00 != PROFILE || !matches!(reserved, 0 | 0x1000_0000 | 0x2000_0000) {
        return Err(Error::Format(format!(
            "UNSUPPORTED_FORMAT: unknown RDS5 profile {profile:#x}/{reserved:#x}"
        )));
    }
    let declared_bytes = (((profile & 255) as u64) << 32) | virtual_low;
    if !(3..=TABLE_LIMIT).contains(&count) {
        return Err(Error::Format(format!("INVALID_HEADER: boundary count {count}")));
    }
    let index_offset = ((16 + count as u64 * 8 + 255) & !255) as u64;
    let table = src.read_at(24, count as usize * 8)?;
    let rows: Vec<(u32, u32)> = (0..count as usize)
        .map(|i| (u32le(&table, i * 8), u32le(&table, i * 8 + 4)))
        .collect();
    let marker_at = 24 + (count as u64 - 1) * 8;
    let shared_marker = marker_at == index_offset
        && index_offset == (raw_16 as u64) << 8
        && table[table.len() - 8..table.len() - 4] == *b"ETPF"
        && u32le(&table, table.len() - 4) == ETPF_VERSION;
    let terminal_ok = *rows.last().unwrap() == (0, 0) || shared_marker;
    if !terminal_ok || rows[..rows.len() - 1].contains(&(0, 0)) {
        return Err(Error::Format("INVALID_HEADER: missing terminal boundary marker".into()));
    }
    let boundaries: Vec<Boundary> = rows[..rows.len() - 1]
        .iter()
        .map(|&(a, b)| Boundary {
            offset: ((a & 0x3ff_ffff) as u64) * 256,
            address: 4096 + ((b & 0xf_ffff) as u64) * 16384 + ((a >> 30) as u64) * 4096,
            codec_id: (a >> 24) & 0x3c,
            padding: b >> 20,
        })
        .collect();
    if boundaries[0].offset < index_offset + 16 {
        return Err(Error::Format("INVALID_HEADER: first payload overlaps the texture catalog".into()));
    }
    if boundaries.windows(2).any(|w| w[0].offset > w[1].offset) {
        return Err(Error::Format("INVALID_HEADER: physical boundary order is not monotone".into()));
    }
    let n = boundaries.len();
    if n >= 3 && boundaries[..n - 2].iter().zip(&boundaries[1..n - 1]).any(|(a, b)| a.address > b.address) {
        return Err(Error::Format("INVALID_HEADER: logical boundary order is not monotone".into()));
    }
    if (profile != PROFILE || reserved != 0)
        && boundaries[n - 1].address != declared_bytes + 4096
    {
        return Err(Error::Format("INVALID_HEADER: wide RDS5 size disagrees with terminal boundary".into()));
    }
    Ok((
        Rds5Header {
            profile,
            raw_header_word_16: raw_16,
            raw_header_word_20: reserved,
            declared_virtual_bytes: declared_bytes,
            boundary_records: count,
            declared_end: boundaries[n - 1].offset,
            terminal_virtual: boundaries[n - 1].address,
            etpf_offset: index_offset,
        },
        boundaries,
    ))
}

fn parse_textures(
    src: &mut Source,
    offset: u64,
    boundaries: &[Boundary],
) -> Result<(EtpfInfo, Vec<Texture>)> {
    let idx = src.read_at(offset, 16)?;
    if &idx[..4] != b"ETPF" || u32le(&idx, 4) != ETPF_VERSION {
        return Err(Error::Format("UNSUPPORTED_FORMAT: ETPF signature/version".into()));
    }
    let revision = u32le(&idx, 4);
    let count = u32le(&idx, 8);
    let raw_word = u32le(&idx, 12);
    let body_size = count as u64 * 24;
    if count > TABLE_LIMIT || offset + 16 + body_size > boundaries[0].offset {
        return Err(Error::Format("INVALID_HEADER: texture index overlaps the payload".into()));
    }
    let logical: Vec<u64> = boundaries[..boundaries.len() - 1]
        .iter()
        .map(|b| b.address)
        .collect();
    let mut textures = Vec::new();
    if count > 0 {
        let body = src.read_at(offset + 16, body_size as usize)?;
        let hash_start = count as usize * 16;
        for i in 0..count as usize {
            let a = u32le(&body, i * 16);
            let b = u32le(&body, i * 16 + 4);
            let locator = u64le(&body, i * 16 + 8);
            let identifier = u64le(&body, hash_start + i * 8);
            let address = (locator & 0x1f_ffff) * 4096 + 4096;
            let owner = logical.partition_point(|&l| l <= address);
            let owner = if owner == 0 {
                None
            } else {
                let o = owner - 1;
                if address >= boundaries[o + 1].address {
                    None
                } else {
                    Some(o)
                }
            };
            textures.push(Texture {
                texture_id: format!("{identifier:016x}"),
                width: (a & 0x3fff) + 1,
                height: ((a >> 14) & 0x3fff) + 1,
                mip_count: (a >> 28) + 1,
                array_size: ((b >> 10) & 0x3ff) + 1,
                dxgi: (b >> 3) & 127,
                tile_mode: (b >> 24) & 15,
                address,
                start_block: owner,
            });
        }
    }
    Ok((
        EtpfInfo {
            version: revision,
            descriptors: count,
            raw_header_word_12: raw_word,
        },
        textures,
    ))
}

fn classify(
    start: &Boundary,
    next: &Boundary,
    length: u64,
    extents: &Extents,
    index: usize,
    block_limit: u64,
) -> BlockRow {
    let stop = next.offset.saturating_sub(start.padding as u64);
    let packed = stop.saturating_sub(start.offset);
    let virtual_bytes = next.address.saturating_sub(start.address);
    let mut row = BlockRow {
        index,
        offset: start.offset,
        end: stop,
        virtual_addr: start.address,
        virtual_bytes,
        packed_bytes: packed,
        codec_id: start.codec_id,
        codec: codec_name(start.codec_id),
        status: String::new(),
        missing: None,
        sha256: None,
        decoded_bytes: None,
        detail: None,
    };
    if packed == 0 || virtual_bytes == 0 || stop < start.offset {
        row.status = "INVALID_BOUNDARY".into();
    } else if stop > length {
        row.status = "TRUNCATED_FILE".into();
        row.missing = Some([start.offset.max(length), stop]);
    } else if let Some(gap) = extents.first_gap(start.offset, stop) {
        row.status = "SPARSE_GAP".into();
        row.missing = Some([gap.0, gap.1]);
    } else if !matches!(start.codec_id, 0 | 0x20) {
        row.status = "UNSUPPORTED_CODEC".into();
    } else if packed.max(virtual_bytes) > block_limit {
        row.status = "BLOCK_LIMIT".into();
    } else if start.codec_id == 0 && packed != virtual_bytes {
        row.status = "CORRUPTED_CHUNK".into();
        row.detail = Some("Stored range length differs from the declared virtual length".into());
    } else if start.codec_id == 0x20 && virtual_bytes > (65536u64).max(4096 * packed) {
        row.status = "EXPANSION_LIMIT".into();
    } else {
        row.status = "AVAILABLE".into();
    }
    row
}

/// Verify one AVAILABLE block: bounded read, zlib validation, SHA-256 of output.
fn verify_block(src: &mut Source, row: &BlockRow, cancel: &Cancel) -> Result<(String, u64)> {
    use flate2::read::ZlibDecoder;
    let compressed = row.codec_id == 0x20;
    let expected = row.virtual_bytes;
    let mut remaining = row.packed_bytes;
    src.file.seek(SeekFrom::Start(row.offset))?;
    let mut packed: Vec<u8> = Vec::with_capacity(row.packed_bytes.min(BLOCK_LIMIT) as usize);
    let mut buf = vec![0u8; READ_SIZE];
    while remaining > 0 {
        if is_cancelled(cancel) {
            return Err(Error::Cancelled);
        }
        let want = remaining.min(READ_SIZE as u64) as usize;
        src.file.read_exact(&mut buf[..want])?;
        packed.extend_from_slice(&buf[..want]);
        remaining -= want as u64;
    }
    if !compressed {
        if packed.len() as u64 != expected {
            return Err(Error::Format("CORRUPTED_CHUNK: raw length mismatch".into()));
        }
        return Ok((sha256_hex(&packed), packed.len() as u64));
    }
    let mut dec = ZlibDecoder::new(std::io::Cursor::new(&packed));
    let mut out: Vec<u8> = Vec::new();
    let mut chunk = vec![0u8; READ_SIZE];
    loop {
        if is_cancelled(cancel) {
            return Err(Error::Cancelled);
        }
        let n = dec.read(&mut chunk).map_err(|e| {
            Error::Format(format!("CORRUPTED_CHUNK: zlib: {e}"))
        })?;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&chunk[..n]);
        if out.len() as u64 > expected {
            return Err(Error::Format("CORRUPTED_CHUNK: decoded stream exceeds its virtual range".into()));
        }
    }
    if dec.total_in() != packed.len() as u64 {
        return Err(Error::Format("CORRUPTED_CHUNK: bytes follow the declared zlib stream".into()));
    }
    if out.len() as u64 != expected {
        return Err(Error::Format(format!(
            "CORRUPTED_CHUNK: decoded {} of {expected} expected bytes",
            out.len()
        )));
    }
    Ok((sha256_hex(&out), out.len() as u64))
}

pub struct AnalyzeOptions {
    pub deep: bool,
    pub keep_textures: bool,
    pub block_limit: u64,
}

impl Default for AnalyzeOptions {
    fn default() -> Self {
        Self {
            deep: false,
            keep_textures: false,
            block_limit: BLOCK_LIMIT,
        }
    }
}

pub fn analyze(
    path: &Path,
    rel: &str,
    opts: &AnalyzeOptions,
    cancel: &Cancel,
    progress: &mut dyn FnMut(usize, usize),
) -> Result<Rds5Report> {
    if !(1..=BLOCK_LIMIT).contains(&opts.block_limit) {
        return Err(Error::Format("invalid block limit".into()));
    }
    let file = File::open(path)?;
    let before = file.metadata()?;
    let size = before.len();
    let (ranges, method) = allocated_ranges(&file, size);
    let extents = Extents::new(ranges);
    let allocated_bytes = extents.total();
    let mut src = Source { file, extents };

    let (header, boundaries) = parse_table(&mut src)?;
    let (etpf, textures, metadata_error) =
        match parse_textures(&mut src, header.etpf_offset, &boundaries) {
            Ok((e, t)) => (Some(e), t, None),
            Err(e) => (None, Vec::new(), Some(e.to_string())),
        };

    let total = boundaries.len() - 1;
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut rows = Vec::with_capacity(total);
    let mut verified_bytes = 0u64;
    for idx in 0..total {
        if is_cancelled(cancel) {
            return Err(Error::Cancelled);
        }
        let mut row = classify(
            &boundaries[idx],
            &boundaries[idx + 1],
            size,
            &src.extents,
            idx,
            opts.block_limit,
        );
        if row.status == "AVAILABLE" && opts.deep {
            if verified_bytes + row.virtual_bytes <= EXPORT_LIMIT {
                match verify_block(&mut src, &row, cancel) {
                    Ok((digest, count)) => {
                        row.status = "SUCCESS_VERIFIED".into();
                        row.sha256 = Some(digest);
                        row.decoded_bytes = Some(count);
                        verified_bytes += count;
                    }
                    Err(Error::Cancelled) => return Err(Error::Cancelled),
                    Err(e) => {
                        row.status = "CORRUPTED_CHUNK".into();
                        row.detail = Some(e.to_string());
                    }
                }
            } else {
                row.detail = Some("EXPORT_LIMIT".into());
            }
        }
        *counts.entry(row.status.clone()).or_insert(0) += 1;
        rows.push(row);
        if idx % 64 == 0 || idx + 1 == total {
            progress(idx + 1, total);
        }
    }

    let after = src.file.metadata()?;
    let changed = |a: &std::fs::Metadata, b: &std::fs::Metadata| {
        a.len() != b.len() || a.modified().ok() != b.modified().ok()
    };
    if changed(&before, &after) {
        return Err(Error::InputChanged);
    }

    let all_verified = counts.get("SUCCESS_VERIFIED").copied().unwrap_or(0) == total as u64;
    let status = if opts.deep && size >= header.declared_end && all_verified && metadata_error.is_none() {
        "SUCCESS_VERIFIED"
    } else {
        "SUCCESS_PARTIAL"
    };

    Ok(Rds5Report {
        schema: "xbox-inspector-rds5/1".into(),
        rel: rel.to_string(),
        file_bytes: size,
        allocated_bytes,
        allocation_method: method,
        status: status.into(),
        header,
        etpf,
        metadata_error,
        counts,
        verified_bytes,
        blocks: rows,
        textures_total: textures.len(),
        textures_sample: textures.iter().take(8).cloned().collect(),
        textures: if opts.keep_textures { Some(textures) } else { None },
    })
}

/// Prefix helper for reports.
pub fn prefix_hex_of(path: &Path) -> Result<String> {
    let mut f = File::open(path)?;
    let mut b = [0u8; 16];
    let n = f.read(&mut b)?;
    Ok(hex(&b[..n]))
}