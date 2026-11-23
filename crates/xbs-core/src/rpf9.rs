//! Observed RPF9 header profile (port of `rpf9.py` / RPF9_SPEC.md).
//! No open catalog schema is claimed: status stays ENCRYPTED_OR_UNRESOLVED.

use crate::hash::sha256_hex;
use crate::{Error, Result};
use serde::Serialize;
use std::fs::File;
use std::io::Read;
use std::path::Path;

pub const PROFILE: &str = "9FPR/64";

#[derive(Debug, Clone, Serialize)]
pub struct Rpf9Report {
    pub schema: String,
    pub rel: String,
    pub file_size: u64,
    pub header_sha256: String,
    pub profile: String,
    pub word_04: u32,
    pub word_08: u32,
    pub word_0c: u32,
    pub word_18: u32,
    pub word_1c: u32,
    pub variant_2c_hex: String,
    /// Candidate catalog region [64, word_04) — a hypothesis, not a parsed table.
    pub catalog_region: Option<[u64; 2]>,
    pub status: String,
}

pub fn inspect(path: &Path, rel: &str, size: u64) -> Result<Rpf9Report> {
    let mut header = [0u8; 64];
    let n = {
        let mut f = File::open(path)?;
        f.read(&mut header)?
    };
    if n < 64 {
        return Err(Error::Format("TRUNCATED_FILE: header shorter than 64 bytes".into()));
    }
    if &header[..4] != b"9FPR" {
        return Err(Error::Format("UNSUPPORTED_FORMAT: 9FPR signature absent".into()));
    }
    let w = |off: usize| u32::from_le_bytes(header[off..off + 4].try_into().unwrap());
    let word_04 = w(4);
    let region_ok = word_04 > 64 && (word_04 as u64) < size && word_04 % 16 == 0;
    Ok(Rpf9Report {
        schema: "xbox-inspector-rpf9/1".into(),
        rel: rel.to_string(),
        file_size: size,
        header_sha256: sha256_hex(&header),
        profile: PROFILE.into(),
        word_04,
        word_08: w(8),
        word_0c: w(0x0c),
        word_18: w(0x18),
        word_1c: w(0x1c),
        variant_2c_hex: crate::hash::hex(&header[0x2c..0x30]),
        catalog_region: if region_ok {
            Some([64, word_04 as u64])
        } else {
            None
        },
        status: if region_ok {
            "ENCRYPTED_OR_UNRESOLVED".into()
        } else {
            "INVALID_HEADER".into()
        },
    })
}