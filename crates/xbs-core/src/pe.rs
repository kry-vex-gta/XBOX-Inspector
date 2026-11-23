//! Bounded PE intake (port of `pe_intake.py`): headers, sections, imports.
//! Reads only the ranges required; never executes anything.

use crate::formats::FileKind;
use crate::{Error, Result};
use serde::Serialize;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

#[derive(Debug, Clone, Serialize)]
pub struct PeSection {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub raw_size: u32,
    pub raw_ptr: u32,
    pub characteristics: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct PeInfo {
    pub machine: u16,
    pub is_dll: bool,
    pub has_exec_section: bool,
    pub entry_in_executable_section: bool,
    pub entry_rva: u32,
    pub subsystem: u16,
    pub timestamp: u32,
    pub image_base: u64,
    pub size_of_image: u32,
    pub characteristics: u16,
    pub sections: Vec<PeSection>,
    pub imports: Vec<String>,
}

fn read_at(f: &mut File, off: u64, buf: &mut [u8]) -> Result<()> {
    f.seek(SeekFrom::Start(off))?;
    let mut got = 0;
    while got < buf.len() {
        let n = f.read(&mut buf[got..])?;
        if n == 0 {
            return Err(Error::Format("TRUNCATED_FILE: short PE read".into()));
        }
        got += n;
    }
    Ok(())
}

fn u16le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes(b[o..o + 2].try_into().unwrap())
}
fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

/// Cheap classification for inventory: DLL flag, entry point, executable sections.
pub fn quick_classify(path: &Path) -> Result<FileKind> {
    let mut f = File::open(path)?;
    let mut dos = [0u8; 64];
    read_at(&mut f, 0, &mut dos)?;
    if &dos[..2] != b"MZ" {
        return Ok(FileKind::Unknown);
    }
    let lf = u32le(&dos, 0x3c) as u64;
    if lf == 0 || lf > 1 << 20 {
        return Ok(FileKind::PeNoEntry);
    }
    let mut nt = [0u8; 24];
    read_at(&mut f, lf, &mut nt)?;
    if &nt[..4] != b"PE\0\0" {
        return Ok(FileKind::PeNoEntry);
    }
    let chars = u16le(&nt, 22);
    let nsec = u16le(&nt, 6) as usize;
    let opt_size = u16le(&nt, 20) as u64;
    let mut opt = vec![0u8; opt_size.min(512) as usize];
    read_at(&mut f, lf + 24, &mut opt)?;
    let magic = if opt.len() >= 2 { u16le(&opt, 0) } else { 0 };
    let entry = if opt.len() >= 20 { u32le(&opt, 16) } else { 0 };
    let mut exec = false;
    if nsec <= 96 {
        let mut sec = vec![0u8; nsec * 40];
        read_at(&mut f, lf + 24 + opt_size, &mut sec)?;
        for i in 0..nsec {
            let c = u32le(&sec, i * 40 + 36);
            if c & 0x2000_0000 != 0 {
                exec = true;
            }
        }
    }
    let _ = magic;
    if chars & 0x2000 != 0 {
        Ok(FileKind::PeDll)
    } else if entry == 0 || !exec {
        Ok(FileKind::PeNoEntry)
    } else {
        Ok(FileKind::PeExecutable)
    }
}

pub fn parse(path: &Path) -> Result<PeInfo> {
    let mut f = File::open(path)?;
    let file_len = f.metadata()?.len();
    let mut dos = [0u8; 64];
    read_at(&mut f, 0, &mut dos)?;
    if &dos[..2] != b"MZ" {
        return Err(Error::Format("MZ signature absent".into()));
    }
    let lf = u32le(&dos, 0x3c) as u64;
    if lf == 0 || lf + 24 > file_len {
        return Err(Error::Format("invalid e_lfanew".into()));
    }
    let mut nt = [0u8; 24];
    read_at(&mut f, lf, &mut nt)?;
    if &nt[..4] != b"PE\0\0" {
        return Err(Error::Format("PE signature absent".into()));
    }
    let machine = u16le(&nt, 4);
    let nsec = u16le(&nt, 6) as usize;
    let timestamp = u32le(&nt, 8);
    let opt_size = u16le(&nt, 20) as u64;
    let characteristics = u16le(&nt, 22);
    if nsec > 96 || opt_size > 1024 {
        return Err(Error::Format("unreasonable PE counts".into()));
    }
    let mut opt = vec![0u8; opt_size as usize];
    read_at(&mut f, lf + 24, &mut opt)?;
    let magic = match opt.get(..2) {
        Some([0x0b, 0x01]) if opt.len() >= 96 => 0x10b,
        Some([0x0b, 0x02]) if opt.len() >= 112 => 0x20b,
        _ => {
            return Err(Error::Format(
                "unsupported or truncated PE optional header".into(),
            ))
        }
    };
    let pe32plus = magic == 0x20b;
    let entry_rva = u32le(&opt, 16);
    let (image_base, size_of_image, subsystem, dd_offset) = if pe32plus {
        (
            u64::from_le_bytes(opt[24..32].try_into().unwrap()),
            u32le(&opt, 56),
            u16le(&opt, 68),
            112usize,
        )
    } else {
        (
            u32le(&opt, 28) as u64,
            u32le(&opt, 56),
            u16le(&opt, 68),
            96usize,
        )
    };
    let mut sections = Vec::with_capacity(nsec);
    let mut sec = vec![0u8; nsec * 40];
    read_at(&mut f, lf + 24 + opt_size, &mut sec)?;
    for i in 0..nsec {
        let b = &sec[i * 40..(i + 1) * 40];
        let name = String::from_utf8_lossy(&b[..8])
            .trim_end_matches('\0')
            .to_string();
        sections.push(PeSection {
            name,
            virtual_size: u32le(b, 8),
            virtual_address: u32le(b, 12),
            raw_size: u32le(b, 16),
            raw_ptr: u32le(b, 20),
            characteristics: u32le(b, 36),
        });
    }
    let has_exec_section = sections
        .iter()
        .any(|s| s.characteristics & 0x2000_0000 != 0);
    let entry_in_executable_section = entry_rva != 0
        && sections.iter().any(|s| {
            s.characteristics & 0x2000_0000 != 0
                && entry_rva
                    .checked_sub(s.virtual_address)
                    .is_some_and(|delta| {
                        delta < s.raw_size && u64::from(s.raw_ptr) + u64::from(delta) < file_len
                    })
        });

    // Import table (data directory 1), bounded.
    let mut imports = Vec::new();
    if dd_offset + 16 <= opt.len() {
        let imp_rva = u32le(&opt, dd_offset + 8);
        let imp_size = u32le(&opt, dd_offset + 12);
        if imp_rva != 0 && imp_size != 0 {
            if let Some(off) = rva_to_offset(imp_rva, &sections) {
                let count = ((imp_size / 20).min(256)) as usize;
                let mut desc = vec![0u8; count * 20];
                if read_at(&mut f, off, &mut desc).is_ok() {
                    for i in 0..count {
                        let name_rva = u32le(&desc, i * 20 + 12);
                        if name_rva == 0 {
                            break;
                        }
                        if let Some(no) = rva_to_offset(name_rva, &sections) {
                            let mut nb = [0u8; 256];
                            if read_at(&mut f, no, &mut nb).is_ok() {
                                let end = nb.iter().position(|&c| c == 0).unwrap_or(256);
                                let name = String::from_utf8_lossy(&nb[..end]).to_string();
                                if !name.is_empty() {
                                    imports.push(name);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(PeInfo {
        machine,
        is_dll: characteristics & 0x2000 != 0,
        has_exec_section,
        entry_in_executable_section,
        entry_rva,
        subsystem,
        timestamp,
        image_base,
        size_of_image,
        characteristics,
        sections,
        imports,
    })
}

pub fn rva_to_offset(rva: u32, sections: &[PeSection]) -> Option<u64> {
    for s in sections {
        if let Some(delta) = rva.checked_sub(s.virtual_address) {
            if delta < s.raw_size {
                return Some(s.raw_ptr as u64 + delta as u64);
            }
        }
    }
    None
}
