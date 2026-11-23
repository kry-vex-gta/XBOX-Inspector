//! Open KB2j/KB2n Bink records inside RPF9 payloads (port of `rpf9_video.py`).

use crate::extents::Extents;
use crate::hash::sha256_hex;
use crate::{is_cancelled, Cancel, Error, Result};
use serde::Serialize;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

const CHUNK: u64 = 8 << 20;
pub const ALIGNMENT: u64 = 4096;
const HEADER_SIZE: u64 = 48; // 4s11I

#[derive(Debug, Clone, Serialize)]
pub struct AudioTrack {
    pub sample_rate: u16,
    pub flags: u16,
    pub track_id: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct BinkRecord {
    pub offset: u64,
    pub size: u64,
    pub revision: String,
    pub width: u32,
    pub height: u32,
    pub frames: u32,
    pub fps: [u32; 2],
    pub seconds: f64,
    pub flags: u32,
    pub largest_frame: u32,
    pub audio_tracks: Vec<AudioTrack>,
    pub index_end: u64,
    pub header_and_index_sha256: String,
    pub nonempty_audio_packets: u64,
    pub status: String,
}

fn read_at(f: &mut File, offset: u64, count: usize) -> Result<Vec<u8>> {
    f.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; count];
    f.read_exact(&mut buf)
        .map_err(|_| Error::Format("short read while checking a Bink record".into()))?;
    Ok(buf)
}

fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

/// Inspect one record at `offset` bounded by `upper` (end of allocated extent).
pub fn inspect(f: &mut File, offset: u64, upper: u64, check_audio: bool) -> Result<BinkRecord> {
    if upper - offset < HEADER_SIZE {
        return Err(Error::Format("incomplete Bink header".into()));
    }
    let raw = read_at(f, offset, HEADER_SIZE as usize)?;
    let magic = &raw[..4];
    if magic != b"KB2j" && magic != b"KB2n" {
        return Err(Error::Format("not a Bink record".into()));
    }
    let stored_minus_eight = u32le(&raw, 4) as u64;
    let frames = u32le(&raw, 8);
    let largest = u32le(&raw, 12);
    let repeat = u32le(&raw, 16);
    let width = u32le(&raw, 20);
    let height = u32le(&raw, 24);
    let fps_num = u32le(&raw, 28);
    let fps_den = u32le(&raw, 32);
    let flags = u32le(&raw, 36);
    let tracks = u32le(&raw, 40);
    let size = stored_minus_eight + 8;
    let index_start = HEADER_SIZE + 12 * tracks as u64;
    let index_end = index_start + 4 * (frames as u64 + 1);
    if !(0 < frames && frames == repeat && frames <= 1_000_000)
        || !(0 < width && width <= 7680)
        || !(0 < height && height <= 4800)
        || fps_num == 0
        || fps_den == 0
        || !(0 < largest && largest as u64 <= size)
        || tracks > 256
        || index_end + frames as u64 * (4 * tracks as u64 + 1) > size
    {
        return Err(Error::Format("unsupported or invalid Bink header fields".into()));
    }
    if offset + size > upper {
        return Err(Error::Format(format!(
            "TRUNCATED_OR_UNALLOCATED: record [{offset}, {}) beyond readable end {upper}",
            offset + size
        )));
    }
    let hi = read_at(f, offset, index_end as usize)?;
    if hi[..HEADER_SIZE as usize] != raw[..] {
        return Err(Error::InputChanged);
    }
    let starts: Vec<u64> = (0..=frames as usize)
        .map(|i| (u32le(&hi, index_start as usize + i * 4) & !1) as u64)
        .collect();
    if starts[0] != index_end
        || u32le(&hi, index_end as usize - 4) as u64 != size
        || starts.windows(2).any(|w| w[1] <= w[0] || w[1] - w[0] > largest as u64)
    {
        return Err(Error::Format("Bink frame table has invalid boundaries".into()));
    }
    let mut audio = Vec::new();
    for t in 0..tracks as usize {
        let rate = u16::from_le_bytes(
            hi[HEADER_SIZE as usize + 4 * (tracks as usize + t)..][..2]
                .try_into()
                .unwrap(),
        );
        let tflags = u16::from_le_bytes(
            hi[HEADER_SIZE as usize + 4 * (tracks as usize + t) + 2..][..2]
                .try_into()
                .unwrap(),
        );
        let track_id = u32le(&hi, HEADER_SIZE as usize + 4 * (2 * tracks as usize + t));
        audio.push(AudioTrack {
            sample_rate: rate,
            flags: tflags,
            track_id,
        });
    }
    let mut packets = 0u64;
    if check_audio && tracks > 0 {
        for i in 0..frames as usize {
            let mut pos = offset + starts[i];
            let frame_end = offset + starts[i + 1];
            for _ in 0..tracks {
                if pos + 4 >= frame_end {
                    return Err(Error::Format("Bink audio length missing from its frame".into()));
                }
                let lb = read_at(f, pos, 4)?;
                let length = u32le(&lb, 0) as u64;
                pos += 4 + length;
                if pos >= frame_end {
                    return Err(Error::Format("Bink audio packet overlaps frame end".into()));
                }
                packets += u64::from(length != 0);
            }
        }
    }
    Ok(BinkRecord {
        offset,
        size,
        revision: String::from_utf8_lossy(magic).to_string(),
        width,
        height,
        frames,
        fps: [fps_num, fps_den],
        seconds: frames as f64 * fps_den as f64 / fps_num as f64,
        flags,
        largest_frame: largest,
        audio_tracks: audio,
        index_end,
        header_and_index_sha256: sha256_hex(&hi),
        nonempty_audio_packets: packets,
        status: if check_audio {
            "VIDEO_LAYOUT_VERIFIED".into()
        } else {
            "VIDEO_HEADER_VERIFIED".into()
        },
    })
}

#[derive(Debug, Clone, Serialize)]
pub struct BinkScan {
    pub videos: Vec<BinkRecord>,
    pub incomplete: Vec<String>,
    pub invalid_candidates: u64,
    pub scanned_payload_bytes: u64,
}

/// Scan allocated extents (already clipped to >= catalog end, 4096-aligned).
pub fn scan(
    f: &mut File,
    extents: &[(u64, u64)],
    cancel: &Cancel,
    progress: &mut dyn FnMut(u64, u64),
) -> Result<BinkScan> {
    let total: u64 = extents.iter().map(|(a, b)| b - a).sum();
    let mut out = BinkScan {
        videos: Vec::new(),
        incomplete: Vec::new(),
        invalid_candidates: 0,
        scanned_payload_bytes: 0,
    };
    let mut next_free = 0u64;
    let mut buf = vec![0u8; CHUNK as usize];
    for &(start, end) in extents {
        let mut cursor = start;
        while cursor < end {
            if is_cancelled(cancel) {
                return Err(Error::Cancelled);
            }
            let want = (end - cursor).min(CHUNK) as usize;
            f.seek(SeekFrom::Start(cursor))?;
            f.read_exact(&mut buf[..want])?;
            let mut i = 0usize;
            while i + 4 <= want {
                if &buf[i..i + 4] == b"KB2j" || &buf[i..i + 4] == b"KB2n" {
                    let offset = cursor + i as u64;
                    if offset % ALIGNMENT == 0 && offset >= next_free {
                        match inspect(f, offset, end, false) {
                            Ok(rec) => {
                                next_free = offset + rec.size;
                                out.videos.push(rec);
                            }
                            Err(e) => {
                                let msg = e.to_string();
                                if msg.contains("TRUNCATED_OR_UNALLOCATED") {
                                    out.incomplete.push(format!("{offset}: {msg}"));
                                } else {
                                    out.invalid_candidates += 1;
                                }
                            }
                        }
                    }
                }
                i += 1;
            }
            cursor += want as u64;
            out.scanned_payload_bytes += want as u64;
            progress(out.scanned_payload_bytes, total);
        }
    }
    Ok(out)
}

/// Clip allocated ranges to the payload area after the candidate catalog end.
pub fn payload_extents(allocated: &[(u64, u64)], lower: u64) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    for &(start, end) in allocated {
        let aligned = (start.max(lower) + ALIGNMENT - 1) & !(ALIGNMENT - 1);
        if aligned < end {
            out.push((aligned, end));
        }
    }
    out
}

pub fn extents_of(allocated: Vec<(u64, u64)>) -> Extents {
    Extents::new(allocated)
}