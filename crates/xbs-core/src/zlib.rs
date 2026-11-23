//! Bounded RFC 1950 decoding for declared open inputs. StreamEnd also
//! establishes that the zlib implementation accepted the Adler-32 trailer.
use crate::{is_cancelled, Cancel};
use flate2::{Decompress, FlushDecompress, Status};
use std::io::BufRead;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZStatus {
    Ok,
    HeaderInvalid,
    DictionaryRequired,
    Truncated,
    StreamCorrupt,
    TailAfterStream,
    LengthMismatch,
    OutputCap,
    Cancelled,
}

#[derive(Debug, Clone)]
pub struct ZOutcome {
    pub status: ZStatus,
    pub decoded: Option<Vec<u8>>,
    pub consumed: u64,
    pub detail: Option<String>,
}

pub fn decode(
    mut input: impl BufRead,
    expected_len: Option<u64>,
    cap: u64,
    cancel: Option<&Cancel>,
) -> ZOutcome {
    let mut decoder = Decompress::new(true);
    let fail = |status, consumed, detail: &str| ZOutcome {
        status,
        decoded: None,
        consumed,
        detail: Some(detail.to_string()),
    };
    let mut output = Vec::new();
    let mut buffer = [0u8; 64 << 10];
    loop {
        let consumed = decoder.total_in();
        if cancel.is_some_and(is_cancelled) {
            return fail(ZStatus::Cancelled, consumed, "cancelled");
        }
        let available = match input.fill_buf() {
            Ok(bytes) => bytes,
            Err(e) => return fail(ZStatus::StreamCorrupt, consumed, &e.to_string()),
        };
        if consumed == 0 {
            let [cmf, flags, ..] = available else {
                return fail(ZStatus::HeaderInvalid, 0, "incomplete zlib header");
            };
            if cmf & 15 != 8
                || cmf >> 4 > 7
                || (u16::from(*cmf) * 256 + u16::from(*flags)) % 31 != 0
            {
                return fail(ZStatus::HeaderInvalid, 0, "invalid zlib header");
            }
            if flags & 0x20 != 0 {
                return fail(
                    ZStatus::DictionaryRequired,
                    0,
                    "zlib preset dictionary required",
                );
            }
        }
        let was_empty = available.is_empty();
        let written = decoder.total_out();
        let state = match decoder.decompress(available, &mut buffer, FlushDecompress::None) {
            Ok(s) => s,
            Err(e) => return fail(ZStatus::StreamCorrupt, decoder.total_in(), &e.to_string()),
        };
        let used = (decoder.total_in() - consumed) as usize;
        let produced = (decoder.total_out() - written) as usize;
        input.consume(used);
        if decoder.total_out() > cap {
            return fail(
                ZStatus::OutputCap,
                decoder.total_in(),
                "decoded byte budget exceeded",
            );
        }
        if expected_len.is_some_and(|len| decoder.total_out() > len) {
            return fail(
                ZStatus::LengthMismatch,
                decoder.total_in(),
                "output exceeds expected length",
            );
        }
        output.extend_from_slice(&buffer[..produced]);
        if state == Status::StreamEnd {
            if expected_len.is_some_and(|len| len != decoder.total_out()) {
                return fail(
                    ZStatus::LengthMismatch,
                    decoder.total_in(),
                    "decoded length differs",
                );
            }
            return ZOutcome {
                status: ZStatus::Ok,
                decoded: Some(output),
                consumed: decoder.total_in(),
                detail: None,
            };
        }
        if used == 0 && produced == 0 {
            let status = if was_empty {
                ZStatus::Truncated
            } else {
                ZStatus::StreamCorrupt
            };
            return fail(status, consumed, "zlib stream has no validated end");
        }
    }
}
