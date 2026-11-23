//! XBOX-Inspector core: read-only inventory, format parsers, preflight.
//! Ported from the SimuXBOX 0.1.0 Python reference (MIT), independently rewritten in Rust.

pub mod bink;
pub mod config;
pub mod extents;
pub mod formats;
pub mod hash;
pub mod inventory;
pub mod pe;
pub mod preflight;
pub mod rds5;
pub mod rpf9;
pub mod safe_path;
pub mod scan;
pub mod zlib;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub type Cancel = Arc<AtomicBool>;

pub fn new_cancel() -> Cancel {
    Arc::new(AtomicBool::new(false))
}

pub fn is_cancelled(c: &Cancel) -> bool {
    c.load(Ordering::Relaxed)
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Format(String),
    Cancelled,
    InputChanged,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "io: {e}"),
            Error::Format(s) => write!(f, "format: {s}"),
            Error::Cancelled => write!(f, "cancelled"),
            Error::InputChanged => write!(f, "input changed during analysis"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

pub fn fmt_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.2} {} ({n} B)", UNITS[u])
    }
}
