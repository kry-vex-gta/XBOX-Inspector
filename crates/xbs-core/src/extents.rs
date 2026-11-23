//! Allocated-range query (Windows FSCTL_QUERY_ALLOCATED_RANGES) with a
//! regular-file fallback, mirroring the reference `file_extents.py`.

use std::fs::File;
use std::os::windows::io::AsRawHandle;

#[cfg(windows)]
pub fn allocated_ranges(file: &File, size: u64) -> (Vec<(u64, u64)>, String) {
    use windows_sys::Win32::System::Ioctl::{
        FILE_ALLOCATED_RANGE_BUFFER, FSCTL_QUERY_ALLOCATED_RANGES,
    };
    use windows_sys::Win32::System::IO::DeviceIoControl;

    if size == 0 {
        return (Vec::new(), "empty".to_string());
    }
    let handle = file.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;
    let unit = std::mem::size_of::<FILE_ALLOCATED_RANGE_BUFFER>();
    let mut input = FILE_ALLOCATED_RANGE_BUFFER {
        FileOffset: 0,
        Length: size as i64,
    };
    let mut out = vec![
        FILE_ALLOCATED_RANGE_BUFFER {
            FileOffset: 0,
            Length: 0
        };
        64
    ];
    let mut ranges: Vec<(u64, u64)> = Vec::new();
    loop {
        let mut returned = 0u32;
        let ok = unsafe {
            DeviceIoControl(
                handle,
                FSCTL_QUERY_ALLOCATED_RANGES,
                &input as *const _ as *const std::ffi::c_void,
                unit as u32,
                out.as_mut_ptr() as *mut std::ffi::c_void,
                (out.len() * unit) as u32,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            // Not supported (FAT, network, ...): treat the whole file as allocated.
            return (vec![(0, size)], "regular-file".to_string());
        }
        let n = returned as usize / unit;
        if n == 0 {
            break;
        }
        for r in &out[..n] {
            let start = r.FileOffset as u64;
            let end = start + r.Length as u64;
            ranges.push((start, end.min(size)));
        }
        if n < out.len() {
            break;
        }
        let last = out[n - 1];
        input.FileOffset = last.FileOffset + last.Length;
        input.Length = size as i64 - input.FileOffset;
        if input.Length <= 0 {
            break;
        }
    }
    if ranges.is_empty() {
        return (vec![(0, size)], "regular-file".to_string());
    }
    (ranges, "fsctl-query-allocated-ranges".to_string())
}

#[cfg(not(windows))]
pub fn allocated_ranges(_file: &File, size: u64) -> (Vec<(u64, u64)>, String) {
    if size == 0 {
        (Vec::new(), "empty".to_string())
    } else {
        (vec![(0, size)], "regular-file".to_string())
    }
}

/// Sorted disjoint extents; helpers for gap detection (port of `Extents`).
pub struct Extents {
    pub ranges: Vec<(u64, u64)>,
    ends: Vec<u64>,
}

impl Extents {
    pub fn new(mut ranges: Vec<(u64, u64)>) -> Self {
        ranges.sort_unstable();
        let ends = ranges.iter().map(|r| r.1).collect();
        Self { ranges, ends }
    }

    pub fn total(&self) -> u64 {
        self.ranges.iter().map(|(a, b)| b - a).sum()
    }

    /// First uncovered sub-range of [start, stop), or None when fully covered.
    pub fn first_gap(&self, start: u64, stop: u64) -> Option<(u64, u64)> {
        if stop <= start {
            return None;
        }
        let idx = self.ends.partition_point(|&e| e <= start);
        if idx == self.ranges.len() {
            return Some((start, stop));
        }
        let (first, end) = self.ranges[idx];
        if start < first {
            return Some((start, stop.min(first)));
        }
        if stop > end {
            let following = self
                .ranges
                .get(idx + 1)
                .map(|r| r.0)
                .unwrap_or(stop);
            return Some((end, stop.min(following)));
        }
        None
    }
}

/// Union length of possibly overlapping intervals.
pub fn union_bytes(ranges: &[(u64, u64)]) -> u64 {
    let mut v: Vec<(u64, u64)> = ranges.iter().copied().filter(|(a, b)| b > a).collect();
    v.sort_unstable();
    let mut total = 0u64;
    let mut cur: Option<(u64, u64)> = None;
    for (a, b) in v {
        match cur {
            None => cur = Some((a, b)),
            Some((cs, ce)) if a <= ce => cur = Some((cs, ce.max(b))),
            Some((cs, ce)) => {
                total += ce - cs;
                cur = Some((a, b));
            }
        }
    }
    if let Some((cs, ce)) = cur {
        total += ce - cs;
    }
    total
}