//! Verification of exactly one declared, open RFC 1950 stream.
pub use xbs_core::zlib::{ZOutcome, ZStatus};

pub fn check(data: &[u8], expected_len: Option<u64>, cap: u64) -> ZOutcome {
    check_with_cancel(data, expected_len, cap, None)
}

pub(crate) fn check_with_cancel(
    data: &[u8],
    expected_len: Option<u64>,
    cap: u64,
    cancel: Option<&xbs_core::Cancel>,
) -> ZOutcome {
    let mut result = xbs_core::zlib::decode(data, expected_len, cap, cancel);
    if result.status == ZStatus::Ok && result.consumed != data.len() as u64 {
        result.status = ZStatus::TailAfterStream;
        result.decoded = None;
        result.detail = Some(format!(
            "{} bytes follow the zlib stream",
            data.len() as u64 - result.consumed
        ));
    }
    result
}
