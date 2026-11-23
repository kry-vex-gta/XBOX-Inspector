//! Inline self-tests of the indexed-range method (the 8 required ZLIB cases
//! plus interval accounting). Mirrors crates/xbs-ranges/tests/method.rs so the
//! shipped binary can prove the method on its own inputs at any time.

use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::io::Write;
use xbs_ranges::zlib::{self, ZStatus};
use xbs_report::TestResult;

fn compress(data: &[u8]) -> Vec<u8> {
    let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

fn t(name: &str, ok: bool, detail: &str) -> TestResult {
    TestResult {
        name: name.to_string(),
        passed: ok,
        detail: detail.to_string(),
    }
}

pub fn run() -> Vec<TestResult> {
    let mut v = Vec::new();
    let payload = b"the quick brown fox jumps over the lazy dog".repeat(64);
    let z = compress(&payload);
    let out = zlib::check(&z, Some(payload.len() as u64), 1 << 20);
    v.push(t(
        "zlib/normal",
        out.status == ZStatus::Ok && out.decoded.as_deref() == Some(&payload[..]),
        "обычный поток: распаковка и длина совпали",
    ));

    let z = compress(b"");
    let out = zlib::check(&z, Some(0), 1 << 20);
    v.push(t(
        "zlib/zero-output",
        out.status == ZStatus::Ok && out.decoded.as_ref().map(|d| d.len()) == Some(0),
        "нулевой выход принят",
    ));

    let mut z = compress(b"checksum will be broken");
    let n = z.len();
    z[n - 1] ^= 0xff;
    let out = zlib::check(&z, None, 1 << 20);
    v.push(t(
        "zlib/bad-adler",
        out.status == ZStatus::StreamCorrupt,
        "битая контрольная сумма отклонена",
    ));

    let z = compress(&b"truncate me please".repeat(32));
    let out = zlib::check(&z[..z.len() - 5], None, 1 << 20);
    v.push(t(
        "zlib/truncated",
        matches!(out.status, ZStatus::Truncated | ZStatus::StreamCorrupt),
        "обрезанный поток отклонён",
    ));

    let mut z = compress(b"first stream");
    z.extend_from_slice(&compress(b"second stream"));
    let out = zlib::check(&z, None, 1 << 20);
    v.push(t(
        "zlib/concatenated",
        out.status == ZStatus::TailAfterStream,
        "два сцепленных потока: хвост обнаружен",
    ));

    let z = compress(b"length mismatch");
    let out = zlib::check(&z, Some(999), 1 << 20);
    v.push(t(
        "zlib/wrong-length",
        out.status == ZStatus::LengthMismatch,
        "неверная ожидаемая длина отклонена",
    ));

    let z = compress(&vec![0u8; 1 << 16]);
    let out = zlib::check(&z, None, 1024);
    v.push(t(
        "zlib/cap",
        out.status == ZStatus::OutputCap,
        "превышение лимита расширения остановлено",
    ));

    let out = zlib::check(&[0x78, 0x20, 0, 0, 0, 0], None, 1 << 20);
    v.push(t(
        "zlib/dictionary",
        out.status == ZStatus::DictionaryRequired,
        "FDICT: требуется разрешённый словарь, поток не распакован",
    ));

    let u = xbs_core::extents::union_bytes(&[(0, 10), (5, 15), (20, 30), (29, 40)]);
    v.push(t(
        "accounting/union",
        u == 35,
        "перекрывающиеся интервалы учтены один раз (35 байт)",
    ));

    let out = zlib::check(&[0x00, 0x01, 0x02], None, 1 << 20);
    v.push(t(
        "zlib/unknown-signature",
        out.status == ZStatus::HeaderInvalid,
        "неизвестная сигнатура отклонена",
    ));
    v
}