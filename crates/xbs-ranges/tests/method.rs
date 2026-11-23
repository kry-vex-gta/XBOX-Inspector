//! Method self-tests on self-created inputs (spec: 8 ZLIB tests + acceptance).

use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::io::Write;
use xbs_ranges::zlib::{self, ZStatus};
use xbs_ranges::*;

fn compress(data: &[u8]) -> Vec<u8> {
    let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

// --- the 8 required ZLIB tests ---

#[test]
fn t1_normal_stream() {
    let payload = b"the quick brown fox jumps over the lazy dog".repeat(64);
    let z = compress(&payload);
    let out = zlib::check(&z, Some(payload.len() as u64), 1 << 20);
    assert_eq!(out.status, ZStatus::Ok);
    assert_eq!(out.decoded.unwrap(), payload);
}

#[test]
fn t2_zero_output() {
    let z = compress(b"");
    let out = zlib::check(&z, Some(0), 1 << 20);
    assert_eq!(out.status, ZStatus::Ok);
    assert_eq!(out.decoded.unwrap().len(), 0);
}

#[test]
fn t3_bad_checksum() {
    let mut z = compress(b"checksum will be broken");
    let n = z.len();
    z[n - 1] ^= 0xff; // corrupt Adler-32
    let out = zlib::check(&z, None, 1 << 20);
    assert_eq!(out.status, ZStatus::StreamCorrupt);
}

#[test]
fn t4_truncated_stream() {
    let z = compress(&b"truncate me please".repeat(32));
    let cut = &z[..z.len() - 5];
    let out = zlib::check(cut, None, 1 << 20);
    assert!(matches!(out.status, ZStatus::Truncated | ZStatus::StreamCorrupt));
}

#[test]
fn t5_two_concatenated_streams() {
    let mut z = compress(b"first stream");
    z.extend_from_slice(&compress(b"second stream"));
    let out = zlib::check(&z, None, 1 << 20);
    assert_eq!(out.status, ZStatus::TailAfterStream);
}

#[test]
fn t6_wrong_expected_length() {
    let z = compress(b"length mismatch");
    let out = zlib::check(&z, Some(999), 1 << 20);
    assert_eq!(out.status, ZStatus::LengthMismatch);
}

#[test]
fn t7_output_cap_exceeded() {
    let z = compress(&vec![0u8; 1 << 16]);
    let out = zlib::check(&z, None, 1024);
    assert_eq!(out.status, ZStatus::OutputCap);
}

#[test]
fn t8_dictionary_required() {
    // 0x78 0x20: CM=8, CINFO=7, FCHECK valid, FDICT set.
    let out = zlib::check(&[0x78, 0x20, 0x00, 0x00, 0x00, 0x00], None, 1 << 20);
    assert_eq!(out.status, ZStatus::DictionaryRequired);
}

// --- interval accounting ---

#[test]
fn union_overlaps_counted_once() {
    let u = xbs_core::extents::union_bytes(&[(0, 10), (5, 15), (20, 30), (29, 40)]);
    assert_eq!(u, 15 + 20);
    assert_eq!(xbs_core::extents::union_bytes(&[]), 0);
    assert_eq!(xbs_core::extents::union_bytes(&[(7, 7)]), 0);
}

// --- end-to-end index verification on own files ---

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("xbs-test-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn make_index(path: &std::path::Path, entries: Vec<Entry>) -> RangeIndex {
    RangeIndex {
        schema: INDEX_SCHEMA.into(),
        source_path: path.to_string_lossy().to_string(),
        source_size: std::fs::metadata(path).unwrap().len(),
        source_sha256: None,
        entries,
    }
}

#[test]
fn raw_hash_match_and_mismatch() {
    let d = temp_dir("raw");
    let p = d.join("source.bin");
    let payload = b"open range payload".to_vec();
    std::fs::write(&p, &payload).unwrap();
    let good = xbs_core::hash::sha256_hex(&payload);
    let idx = make_index(&p, vec![
        Entry { id: "good".into(), offset: 0, stored_len: payload.len() as u64,
                expected_len: None, sha256: Some(good), encoding: Encoding::Raw, kind: "test".into() },
        Entry { id: "bad".into(), offset: 0, stored_len: payload.len() as u64,
                expected_len: None, sha256: Some("0".repeat(64)), encoding: Encoding::Raw, kind: "test".into() },
    ]);
    let rep = verify_index(&idx, &p, &VerifyOptions::default(), &xbs_core::new_cancel(), &mut |_, _, _| {}).unwrap();
    assert_eq!(rep.entries[0].status, Status::VerifiedHash);
    assert_eq!(rep.entries[1].status, Status::FailedHash);
    assert_eq!(rep.coverage_bytes, payload.len() as u64); // overlap counted once
    std::fs::remove_dir_all(&d).ok();
}

#[test]
fn bounds_truncation_and_overflow() {
    let d = temp_dir("bounds");
    let p = d.join("small.bin");
    std::fs::write(&p, b"0123456789").unwrap();
    let idx = make_index(&p, vec![
        Entry { id: "past-eof".into(), offset: 8, stored_len: 10, expected_len: None,
                sha256: None, encoding: Encoding::Raw, kind: "test".into() },
        Entry { id: "overflow".into(), offset: u64::MAX - 1, stored_len: 10, expected_len: None,
                sha256: None, encoding: Encoding::Raw, kind: "test".into() },
        Entry { id: "zero".into(), offset: 0, stored_len: 0, expected_len: None,
                sha256: None, encoding: Encoding::Raw, kind: "test".into() },
    ]);
    let rep = verify_index(&idx, &p, &VerifyOptions::default(), &xbs_core::new_cancel(), &mut |_, _, _| {}).unwrap();
    assert_eq!(rep.entries[0].status, Status::TruncatedFile);
    assert_eq!(rep.entries[1].status, Status::FailedBounds);
    assert_eq!(rep.entries[2].status, Status::FailedBounds);
    assert_eq!(rep.coverage_bytes, 0);
    std::fs::remove_dir_all(&d).ok();
}

#[test]
fn zlib_member_in_index_roundtrip() {
    let d = temp_dir("zmember");
    let p = d.join("container.bin");
    let inner = b"RBF0 pretend resource body".repeat(100);
    let z = compress(&inner);
    let mut file = vec![0u8; 64]; // pretend catalog area
    let offset = file.len() as u64;
    file.extend_from_slice(&z);
    file.extend_from_slice(&[0u8; 16]);
    std::fs::write(&p, &file).unwrap();
    let idx = make_index(&p, vec![Entry {
        id: "member-0".into(), offset, stored_len: z.len() as u64,
        expected_len: Some(inner.len() as u64),
        sha256: Some(xbs_core::hash::sha256_hex(&inner)),
        encoding: Encoding::Zlib, kind: "RBF".into(),
    }]);
    let rep = verify_index(&idx, &p, &VerifyOptions::default(), &xbs_core::new_cancel(), &mut |_, _, _| {}).unwrap();
    assert_eq!(rep.entries[0].status, Status::VerifiedHash);
    assert_eq!(rep.entries[0].decoded_len, Some(inner.len() as u64));
    std::fs::remove_dir_all(&d).ok();
}

#[test]
fn nested_container_two_stage() {
    // A zlib stream whose decoded output is itself a zlib stream.
    let innermost = b"nested payload";
    let stage1 = compress(innermost);
    let stage2 = compress(&stage1);
    let out = zlib::check(&stage2, Some(stage1.len() as u64), 1 << 20);
    assert_eq!(out.status, ZStatus::Ok);
    let mid = out.decoded.unwrap();
    let out2 = zlib::check(&mid, Some(innermost.len() as u64), 1 << 20);
    assert_eq!(out2.status, ZStatus::Ok);
    assert_eq!(out2.decoded.unwrap(), innermost);
}

#[test]
fn unknown_signature_rejected() {
    let out = zlib::check(&[0x00, 0x01, 0x02, 0x03], None, 1 << 20);
    assert_eq!(out.status, ZStatus::HeaderInvalid);
    let out = zlib::check(&[0x78], None, 1 << 20);
    assert_eq!(out.status, ZStatus::HeaderInvalid);
}

#[test]
fn cyrillic_and_spaces_path() {
    let d = temp_dir("кириллица пробел");
    let sub = d.join("тест папка");
    std::fs::create_dir_all(&sub).unwrap();
    let p = sub.join("архив источник.bin");
    let payload = "проверка пути".as_bytes().to_vec();
    std::fs::write(&p, &payload).unwrap();
    let idx = make_index(&p, vec![Entry {
        id: "cyr".into(), offset: 0, stored_len: payload.len() as u64,
        expected_len: None, sha256: Some(xbs_core::hash::sha256_hex(&payload)),
        encoding: Encoding::Raw, kind: "test".into(),
    }]);
    let rep = verify_index(&idx, &p, &VerifyOptions::default(), &xbs_core::new_cancel(), &mut |_, _, _| {}).unwrap();
    assert_eq!(rep.entries[0].status, Status::VerifiedHash);
    std::fs::remove_dir_all(&d).ok();
}

#[test]
fn cancel_stops_and_rerun_works() {
    let d = temp_dir("cancel");
    let p = d.join("c.bin");
    std::fs::write(&p, b"abcdef").unwrap();
    let idx = make_index(&p, vec![Entry {
        id: "x".into(), offset: 0, stored_len: 6, expected_len: None,
        sha256: Some(xbs_core::hash::sha256_hex(b"abcdef")), encoding: Encoding::Raw, kind: "t".into(),
    }]);
    let cancel = xbs_core::new_cancel();
    cancel.store(true, std::sync::atomic::Ordering::Relaxed);
    let rep = verify_index(&idx, &p, &VerifyOptions::default(), &cancel, &mut |_, _, _| {}).unwrap();
    assert_eq!(rep.entries[0].status, Status::Cancelled);
    // rerun after the cancelled pass, on the unchanged source
    let cancel2 = xbs_core::new_cancel();
    let rep2 = verify_index(&idx, &p, &VerifyOptions::default(), &cancel2, &mut |_, _, _| {}).unwrap();
    assert_eq!(rep2.entries[0].status, Status::VerifiedHash);
    std::fs::remove_dir_all(&d).ok();
}

#[test]
fn identity_mismatch_blocks_entries() {
    let d = temp_dir("identity");
    let p = d.join("i.bin");
    std::fs::write(&p, b"12345").unwrap();
    let mut idx = make_index(&p, vec![Entry {
        id: "x".into(), offset: 0, stored_len: 5, expected_len: None,
        sha256: None, encoding: Encoding::Raw, kind: "t".into(),
    }]);
    idx.source_size = 999; // wrong snapshot size
    let rep = verify_index(&idx, &p, &VerifyOptions::default(), &xbs_core::new_cancel(), &mut |_, _, _| {}).unwrap();
    assert_eq!(rep.entries[0].status, Status::IdentityMismatch);
    std::fs::remove_dir_all(&d).ok();
}

#[test]
fn missing_source_file_is_io_error() {
    let idx = RangeIndex {
        schema: INDEX_SCHEMA.into(),
        source_path: "nope.bin".into(),
        source_size: 1,
        source_sha256: None,
        entries: vec![],
    };
    let r = verify_index(&idx, std::path::Path::new("nope.bin"), &VerifyOptions::default(), &xbs_core::new_cancel(), &mut |_, _, _| {});
    assert!(r.is_err());
}