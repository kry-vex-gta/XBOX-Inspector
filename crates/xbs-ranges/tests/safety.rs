//! Negative tests: index paths must stay inside the selected root (spec 14/16/17/19).

use xbs_core::safe_path::{find_case_duplicates, resolve_within};
use xbs_ranges::{validate_index_structure, Encoding, Entry, RangeIndex, INDEX_SCHEMA};

fn temp_root(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("xbs-safety-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn entry(id: &str, offset: u64, len: u64) -> Entry {
    Entry {
        id: id.into(),
        offset,
        stored_len: len,
        expected_len: None,
        sha256: None,
        encoding: Encoding::Raw,
        kind: "t".into(),
    }
}

fn index(entries: Vec<Entry>) -> RangeIndex {
    RangeIndex {
        schema: INDEX_SCHEMA.into(),
        source_path: "source.bin".into(),
        source_size: 1024,
        source_sha256: None,
        entries,
    }
}

#[test]
fn rejects_parent_traversal() {
    let root = temp_root("traversal");
    let outside = std::env::temp_dir().join(format!("xbs-outside-{}.bin", std::process::id()));
    std::fs::write(&outside, b"secret").unwrap();
    let rel = format!("../{}", outside.file_name().unwrap().to_string_lossy());
    assert!(resolve_within(&root, &rel).is_err());
    assert!(resolve_within(&root, "a/../../b").is_err());
    std::fs::remove_file(&outside).ok();
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn rejects_absolute_and_unc_and_ads() {
    let root = temp_root("absolute");
    assert!(resolve_within(&root, "C:\\Windows\\win.ini").is_err());
    assert!(resolve_within(&root, "/etc/passwd").is_err());
    assert!(resolve_within(&root, "\\\\server\\share\\x.bin").is_err());
    assert!(resolve_within(&root, "file.bin:ads").is_err());
    assert!(resolve_within(&root, "C:file.bin").is_err());
    assert!(resolve_within(&root, "").is_err());
    assert!(resolve_within(&root, "a/./b").is_err());
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn accepts_nested_inside_root() {
    let root = temp_root("nested");
    let sub = root.join("sub");
    std::fs::create_dir_all(&sub).unwrap();
    std::fs::write(sub.join("file.bin"), b"data").unwrap();
    let p = resolve_within(&root, "sub/file.bin").unwrap();
    assert!(p.starts_with(root.canonicalize().unwrap()));
    // backslash separator is normalized
    assert!(resolve_within(&root, "sub\\file.bin").is_ok());
    std::fs::remove_dir_all(&root).ok();
}

#[test]
#[cfg(windows)]
fn rejects_junction_escape() {
    let root = temp_root("junction");
    let outside = std::env::temp_dir().join(format!("xbs-junction-target-{}", std::process::id()));
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("secret.bin"), b"secret").unwrap();
    let link = root.join("link");
    let status = std::process::Command::new("cmd")
        .args([
            "/C",
            "mklink",
            "/J",
            &link.to_string_lossy(),
            &outside.to_string_lossy(),
        ])
        .output()
        .unwrap();
    assert!(status.status.success(), "mklink /J failed");
    // canonicalize resolves the junction outside the root -> must reject
    let res = resolve_within(&root, "link/secret.bin");
    assert!(res.is_err(), "junction escape was accepted: {res:?}");
    std::fs::remove_dir(&link).ok(); // removes junction, not target
    std::fs::remove_dir_all(&outside).ok();
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn rejects_bad_index_structure_before_open() {
    assert!(validate_index_structure(&index(vec![entry("a", 0, 10), entry("a", 0, 10)])).is_err()); // dup id
    assert!(validate_index_structure(&index(vec![entry("z", 0, 0)])).is_err()); // zero len
    assert!(validate_index_structure(&index(vec![entry("o", u64::MAX - 1, 10)])).is_err()); // overflow
    let mut e = entry("big", 0, 10);
    e.expected_len = Some(1 << 30);
    assert!(validate_index_structure(&index(vec![e])).is_err()); // expected over cap
    let mut bad = index(vec![entry("ok", 0, 10)]);
    bad.schema = "unknown/9".into();
    assert!(validate_index_structure(&bad).is_err());
    assert!(validate_index_structure(&index(vec![entry("", 0, 10)])).is_err()); // empty id
    assert!(validate_index_structure(&index(vec![entry("ok", 0, 10)])).is_ok());
}

#[test]
fn rejects_malformed_index_json() {
    let d = temp_root("badjson");
    let p = d.join("bad.json");
    std::fs::write(&p, b"{ not json").unwrap();
    assert!(xbs_ranges::load_index(&p).is_err());
    std::fs::write(&p, br#"{"schema":"xbox-inspector-range-index/1","source_path":"../x","source_size":1,"entries":[]}"#).unwrap();
    assert!(xbs_ranges::load_index(&p).is_err());
    std::fs::remove_dir_all(&d).ok();
}

#[test]
fn case_duplicate_paths_detected() {
    let dups = find_case_duplicates(&["a.bin".into(), "A.BIN".into(), "b.bin".into()]);
    assert_eq!(dups.len(), 1);
    assert_eq!(dups[0], ("a.bin".to_string(), "A.BIN".to_string()));
    assert!(find_case_duplicates(&["a.bin".into(), "a.bin".into()]).is_empty());
}

#[test]
fn bounded_text_rejects_oversized_file() {
    let root = temp_root("metadata-budget");
    let file = root.join("index.json");
    std::fs::write(&file, b"12345").unwrap();
    assert!(xbs_core::safe_path::read_text(&file, 4).is_err());
    assert_eq!(xbs_core::safe_path::read_text(&file, 5).unwrap(), "12345");
}

#[test]
fn report_cannot_be_written_into_source_or_a_new_subdirectory() {
    let root = temp_root("protected-output");
    let source = root.join("input");
    std::fs::create_dir(&source).unwrap();
    let original = source.join("original.bin");
    std::fs::write(&original, b"fixture").unwrap();
    assert!(xbs_core::safe_path::write_outside(&source, &original, b"report").is_err());
    assert!(xbs_core::safe_path::outside_source(&source, &source.join("new/report.json")).is_err());
    assert_eq!(std::fs::read(original).unwrap(), b"fixture");
    assert!(!source.join("new").exists());
    let output = root.join("outside.json");
    xbs_core::safe_path::write_outside(&source, &output, b"first").unwrap();
    xbs_core::safe_path::write_outside(&source, &output, b"second").unwrap();
    assert_eq!(std::fs::read(output).unwrap(), b"second");
}

#[test]
fn declared_source_digest_is_mandatory_with_default_options() {
    let root = temp_root("mandatory-digest");
    let path = root.join("source.bin");
    let source = vec![0; 128];
    std::fs::write(&path, &source).unwrap();
    let mut row = entry("first", 0, 1);
    row.sha256 = Some(xbs_core::hash::sha256_hex(&source[..1]));
    let mut ix = index(vec![row]);
    ix.source_size = 128;
    ix.source_sha256 = Some("0".repeat(64));
    let report = xbs_ranges::verify_index(
        &ix,
        &path,
        &Default::default(),
        &xbs_core::new_cancel(),
        &mut |_, _, _| {},
    )
    .unwrap();
    assert_eq!(
        report.entries[0].status,
        xbs_ranges::Status::IdentityMismatch
    );
    assert_eq!(report.coverage_bytes, 0);
    ix.source_sha256 = Some(xbs_core::hash::sha256_hex(&source).to_ascii_uppercase());
    let report = xbs_ranges::verify_index(
        &ix,
        &path,
        &Default::default(),
        &xbs_core::new_cancel(),
        &mut |_, _, _| {},
    )
    .unwrap();
    assert_eq!(report.entries[0].status, xbs_ranges::Status::VerifiedHash);
}

#[test]
fn failed_hash_and_unverified_bytes_do_not_inflate_coverage() {
    let root = temp_root("verified-union");
    let path = root.join("source.bin");
    std::fs::write(&path, b"abcdefghij").unwrap();
    let mut failed = entry("bad", 0, 8);
    failed.sha256 = Some("0".repeat(64));
    let mut good = entry("passed", 1, 3);
    good.sha256 = Some(xbs_core::hash::sha256_hex(b"bcd"));
    let mut unverified = entry("bounds", 4, 5);
    unverified.sha256 = None;
    let mut ix = index(vec![failed, good, unverified]);
    ix.source_size = 10;
    let report = xbs_ranges::verify_index(
        &ix,
        &path,
        &Default::default(),
        &xbs_core::new_cancel(),
        &mut |_, _, _| {},
    )
    .unwrap();
    assert_eq!(report.entries[0].status, xbs_ranges::Status::FailedHash);
    assert_eq!(report.entries[2].status, xbs_ranges::Status::BoundsOnly);
    assert_eq!(report.coverage_bytes, 3);
}

#[test]
fn changed_source_invalidates_previously_verified_intervals() {
    let root = temp_root("changed");
    let path = root.join("source.bin");
    std::fs::write(&path, b"abcdefghij").unwrap();
    let mut good = entry("passed", 1, 3);
    good.sha256 = Some(xbs_core::hash::sha256_hex(b"bcd"));
    let mut ix = index(vec![good]);
    ix.source_size = 10;
    let report = xbs_ranges::verify_index(
        &ix,
        &path,
        &Default::default(),
        &xbs_core::new_cancel(),
        &mut |_, _, _| {
            std::fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .unwrap()
                .set_len(0)
                .unwrap();
        },
    )
    .unwrap();
    assert_eq!(report.entries[0].status, xbs_ranges::Status::SourceChanged);
    assert_eq!(report.coverage_bytes, 0);
}
