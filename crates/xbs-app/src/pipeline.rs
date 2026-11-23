//! Shared scan pipeline for CLI and GUI. Read-only on the source folder;
//! all artifacts go to the work directory.

use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use xbs_core::inventory::{self, InvFile};
use xbs_core::safe_path::{
    outside_source, read_text, resolve_within, write_outside, MAX_INDEX_BYTES, MAX_INDEX_ENTRIES,
};
use xbs_core::{is_cancelled, Cancel, Error};
use xbs_ranges::{Encoding, Entry, IndexReport, RangeIndex, Status, VerifyOptions};
use xbs_report::{CoverageRow, Report, ResourceTotals, ScanSummary, TestResult, VideoVerification};

pub const CHEAP_CLAIM_LIMIT: u64 = 64 << 20;

/// Resolve the bundled indexes directory: next to the exe (dev layout) or one
/// level up (ZIP layout: bin/XBOX-Inspector.exe + indexes/ at the root).
pub fn default_indexes_dir(exe_dir: &Path) -> PathBuf {
    let direct = exe_dir.join("indexes");
    if direct.is_dir() {
        return direct;
    }
    if let Some(parent) = exe_dir.parent() {
        let up = parent.join("indexes");
        if up.is_dir() {
            return up;
        }
    }
    direct
}

pub struct ScanConfig {
    pub root: PathBuf,
    pub hash_all: bool,
    pub deep_rds5: bool,
    pub scan_open: bool,
    pub verify_indexes: bool,
    pub indexes_dir: Option<PathBuf>,
    pub extra_indexes: Vec<PathBuf>,
    pub out_json: Option<PathBuf>,
    pub out_md: Option<PathBuf>,
    pub work_dir: PathBuf,
}

pub enum Event {
    Stage(String),
    Progress {
        stage: String,
        done: u64,
        total: u64,
    },
    Log(String),
    Done(Box<Report>),
    Cancelled,
    Failed(String),
}

#[derive(Debug, Deserialize)]
struct Claim {
    path: String,
    label: String,
    start: u64,
    end: u64,
    sha256: String,
}

#[derive(Debug, Deserialize)]
struct ClaimsFile {
    schema: String,
    claims: Vec<Claim>,
}

#[derive(Debug, Deserialize)]
struct VideoRecord {
    offset: u64,
    size: u64,
    revision: String,
    width: u32,
    height: u32,
    frames: u32,
    fps: [u32; 2],
    flags: u32,
    largest_frame: u32,
    header_and_index_sha256: String,
}

#[derive(Debug, Deserialize)]
struct VideoIndex {
    schema: String,
    source_path: String,
    source_size: u64,
    #[allow(dead_code)] // snapshot binding; verified via --hash-all pass
    source_sha256: Option<String>,
    records: Vec<VideoRecord>,
}

#[derive(Debug, Deserialize)]
struct SourceHash {
    path: String,
    #[allow(dead_code)] // size cross-check is done via the inventory snapshot
    size: u64,
    sha256: String,
}

#[derive(Debug, Deserialize)]
struct SourceHashes {
    schema: String,
    entries: Vec<SourceHash>,
}

pub fn run(cfg: &ScanConfig, cancel: &Cancel, emit: &mut dyn FnMut(Event)) {
    match run_inner(cfg, cancel, emit) {
        Ok(()) => {}
        Err(Error::Cancelled) => emit(Event::Cancelled),
        Err(e) => emit(Event::Failed(e.to_string())),
    }
}

fn run_inner(
    cfg: &ScanConfig,
    cancel: &Cancel,
    emit: &mut dyn FnMut(Event),
) -> xbs_core::Result<()> {
    let root = &cfg.root;
    if !root.is_dir() {
        return Err(Error::Format(format!(
            "папка не найдена: {}",
            root.display()
        )));
    }
    let work_dir = outside_source(root, &cfg.work_dir)?;
    let out_json = cfg
        .out_json
        .as_deref()
        .map(|p| outside_source(root, p))
        .transpose()?;
    let out_md = cfg
        .out_md
        .as_deref()
        .map(|p| outside_source(root, p))
        .transpose()?;
    if out_json.is_some() && out_json == out_md {
        return Err(Error::Format(
            "JSON and Markdown need different output paths".into(),
        ));
    }
    std::fs::create_dir_all(&work_dir)?;

    // 1. Inventory (metadata + prefixes only).
    emit(Event::Stage("Инвентаризация".into()));
    let files = inventory::walk(root, cancel, &mut |n| {
        emit(Event::Progress {
            stage: "Инвентаризация".into(),
            done: n,
            total: 0,
        });
    })?;
    let logical_bytes = inventory::logical_bytes(&files);
    emit(Event::Log(format!(
        "Файлов: {} · логический размер: {} байт ({})",
        files.len(),
        logical_bytes,
        xbs_core::fmt_bytes(logical_bytes)
    )));
    let mut file_reports = xbs_report::file_reports(&files);
    let by_rel: BTreeMap<String, &InvFile> = files.iter().map(|f| (f.rel.clone(), f)).collect();

    // 2. Configuration + launch preflight.
    emit(Event::Stage("Конфигурация и preflight".into()));
    let read_manifest = |name| {
        resolve_within(root, name)
            .and_then(|p| read_text(&p, 1 << 20))
            .ok()
    };
    let cfg_text = read_manifest("MicrosoftGame.Config");
    let manifest_text = read_manifest("appxmanifest.xml");
    let game_config = cfg_text
        .as_deref()
        .and_then(|t| xbs_core::config::parse_game_config(t).ok());
    let appx = manifest_text
        .as_deref()
        .and_then(|t| xbs_core::config::parse_appxmanifest(t).ok());
    let preflight = xbs_core::preflight::run(root, &files, game_config.as_ref(), appx.as_ref());
    for b in &preflight.blockers {
        emit(Event::Log(format!("PRELIGHT: {b}")));
    }

    // Named passes keep counters of different modes separate (spec item 33/99).
    let mut passes: Vec<xbs_report::PassRecord> = Vec::new();
    let mut record_pass = |name: &str, mode: &str, counters: Vec<(&str, u64)>| {
        passes.push(xbs_report::PassRecord {
            name: name.to_string(),
            mode: mode.to_string(),
            finished_utc: xbs_report::utc_now(),
            counters: counters
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        });
    };
    record_pass(
        "inventory+preflight",
        "metadata",
        vec![
            ("files", files.len() as u64),
            ("logical_bytes", logical_bytes),
        ],
    );

    // 3. Optional full hashing (explicit heavy pass).
    let mut hashes: BTreeMap<String, String> = BTreeMap::new();
    if cfg.hash_all {
        emit(Event::Stage("Полный SHA-256".into()));
        let total = logical_bytes;
        let mut done = 0u64;
        for (i, f) in files.iter().enumerate() {
            if is_cancelled(cancel) {
                return Err(Error::Cancelled);
            }
            if f.catalog_state == "SKIPPED_LINK" {
                continue;
            }
            if f.size == 0 {
                let empty = xbs_core::hash::sha256_hex(b"");
                hashes.insert(f.rel.clone(), empty.clone());
                file_reports[i].source_sha256 = Some(empty);
                file_reports[i].validation_level = "hash-verified".into();
                continue;
            }
            let path = resolve_within(root, &f.rel)?;
            let base = done;
            let digest = xbs_core::hash::sha256_file(&path, f.size, cancel, &mut |n| {
                emit(Event::Progress {
                    stage: format!("SHA-256: {}", f.rel),
                    done: base + n,
                    total,
                });
            })?;
            done += f.size;
            hashes.insert(f.rel.clone(), digest.clone());
            file_reports[i].source_sha256 = Some(digest);
            file_reports[i].validation_level = "hash-verified".into();
        }
    }

    // 4. RPF9 header profiles.
    emit(Event::Stage("Заголовки RPF9".into()));
    let mut rpf9_reports = Vec::new();
    for f in files
        .iter()
        .filter(|f| f.kind == xbs_core::formats::FileKind::Rpf9)
    {
        if is_cancelled(cancel) {
            return Err(Error::Cancelled);
        }
        let source = resolve_within(root, &f.rel)?;
        match xbs_core::rpf9::inspect(&source, &f.rel, f.size) {
            Ok(r) => {
                if let Some(fr) = file_reports.iter_mut().find(|x| x.source_path == f.rel) {
                    fr.validation_level = "header-parsed".into();
                }
                rpf9_reports.push(r);
            }
            Err(e) => emit(Event::Log(format!("RPF9 {}: {e}", f.rel))),
        }
    }

    // 5. RDS5/ETPF tables (metadata by default, blocks when deep).
    emit(Event::Stage("Таблицы RDS5/ETPF".into()));
    let rds5_files: Vec<&InvFile> = files
        .iter()
        .filter(|f| f.kind == xbs_core::formats::FileKind::Rds5)
        .collect();
    let mut rds5_summaries = Vec::new();
    let mut rds5_blocks_available = 0u64;
    let mut rds5_blocks_verified = 0u64;
    let mut rds5_descriptors = 0u64;
    for (i, f) in rds5_files.iter().enumerate() {
        if is_cancelled(cancel) {
            return Err(Error::Cancelled);
        }
        let opts = xbs_core::rds5::AnalyzeOptions {
            deep: cfg.deep_rds5,
            keep_textures: false,
            ..Default::default()
        };
        let rel = f.rel.clone();
        let source = resolve_within(root, &f.rel)?;
        match xbs_core::rds5::analyze(&source, &f.rel, &opts, cancel, &mut |d, t| {
            emit(Event::Progress {
                stage: format!("RDS5 {rel}: блоки"),
                done: d as u64,
                total: t as u64,
            });
        }) {
            Ok(r) => {
                rds5_blocks_available += r.counts.get("AVAILABLE").copied().unwrap_or(0);
                rds5_blocks_verified += r.counts.get("SUCCESS_VERIFIED").copied().unwrap_or(0);
                rds5_descriptors += r.etpf.as_ref().map(|e| e.descriptors as u64).unwrap_or(0);
                if let Some(fr) = file_reports.iter_mut().find(|x| x.source_path == f.rel) {
                    fr.validation_level = if cfg.deep_rds5 && r.status == "SUCCESS_VERIFIED" {
                        "blocks-verified".into()
                    } else {
                        "table-parsed".into()
                    };
                }
                rds5_summaries.push(xbs_report::Rds5Summary::from_report(&r));
            }
            Err(Error::Cancelled) => return Err(Error::Cancelled),
            Err(e) => emit(Event::Log(format!("RDS5 {}: {e}", f.rel))),
        }
        emit(Event::Progress {
            stage: "RDS5".into(),
            done: (i + 1) as u64,
            total: rds5_files.len() as u64,
        });
    }
    record_pass(
        "rds5-tables",
        if cfg.deep_rds5 {
            "deep-blocks"
        } else {
            "metadata"
        },
        vec![
            ("stores", rds5_summaries.len() as u64),
            ("descriptors", rds5_descriptors),
            ("blocks_available", rds5_blocks_available),
            ("blocks_verified", rds5_blocks_verified),
        ],
    );

    // 6. Indexed-range verification.
    let mut index_reports: Vec<IndexReport> = Vec::new();
    let mut video_reports: Vec<VideoVerification> = Vec::new();
    let mut coverage: Vec<CoverageRow> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    let mut ranges_hash = 0u64;
    let mut bundled_ranges_hash = 0u64;
    let mut ranges_stream = 0u64;
    let mut ranges_unconfirmed = 0u64;

    if cfg.verify_indexes {
        emit(Event::Stage("Проверка индексированных диапазонов".into()));
        let idx_dir = cfg.indexes_dir.clone();
        // 6a. Claims (independent catalog from the 0.1.0 verification pass).
        if let Some(dir) = &idx_dir {
            let claims_path = dir.join("claims.json");
            if claims_path.is_file() {
                let text = read_text(&claims_path, MAX_INDEX_BYTES)?;
                let cf: ClaimsFile = serde_json::from_str(&text)
                    .map_err(|e| Error::Format(format!("claims.json: {e}")))?;
                if cf.schema != "xbox-inspector-claims/1" || cf.claims.len() > MAX_INDEX_ENTRIES {
                    return Err(Error::Format("claims.json: неизвестная схема".into()));
                }
                let mut groups: BTreeMap<String, Vec<&Claim>> = BTreeMap::new();
                for c in &cf.claims {
                    groups.entry(c.path.clone()).or_default().push(c);
                }
                let mut skipped_heavy = 0u64;
                let mut skipped_bytes = 0u64;
                for (path, claims) in &groups {
                    if is_cancelled(cancel) {
                        return Err(Error::Cancelled);
                    }
                    let source_path = match resolve_within(root, path) {
                        Ok(source) => source,
                        Err(e) => {
                            notes.push(format!("claims: путь отклонён ({path}): {e}"));
                            continue;
                        }
                    };
                    let Some(inv) = by_rel.get(path) else {
                        notes.push(format!("claims: файл отсутствует в текущем снимке: {path}"));
                        continue;
                    };
                    let mut entries = Vec::new();
                    for c in claims {
                        let len = c.end.saturating_sub(c.start);
                        let full_file = c.start == 0 && c.end == inv.size;
                        if full_file {
                            if let Some(h) = hashes.get(path) {
                                // Reuse the computed full-file hash; no second read.
                                let ok = h.eq_ignore_ascii_case(&c.sha256);
                                let mut ir = IndexReport {
                                    schema: xbs_ranges::REPORT_SCHEMA.into(),
                                    source_path: path.clone(),
                                    source_size: inv.size,
                                    identity: xbs_ranges::IdentityCheck {
                                        path: root.join(path).to_string_lossy().to_string(),
                                        size: inv.size,
                                        mtime_ns: inv.mtime_ns,
                                        size_matches: true,
                                        sha256: Some(h.clone()),
                                        sha256_matches: Some(ok),
                                    },
                                    entries: vec![xbs_ranges::EntryResult {
                                        id: c.label.clone(),
                                        offset: 0,
                                        stored_len: inv.size,
                                        decoded_len: Some(inv.size),
                                        sha256: Some(h.clone()),
                                        status: if ok {
                                            Status::VerifiedHash
                                        } else {
                                            Status::FailedHash
                                        },
                                        detail: None,
                                    }],
                                    coverage_bytes: if ok { inv.size } else { 0 },
                                    counts: BTreeMap::new(),
                                    entries_total: 1,
                                    entries_verified: usize::from(ok),
                                };
                                ir.counts.insert(
                                    if ok {
                                        "VerifiedHash".into()
                                    } else {
                                        "FailedHash".into()
                                    },
                                    1,
                                );
                                if ok {
                                    ranges_hash += 1;
                                    coverage.push(CoverageRow {
                                        archive: path.clone(),
                                        archive_bytes: inv.size,
                                        union_verified_bytes: inv.size,
                                        percent: 100.0,
                                        scope: "full-file claim (hash-all)".into(),
                                    });
                                } else {
                                    ranges_unconfirmed += 1;
                                }
                                index_reports.push(ir);
                                continue;
                            }
                        }
                        if !cfg.hash_all && len > CHEAP_CLAIM_LIMIT {
                            skipped_heavy += 1;
                            skipped_bytes += len;
                            continue;
                        }
                        entries.push(Entry {
                            id: c.label.clone(),
                            offset: c.start,
                            stored_len: len,
                            expected_len: None,
                            sha256: Some(c.sha256.clone()),
                            encoding: Encoding::Raw,
                            kind: "claim".into(),
                        });
                    }
                    if entries.is_empty() {
                        continue;
                    }
                    let idx = RangeIndex {
                        schema: xbs_ranges::INDEX_SCHEMA.into(),
                        source_path: path.clone(),
                        source_size: inv.size,
                        source_sha256: None,
                        entries,
                    };
                    let rel2 = path.clone();
                    let rep = xbs_ranges::verify_index(
                        &idx,
                        &source_path,
                        &VerifyOptions::default(),
                        cancel,
                        &mut |d, t, _| {
                            emit(Event::Progress {
                                stage: format!("Диапазоны {rel2}"),
                                done: d as u64,
                                total: t as u64,
                            });
                        },
                    )?;
                    for e in &rep.entries {
                        match e.status {
                            Status::VerifiedHash => ranges_hash += 1,
                            Status::VerifiedStream => ranges_stream += 1,
                            _ => ranges_unconfirmed += 1,
                        }
                    }
                    if rep.entries_verified > 0 {
                        coverage.push(CoverageRow {
                            archive: path.clone(),
                            archive_bytes: inv.size,
                            union_verified_bytes: rep.coverage_bytes,
                            percent: rep.coverage_bytes as f64 * 100.0 / inv.size as f64,
                            scope: "claims (union of verified stored ranges)".into(),
                        });
                    }
                    index_reports.push(rep);
                }
                if skipped_heavy > 0 {
                    notes.push(format!(
                        "claims: {skipped_heavy} тяжёлых диапазонов ({}) пропущены в дешёвом проходе; включите --hash-all для полной проверки",
                        xbs_core::fmt_bytes(skipped_bytes)
                    ));
                }
            }
            // 6b. Video index (515 Bink records, header+index hashes).
            let video_path = dir.join("movies-video.json");
            if video_path.is_file() {
                let text = read_text(&video_path, MAX_INDEX_BYTES)?;
                let vi: VideoIndex = serde_json::from_str(&text)
                    .map_err(|e| Error::Format(format!("movies-video.json: {e}")))?;
                if vi.schema != "xbox-inspector-video-index/1"
                    || vi.records.len() > MAX_INDEX_ENTRIES
                {
                    return Err(Error::Format("movies-video.json: неизвестная схема".into()));
                }
                if let Err(e) = xbs_core::safe_path::resolve_within(root, &vi.source_path) {
                    notes.push(format!("video-index: путь отклонён: {e}"));
                } else if let Some(inv) = by_rel.get(&vi.source_path) {
                    let vr = verify_video(root, &vi, inv, cancel, emit)?;
                    if vr.records_verified > 0 {
                        coverage.push(CoverageRow {
                            archive: vi.source_path.clone(),
                            archive_bytes: inv.size,
                            union_verified_bytes: vr.verified_record_bytes,
                            percent: vr.verified_record_bytes as f64 * 100.0 / inv.size as f64,
                            scope: "Bink records (header+index verified, union)".into(),
                        });
                    }
                    video_reports.push(vr);
                } else {
                    notes.push(format!("video-index: {} отсутствует", vi.source_path));
                }
            }
            // 6c. Source hashes catalog.
            let sh_path = dir.join("source-hashes.json");
            if sh_path.is_file() {
                let text = read_text(&sh_path, MAX_INDEX_BYTES)?;
                let sh: SourceHashes = serde_json::from_str(&text)
                    .map_err(|e| Error::Format(format!("source-hashes.json: {e}")))?;
                if sh.schema != "xbox-inspector-source-hashes/1"
                    || sh.entries.len() > MAX_INDEX_ENTRIES
                {
                    return Err(Error::Format(
                        "source-hashes.json: неизвестная схема".into(),
                    ));
                }
                if cfg.hash_all {
                    let mut matched = 0u64;
                    let mut mismatched = 0u64;
                    for e in &sh.entries {
                        match hashes.get(&e.path) {
                            Some(h) if h.eq_ignore_ascii_case(&e.sha256) => matched += 1,
                            Some(_) => {
                                mismatched += 1;
                                notes.push(format!("source-hashes: РАСХОЖДЕНИЕ {}", e.path));
                            }
                            None => notes.push(format!("source-hashes: нет в снимке {}", e.path)),
                        }
                    }
                    emit(Event::Log(format!(
                        "source-hashes: совпало {matched}, расхождений {mismatched} из {}",
                        sh.entries.len()
                    )));
                } else {
                    notes.push(format!(
                        "source-hashes.json ({} записей) не проверялся: нужен --hash-all",
                        sh.entries.len()
                    ));
                }
            }
        }
        // 6d. User-supplied generic indexes.
        bundled_ranges_hash = ranges_hash;
        let mut seen_indexes = std::collections::BTreeSet::new();
        let mut extra_entries = 0usize;
        if cfg.extra_indexes.len() > 32 {
            return Err(Error::Format(
                "too many additional indexes (limit 32)".into(),
            ));
        }
        for p in &cfg.extra_indexes {
            if is_cancelled(cancel) {
                return Err(Error::Cancelled);
            }
            let canonical = match p.canonicalize() {
                Ok(value) if seen_indexes.insert(value.clone()) => value,
                Ok(_) => {
                    notes.push(format!("duplicate index skipped: {}", p.display()));
                    continue;
                }
                Err(e) => {
                    notes.push(format!("index unavailable {}: {e}", p.display()));
                    continue;
                }
            };
            let idx = match xbs_ranges::load_index(&canonical) {
                Ok(i) => i,
                Err(e) => {
                    notes.push(format!(
                        "индекс {} отклонён до открытия файлов: {e}",
                        p.display()
                    ));
                    continue;
                }
            };
            extra_entries += idx.entries.len();
            if extra_entries > MAX_INDEX_ENTRIES {
                return Err(Error::Format(
                    "additional indexes exceed the total entry budget".into(),
                ));
            }
            let source = match xbs_core::safe_path::resolve_within(root, &idx.source_path) {
                Ok(s) => s,
                Err(e) => {
                    notes.push(format!("индекс {}: путь отклонён: {e}", p.display()));
                    continue;
                }
            };
            let rep = xbs_ranges::verify_index(
                &idx,
                &source,
                &VerifyOptions::default(),
                cancel,
                &mut |d, t, _| {
                    emit(Event::Progress {
                        stage: format!("Индекс {}", p.display()),
                        done: d as u64,
                        total: t as u64,
                    });
                },
            )?;
            for e in &rep.entries {
                match e.status {
                    Status::VerifiedHash => ranges_hash += 1,
                    Status::VerifiedStream => ranges_stream += 1,
                    _ => ranges_unconfirmed += 1,
                }
            }
            index_reports.push(rep);
        }
    }

    record_pass(
        "indexes",
        "bundled+additional",
        vec![
            ("ranges_verified_hash", ranges_hash),
            ("bundled_ranges_verified_hash", bundled_ranges_hash),
            (
                "additional_ranges_verified_hash",
                ranges_hash - bundled_ranges_hash,
            ),
            ("ranges_verified_stream", ranges_stream),
            ("ranges_unconfirmed", ranges_unconfirmed),
            (
                "bink_records_verified",
                video_reports
                    .iter()
                    .map(|v| v.records_verified as u64)
                    .sum(),
            ),
        ],
    );

    // 7. Open-stream discovery (explicit option).
    let mut open_scans: Vec<ScanSummary> = Vec::new();
    let mut zlib_members = 0u64;
    let mut bink_verified = 0u64;
    for v in &video_reports {
        bink_verified += v.records_verified as u64;
    }
    if cfg.scan_open {
        emit(Event::Stage("Поиск открытых потоков".into()));
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| Error::Format(e.to_string()))?
            .as_nanos();
        let scan_dir = work_dir.join(format!("scan-{}-{stamp}", std::process::id()));
        std::fs::create_dir(&scan_dir)?;
        const ZLIB_TARGETS: &[&str] = &[
            "data.rpf",
            "script.rpf",
            "common.rpf",
            "pack/story000/story000_script.rpf",
        ];
        notes.push(
            "Правило отбора открытого поиска: ZLIB — data/script/common/story000_script; Bink — movies.rpf (если нет видеоиндекса). Остальные RPF9 не сканировались в этом проходе."
                .into(),
        );
        for r in &rpf9_reports {
            if is_cancelled(cancel) {
                return Err(Error::Cancelled);
            }
            let Some(region) = r.catalog_region else {
                continue;
            };
            let path = resolve_within(root, &r.rel)?;
            let mut f = std::fs::File::open(&path)?;
            let (allocated, _method) = xbs_core::extents::allocated_ranges(&f, r.file_size);
            let extents = xbs_core::bink::payload_extents(&allocated, region[1]);
            if ZLIB_TARGETS.contains(&r.rel.as_str()) {
                let rel = r.rel.clone();
                let scan = xbs_core::scan::scan(&mut f, &extents, cancel, &mut |d, t| {
                    emit(Event::Progress {
                        stage: format!("ZLIB-поиск {rel}"),
                        done: d,
                        total: t,
                    });
                })?;
                zlib_members += scan.members.len() as u64;
                // Persist a fresh index (new file; bundled indexes untouched).
                let idx = RangeIndex {
                    schema: xbs_ranges::INDEX_SCHEMA.into(),
                    source_path: r.rel.clone(),
                    source_size: r.file_size,
                    source_sha256: None,
                    entries: scan
                        .members
                        .iter()
                        .enumerate()
                        .map(|(i, m)| Entry {
                            id: format!("zlib-{i:06}"),
                            offset: m.offset,
                            stored_len: m.stored_len,
                            expected_len: Some(m.decoded_len),
                            sha256: Some(m.sha256.clone()),
                            encoding: Encoding::Zlib,
                            kind: m.inner_kind.clone(),
                        })
                        .collect(),
                };
                let idx_path =
                    scan_dir.join(format!("scan-{}.zlib-index.json", r.rel.replace('/', "_")));
                write_outside(root, &idx_path, &serde_json::to_vec_pretty(&idx).unwrap())?;
                open_scans.push(ScanSummary {
                    rel: r.rel.clone(),
                    kind: "ZLIB".into(),
                    scanned_payload_bytes: scan.scanned_payload_bytes,
                    members_found: scan.members.len(),
                    decoded_bytes_total: scan.decoded_bytes_total,
                    rejected_candidates: scan.rejected_candidates,
                    sample: scan
                        .members
                        .iter()
                        .take(16)
                        .map(|m| serde_json::to_value(m).unwrap())
                        .collect(),
                    stopped_reason: scan.stopped_reason,
                    full_index_path: Some(idx_path.to_string_lossy().to_string()),
                });
            } else if r.rel == "movies.rpf" && video_reports.is_empty() {
                let rel = r.rel.clone();
                let scan = xbs_core::bink::scan(&mut f, &extents, cancel, &mut |d, t| {
                    emit(Event::Progress {
                        stage: format!("Bink-поиск {rel}"),
                        done: d,
                        total: t,
                    });
                })?;
                bink_verified += scan.videos.len() as u64;
                open_scans.push(ScanSummary {
                    rel: r.rel.clone(),
                    kind: "Bink".into(),
                    scanned_payload_bytes: scan.scanned_payload_bytes,
                    members_found: scan.videos.len(),
                    decoded_bytes_total: 0,
                    rejected_candidates: scan.invalid_candidates,
                    sample: scan
                        .videos
                        .iter()
                        .take(8)
                        .map(|m| serde_json::to_value(m).unwrap())
                        .collect(),
                    stopped_reason: None,
                    full_index_path: None,
                });
            }
        }
    }

    if cfg.scan_open {
        let decoded: u64 = open_scans.iter().map(|s| s.decoded_bytes_total).sum();
        record_pass(
            "scan-open",
            "zlib+bink-discovery",
            vec![
                ("zlib_members_found", zlib_members),
                ("decoded_bytes", decoded),
                ("bink_records_verified", bink_verified),
            ],
        );
    }

    // 8. Totals, tests, report.
    let totals = ResourceTotals {
        files: files.len() as u64,
        rpf9_containers: rpf9_reports.len() as u64,
        rds5_stores: rds5_summaries.len() as u64,
        rds5_descriptors,
        rds5_blocks_available,
        rds5_blocks_verified,
        pe_dlls: files
            .iter()
            .filter(|f| f.kind == xbs_core::formats::FileKind::PeDll)
            .count() as u64,
        pe_other: files
            .iter()
            .filter(|f| {
                matches!(
                    f.kind,
                    xbs_core::formats::FileKind::PeExecutable
                        | xbs_core::formats::FileKind::PeNoEntry
                )
            })
            .count() as u64,
        bink_records_verified: bink_verified,
        zlib_members_found: zlib_members,
        ranges_verified_hash: ranges_hash,
        bundled_ranges_verified_hash: bundled_ranges_hash,
        additional_ranges_verified_hash: ranges_hash - bundled_ranges_hash,
        ranges_verified_stream: ranges_stream,
        ranges_unconfirmed: ranges_unconfirmed,
    };
    notes.push(
        "Закрытые каталоги RPF9 и XVD не расшифровывались; статус ENCRYPTED_OR_UNRESOLVED не устанавливает алгоритм шифрования."
            .into(),
    );
    if !cfg.hash_all {
        notes.push("Полное хеширование всех файлов не выполнялось в этом проходе.".into());
    }
    let tests: Vec<TestResult> = crate::selftest::run();
    let passed = tests.iter().filter(|t| t.passed).count();
    emit(Event::Log(format!(
        "Self-тесты метода: {passed}/{}",
        tests.len()
    )));

    // checked_intervals for files with verified ranges (capped).
    for ir in &index_reports {
        if let Some(fr) = file_reports
            .iter_mut()
            .find(|x| x.source_path == ir.source_path)
        {
            let ints: Vec<[u64; 2]> = ir
                .entries
                .iter()
                .filter(|e| e.status.is_verified())
                .take(64)
                .map(|e| [e.offset, e.offset + e.stored_len])
                .collect();
            if !ints.is_empty() {
                fr.checked_intervals = Some(ints);
                if fr.validation_level == "metadata+prefix" {
                    fr.validation_level = "ranges-verified".into();
                }
            }
        }
    }

    let report = Report {
        schema: xbs_report::SCHEMA.into(),
        tool: "XBOX-Inspector".into(),
        tool_version: env!("CARGO_PKG_VERSION").into(),
        generated_utc: xbs_report::utc_now(),
        source_root: root.to_string_lossy().to_string(),
        file_count: files.len() as u64,
        logical_bytes,
        files: file_reports,
        game_config,
        appx_manifest: appx,
        runtime_preflight: preflight,
        rpf9: rpf9_reports,
        rds5: rds5_summaries,
        index_verifications: index_reports,
        video_verifications: video_reports,
        open_scans,
        resource_totals: totals,
        passes,
        coverage,
        tests,
        notes,
    };

    if is_cancelled(cancel) {
        return Err(Error::Cancelled);
    }
    if let Some(p) = &out_json {
        write_outside(root, p, &serde_json::to_vec_pretty(&report).unwrap())?;
        emit(Event::Log(format!("Отчёт JSON: {}", p.display())));
    }
    if let Some(p) = &out_md {
        write_outside(root, p, xbs_report::to_markdown(&report).as_bytes())?;
        emit(Event::Log(format!("Отчёт Markdown: {}", p.display())));
    }
    emit(Event::Done(Box::new(report)));
    Ok(())
}

fn verify_video(
    root: &Path,
    vi: &VideoIndex,
    inv: &InvFile,
    cancel: &Cancel,
    emit: &mut dyn FnMut(Event),
) -> xbs_core::Result<VideoVerification> {
    let path = resolve_within(root, &vi.source_path)?;
    let mut f = std::fs::File::open(&path)?;
    let size_ok = inv.size == vi.source_size;
    let mut verified = 0usize;
    let mut failed = Vec::new();
    let mut ranges: Vec<(u64, u64)> = Vec::new();
    let total = vi.records.len();
    if !size_ok {
        failed.push(format!(
            "identity: размер {} != {} в индексе",
            inv.size, vi.source_size
        ));
    }
    for (i, rec) in vi.records.iter().enumerate() {
        if is_cancelled(cancel) {
            return Err(Error::Cancelled);
        }
        if size_ok {
            if let Some(upper) = rec
                .offset
                .checked_add(rec.size)
                .filter(|&end| end <= inv.size)
            {
                match xbs_core::bink::inspect(&mut f, rec.offset, upper, false) {
                    Ok(got) => {
                        let hash_ok = got
                            .header_and_index_sha256
                            .eq_ignore_ascii_case(&rec.header_and_index_sha256);
                        let fields_ok = got.revision == rec.revision
                            && got.width == rec.width
                            && got.height == rec.height
                            && got.frames == rec.frames
                            && got.size == rec.size
                            && got.fps == rec.fps
                            && got.flags == rec.flags
                            && got.largest_frame == rec.largest_frame;
                        if hash_ok && fields_ok {
                            verified += 1;
                            ranges.push((rec.offset, upper));
                        } else {
                            failed.push(format!(
                                "record@{}: hash_ok={hash_ok} fields_ok={fields_ok}",
                                rec.offset
                            ));
                        }
                    }
                    Err(e) => failed.push(format!("record@{}: {e}", rec.offset)),
                }
            } else {
                failed.push(format!("record@{}: beyond EOF", rec.offset));
            }
        }
        if i % 32 == 0 || i + 1 == total {
            emit(Event::Progress {
                stage: "Видеоиндекс movies.rpf".into(),
                done: (i + 1) as u64,
                total: total as u64,
            });
        }
    }
    Ok(VideoVerification {
        rel: vi.source_path.clone(),
        source_size: inv.size,
        records_total: total,
        records_verified: verified,
        failed,
        verified_record_bytes: xbs_core::extents::union_bytes(&ranges),
    })
}
