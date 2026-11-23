//! Versioned report schema (JSON + Markdown), spec fields included.

use serde::Serialize;
use xbs_core::config::{AppxManifest, GameConfig};
use xbs_core::inventory::InvFile;
use xbs_core::preflight::RuntimePreflight;
use xbs_core::rds5::Rds5Report;
use xbs_core::rpf9::Rpf9Report;
use xbs_ranges::IndexReport;

pub const SCHEMA: &str = "xbox-inspector-report/1";

#[derive(Debug, Clone, Serialize)]
pub struct FileReport {
    pub source_path: String,
    pub source_size: u64,
    pub prefix_hex: String,
    pub file_type: String,
    pub catalog_state: String,
    pub mtime_ns: u128,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checked_intervals: Option<Vec<[u64; 2]>>,
    pub validation_level: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Rds5Summary {
    pub rel: String,
    pub status: String,
    pub file_bytes: u64,
    pub declared_virtual_bytes: u64,
    pub boundary_records: u32,
    pub etpf_descriptors: Option<u32>,
    pub textures_total: usize,
    pub counts: std::collections::BTreeMap<String, u64>,
    pub verified_bytes: u64,
    pub metadata_error: Option<String>,
    /// Non-available blocks, capped; full rows stay in the per-file deep report.
    pub problem_blocks: Vec<xbs_core::rds5::BlockRow>,
}

impl Rds5Summary {
    pub fn from_report(r: &Rds5Report) -> Self {
        Self {
            rel: r.rel.clone(),
            status: r.status.clone(),
            file_bytes: r.file_bytes,
            declared_virtual_bytes: r.header.declared_virtual_bytes,
            boundary_records: r.header.boundary_records,
            etpf_descriptors: r.etpf.as_ref().map(|e| e.descriptors),
            textures_total: r.textures_total,
            counts: r.counts.clone(),
            verified_bytes: r.verified_bytes,
            metadata_error: r.metadata_error.clone(),
            problem_blocks: r
                .blocks
                .iter()
                .filter(|b| b.status != "AVAILABLE" && b.status != "SUCCESS_VERIFIED")
                .take(64)
                .cloned()
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanSummary {
    pub rel: String,
    pub kind: String,
    pub scanned_payload_bytes: u64,
    pub members_found: usize,
    pub decoded_bytes_total: u64,
    pub rejected_candidates: u64,
    pub sample: Vec<serde_json::Value>,
    pub stopped_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_index_path: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VideoVerification {
    pub rel: String,
    pub source_size: u64,
    pub records_total: usize,
    pub records_verified: usize,
    pub failed: Vec<String>,
    pub verified_record_bytes: u64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ResourceTotals {
    pub files: u64,
    pub rpf9_containers: u64,
    pub rds5_stores: u64,
    pub rds5_descriptors: u64,
    pub rds5_blocks_available: u64,
    pub rds5_blocks_verified: u64,
    pub pe_dlls: u64,
    pub pe_other: u64,
    pub bink_records_verified: u64,
    pub zlib_members_found: u64,
    pub ranges_verified_hash: u64,
    pub bundled_ranges_verified_hash: u64,
    pub additional_ranges_verified_hash: u64,
    pub ranges_verified_stream: u64,
    pub ranges_unconfirmed: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CoverageRow {
    pub archive: String,
    pub archive_bytes: u64,
    pub union_verified_bytes: u64,
    pub percent: f64,
    pub scope: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TestResult {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

/// One named verification pass with its own counters and timestamp.
/// Keeps "found" (scan) and "verified" (index round-trip) numbers separate.
#[derive(Debug, Clone, Serialize)]
pub struct PassRecord {
    pub name: String,
    pub mode: String,
    pub finished_utc: String,
    pub counters: std::collections::BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub schema: String,
    pub tool: String,
    pub tool_version: String,
    pub generated_utc: String,
    pub source_root: String,
    pub file_count: u64,
    pub logical_bytes: u64,
    pub files: Vec<FileReport>,
    pub game_config: Option<GameConfig>,
    pub appx_manifest: Option<AppxManifest>,
    pub runtime_preflight: RuntimePreflight,
    pub rpf9: Vec<Rpf9Report>,
    pub rds5: Vec<Rds5Summary>,
    pub index_verifications: Vec<IndexReport>,
    pub video_verifications: Vec<VideoVerification>,
    pub open_scans: Vec<ScanSummary>,
    pub resource_totals: ResourceTotals,
    pub passes: Vec<PassRecord>,
    pub coverage: Vec<CoverageRow>,
    pub tests: Vec<TestResult>,
    pub notes: Vec<String>,
}

pub fn file_reports(files: &[InvFile]) -> Vec<FileReport> {
    files
        .iter()
        .map(|f| FileReport {
            source_path: f.rel.clone(),
            source_size: f.size,
            prefix_hex: f.prefix_hex.clone(),
            file_type: f.kind.label().to_string(),
            catalog_state: f.catalog_state.clone(),
            mtime_ns: f.mtime_ns,
            source_sha256: None,
            checked_intervals: None,
            validation_level: if f.size == 0 {
                "empty".into()
            } else {
                "metadata+prefix".into()
            },
        })
        .collect()
}

pub fn utc_now() -> String {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = d.as_secs();
    // civil-from-days (Howard Hinnant algorithm)
    let days = (secs / 86400) as i64;
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    let (hh, mm, ss) = ((secs % 86400) / 3600, (secs % 3600) / 60, secs % 60);
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

pub fn to_markdown(r: &Report) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "# XBOX-Inspector {} — отчёт проверки\n\n",
        r.tool_version
    ));
    s.push_str(&format!(
        "- Схема: `{}`\n- Время (UTC): {}\n- Источник: `{}`\n",
        r.schema, r.generated_utc, r.source_root
    ));
    s.push_str(&format!(
        "- Файлов: **{}** · логический размер: **{} байт** ({})\n\n",
        r.file_count,
        r.logical_bytes,
        xbs_core::fmt_bytes(r.logical_bytes)
    ));
    s.push_str("## Готовность к запуску\n\n");
    let pf = &r.runtime_preflight;
    s.push_str(&format!(
        "- Объявленный исполняемый файл: `{}`\n- Найден: **{}\n",
        pf.declared_executable.clone().unwrap_or_else(|| "—".into()),
        if pf.executable_found {
            "да"
        } else {
            "нет"
        }
    ));
    s.push_str(&format!(
        "- TitleId: `{}` · StoreId: `{}` · версия: {}\n",
        pf.title_id, pf.store_id, pf.package_version
    ));
    s.push_str(&format!(
        "- Слой совместимости: {}\n",
        pf.compatibility_layer_status
    ));
    if pf.blockers.is_empty() {
        s.push_str("- Блокеров нет.\n");
    } else {
        s.push_str("- **Блокеры:**\n");
        for b in &pf.blockers {
            s.push_str(&format!("  - {b}\n"));
        }
    }
    s.push_str("\n## Сводка ресурсов\n\n");
    let t = &r.resource_totals;
    s.push_str(&format!(
        "| Показатель | Значение |\n|---|---:|\n\
         | RPF9 контейнеров | {} |\n\
         | RDS5 хранилищ | {} |\n\
         | Дескрипторов ETPF | {} |\n\
         | Блоков RDS5 AVAILABLE | {} |\n\
         | Блоков RDS5 проверено (deep) | {} |\n\
         | PE DLL | {} |\n\
         | Bink записей проверено | {} |\n\
         | Открытых ZLIB потоков найдено | {} |\n\
         | Диапазонов VERIFIED_HASH | {} |\n\
         | Из них встроенные проверки | {} |\n\
         | Из них дополнительные индексы | {} |\n\
         | Диапазонов VERIFIED_STREAM | {} |\n\
         | Неподтверждённых диапазонов | {} |\n\n",
        t.rpf9_containers,
        t.rds5_stores,
        t.rds5_descriptors,
        t.rds5_blocks_available,
        t.rds5_blocks_verified,
        t.pe_dlls,
        t.bink_records_verified,
        t.zlib_members_found,
        t.ranges_verified_hash,
        t.bundled_ranges_verified_hash,
        t.additional_ranges_verified_hash,
        t.ranges_verified_stream,
        t.ranges_unconfirmed
    ));
    if !r.coverage.is_empty() {
        s.push_str("## Покрытие подтверждёнными диапазонами\n\n| Архив | Байт архива | Подтверждено (объединение) | % |\n|---|---:|---:|---:|\n");
        for c in &r.coverage {
            s.push_str(&format!(
                "| {} | {} | {} | {:.3} |\n",
                c.archive, c.archive_bytes, c.union_verified_bytes, c.percent
            ));
        }
        s.push('\n');
    }
    if !r.index_verifications.is_empty() {
        s.push_str("## Проверка индексированных диапазонов\n\n| Индекс | Записей | Подтверждено | Покрытие, байт |\n|---|---:|---:|---:|\n");
        for iv in &r.index_verifications {
            s.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                iv.source_path, iv.entries_total, iv.entries_verified, iv.coverage_bytes
            ));
        }
        s.push('\n');
    }
    if !r.video_verifications.is_empty() {
        s.push_str("## Видео (Bink)\n\n");
        for v in &r.video_verifications {
            s.push_str(&format!(
                "- `{}`: {}/{} записей проверено, {} байт.\n",
                v.rel, v.records_verified, v.records_total, v.verified_record_bytes
            ));
            for f in v.failed.iter().take(8) {
                s.push_str(&format!("  - отказ: {f}\n"));
            }
        }
        s.push('\n');
    }
    if !r.open_scans.is_empty() {
        s.push_str("## Поиск открытых потоков\n\n");
        for sc in &r.open_scans {
            s.push_str(&format!(
                "- `{}` ({}): найдено {} записей, распаковано {} байт, просмотрено {} байт.\n",
                sc.rel, sc.kind, sc.members_found, sc.decoded_bytes_total, sc.scanned_payload_bytes
            ));
        }
        s.push('\n');
    }
    if !r.passes.is_empty() {
        s.push_str("## Проходы (имя, режим, время, счётчики)\n\n");
        for p in &r.passes {
            let counters: Vec<String> =
                p.counters.iter().map(|(k, v)| format!("{k}={v}")).collect();
            s.push_str(&format!(
                "- **{}** [{}] {} — {}\n",
                p.name,
                p.mode,
                p.finished_utc,
                counters.join(", ")
            ));
        }
        s.push('\n');
    }
    if !r.tests.is_empty() {
        let passed = r.tests.iter().filter(|t| t.passed).count();
        s.push_str(&format!(
            "## Self-тесты метода: {}/{}\n\n",
            passed,
            r.tests.len()
        ));
        for t in &r.tests {
            s.push_str(&format!(
                "- [{}] {} — {}\n",
                if t.passed { "x" } else { " " },
                t.name,
                t.detail
            ));
        }
        s.push('\n');
    }
    if !r.notes.is_empty() {
        s.push_str("## Примечания\n\n");
        for n in &r.notes {
            s.push_str(&format!("- {n}\n"));
        }
    }
    s.push_str("\nСтатусы не означают полной расшифровки: закрытые каталоги RPF9 остаются ENCRYPTED_OR_UNRESOLVED.\n");
    s
}
