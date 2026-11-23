use crate::pipeline::{self, Event, ScanConfig};
use std::path::PathBuf;

pub fn scan(args: &[String]) -> i32 {
    let mut root: Option<PathBuf> = None;
    let mut out_json = None;
    let mut out_md = None;
    let mut work_dir = None;
    let mut indexes_dir = None;
    let mut extra_indexes = Vec::new();
    let mut hash_all = false;
    let mut deep = false;
    let mut scan_open = false;
    let mut no_indexes = false;
    let mut lang = crate::i18n::Lang::Ru;

    let mut i = 0;
    while i < args.len() {
        if matches!(
            args[i].as_str(),
            "--lang" | "--json" | "--md" | "--work" | "--indexes" | "--index"
        ) && args
            .get(i + 1)
            .is_none_or(|v| v.is_empty() || v.starts_with("--"))
        {
            eprintln!("{}: {}", crate::i18n::tr(lang, "error"), args[i]);
            return 2;
        }
        match args[i].as_str() {
            "--lang" => {
                i += 1;
                if let Some(l) = args.get(i).and_then(|s| crate::i18n::Lang::from_code(s)) {
                    lang = l;
                } else {
                    eprintln!(
                        "{}: --lang en|ru|zh-Hans|kk",
                        crate::i18n::tr(lang, "error")
                    );
                    return 2;
                }
            }
            "--json" => {
                i += 1;
                out_json = args.get(i).map(PathBuf::from);
            }
            "--md" => {
                i += 1;
                out_md = args.get(i).map(PathBuf::from);
            }
            "--work" => {
                i += 1;
                work_dir = args.get(i).map(PathBuf::from);
            }
            "--indexes" => {
                i += 1;
                indexes_dir = args.get(i).map(PathBuf::from);
            }
            "--index" => {
                i += 1;
                if let Some(p) = args.get(i) {
                    extra_indexes.push(PathBuf::from(p));
                }
            }
            "--hash-all" => hash_all = true,
            "--deep" => deep = true,
            "--scan-open" => scan_open = true,
            "--no-indexes" => no_indexes = true,
            other if !other.starts_with("--") && root.is_none() => {
                root = Some(PathBuf::from(other));
            }
            other => {
                eprintln!("{}: {other}", crate::i18n::tr(lang, "error"));
                return 2;
            }
        }
        i += 1;
    }
    let Some(root) = root else {
        eprintln!("{}: scan <folder>", crate::i18n::tr(lang, "err_folder"));
        return 2;
    };
    if no_indexes && (!extra_indexes.is_empty() || indexes_dir.is_some()) {
        eprintln!(
            "{}: --no-indexes · --index/--indexes",
            crate::i18n::tr(lang, "error")
        );
        return 2;
    }

    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));
    let work_dir = work_dir.unwrap_or_else(|| exe_dir.join("work"));
    let indexes_dir = if no_indexes {
        None
    } else {
        Some(indexes_dir.unwrap_or_else(|| pipeline::default_indexes_dir(&exe_dir)))
    };
    let out_json = out_json.or_else(|| Some(work_dir.join("report.json")));
    let out_md = out_md.or_else(|| Some(work_dir.join("report.md")));

    let cfg = ScanConfig {
        root,
        hash_all,
        deep_rds5: deep,
        scan_open,
        verify_indexes: !no_indexes,
        indexes_dir,
        extra_indexes,
        out_json,
        out_md,
        work_dir,
    };
    let cancel = xbs_core::new_cancel();
    let mut next_progress = std::time::Instant::now();
    let mut code = 0;
    pipeline::run(&cfg, &cancel, &mut |ev| match ev {
        Event::Stage(s) => {
            eprintln!("\n== {} ==", crate::i18n::stage(lang, &s));
        }
        Event::Progress { stage, done, total } => {
            let now = std::time::Instant::now();
            if now < next_progress && (total == 0 || done < total) {
                return;
            }
            next_progress = now + std::time::Duration::from_millis(150);
            let stage = crate::i18n::stage(lang, &stage);
            if total > 0 {
                let pct = done as f64 * 100.0 / total as f64;
                eprint!("\r{stage}: {done}/{total} ({pct:.1}%)   ");
            } else {
                eprint!("\r{stage}: {done}   ");
            }
        }
        Event::Log(s) => eprintln!("\n{s}"),
        Event::Done(r) => {
            eprintln!();
            println!("{}", xbs_report::to_markdown(&r));
        }
        Event::Failed(s) => {
            eprintln!("\n{}: {s}", crate::i18n::tr(lang, "error"));
            code = 1;
        }
        Event::Cancelled => {
            eprintln!("\n{}", crate::i18n::tr(lang, "cancelled"));
            code = 130;
        }
    });
    code
}

pub fn selftest() -> i32 {
    let results = crate::selftest::run();
    let passed = results.iter().filter(|t| t.passed).count();
    for t in &results {
        println!(
            "[{}] {} — {}",
            if t.passed { "PASS" } else { "FAIL" },
            t.name,
            t.detail
        );
    }
    println!("{passed}/{} тестов прошли", results.len());
    let json = serde_json::json!({
        "schema": "xbox-inspector-selftest/1",
        "passed": passed,
        "total": results.len(),
        "tests": results,
    });
    if let Ok(p) = std::env::current_exe() {
        if let Some(dir) = p.parent() {
            let _ = std::fs::write(
                dir.join("work").join("selftest.json"),
                serde_json::to_vec_pretty(&json).unwrap(),
            );
        }
    }
    if passed == results.len() {
        0
    } else {
        1
    }
}
