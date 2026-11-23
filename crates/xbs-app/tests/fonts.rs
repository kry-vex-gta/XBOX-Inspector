//! Font glyph coverage for the required locales (spec items 87/88).

#[path = "../src/i18n.rs"]
mod i18n;

use ab_glyph::Font;

fn noto() -> ab_glyph::FontRef<'static> {
    ab_glyph::FontRef::try_from_slice(include_bytes!("../../../assets/fonts/NotoSans-Regular.ttf"))
        .unwrap()
}

fn noto_sc() -> ab_glyph::FontRef<'static> {
    ab_glyph::FontRef::try_from_slice(include_bytes!(
        "../../../assets/fonts/NotoSansSC-Regular.ttf"
    ))
    .unwrap()
}

#[test]
fn kazakh_glyphs_present() {
    let f = noto();
    for c in ['Ә', 'Ғ', 'Қ', 'Ң', 'Ө', 'Ұ', 'Ү', 'Һ', 'І'] {
        assert_ne!(f.glyph_id(c).0, 0, "Noto Sans missing Kazakh glyph {c}");
    }
}

#[test]
fn russian_glyphs_present() {
    let f = noto();
    for c in [
        'П', 'р', 'о', 'в', 'е', 'к', 'а', 'ж', 'у', 'р', 'н', 'а', 'л',
    ] {
        assert_ne!(f.glyph_id(c).0, 0, "Noto Sans missing Cyrillic glyph {c}");
    }
}

#[test]
fn chinese_glyphs_present() {
    let f = noto_sc();
    for c in ['中', '文', '检', '查', '主', '题', '语', '言', '报', '告'] {
        assert_ne!(f.glyph_id(c).0, 0, "Noto Sans SC missing glyph {c}");
    }
}

#[test]
fn ui_dictionaries_complete() {
    // every key used by the GUI must resolve in all four locales (no fallback)
    let keys = [
        "subtitle",
        "folder",
        "browse",
        "check",
        "cancel",
        "cancelling",
        "opt_indexes",
        "opt_scan",
        "opt_deep",
        "opt_hash",
        "theme",
        "theme_system",
        "theme_light",
        "theme_dark",
        "language",
        "log",
        "summary",
        "files",
        "size",
        "exe_declared",
        "found",
        "missing",
        "report",
        "save_json",
        "save_md",
        "saved",
        "passes",
        "err_folder",
        "err_save",
        "done",
        "error",
        "selftests",
        "not_ready",
        "cancelled",
        "zlib_found",
        "bundled_hash",
        "additional_hash",
        "total_hash",
        "inventory",
        "configuration",
        "full_hash",
        "rpf_header",
        "rds5_table",
        "indexed",
        "discover",
        "range_item",
        "index_item",
        "zlib_item",
        "bink_item",
        "video_item",
        "open_report",
    ];
    for lang in i18n::Lang::ALL {
        assert_eq!(i18n::Lang::from_code(lang.code()), Some(lang));
        assert!(!lang.label().is_empty());
        for k in keys {
            let v = i18n::tr(lang, k);
            assert!(!v.is_empty(), "locale {} missing key {k}", lang.code());
        }
        let sample = i18n::stage(lang, "Видеоиндекс movies.rpf");
        assert!(sample.ends_with("movies.rpf") && sample.starts_with(i18n::tr(lang, "video_item")));
    }
}

#[test]
fn json_status_codes_locale_independent() {
    // stable codes must not change with UI language
    let codes = [
        format!("{:?}", xbs_ranges::Status::VerifiedHash),
        format!("{:?}", xbs_ranges::Status::TruncatedFile),
    ];
    assert_eq!(codes[0], "VerifiedHash");
    assert_eq!(codes[1], "TruncatedFile");
    for lang in i18n::Lang::ALL {
        let _ = i18n::tr(lang, "done");
        assert_eq!(
            format!("{:?}", xbs_ranges::Status::VerifiedHash),
            "VerifiedHash"
        );
    }
}
