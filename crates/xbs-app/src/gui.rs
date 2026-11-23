//! egui GUI. Layout preserved from 0.2.0: folder row, explicit options,
//! check/cancel + progress, read-only log, summary with save links.
//! Added: compact theme/language selectors, 4 locales, embedded OFL fonts,
//! per-pass counters, settings persisted outside the game folder.

use crate::i18n::{tr, Lang};
use crate::pipeline::{self, Event, ScanConfig};
use crate::settings::{Settings, Theme};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::mpsc::{sync_channel, Receiver};
use xbs_core::Cancel;

pub fn run(prefill: Option<String>) -> i32 {
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([1060.0, 780.0])
            .with_visible(std::env::var_os("XBS_SMOKE_HIDDEN").is_none())
            .with_title("XBOX-Inspector"),
        ..Default::default()
    };
    match eframe::run_native(
        "XBOX-Inspector",
        options,
        Box::new(move |cc| {
            install_fonts(&cc.egui_ctx);
            Ok(Box::new(App::new(prefill.clone())))
        }),
    ) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("GUI error: {e}");
            1
        }
    }
}

fn install_fonts(ctx: &eframe::egui::Context) {
    let mut fonts = eframe::egui::FontDefinitions::default();
    fonts.font_data.insert(
        "noto".into(),
        std::sync::Arc::new(eframe::egui::FontData::from_owned(
            include_bytes!("../../../assets/fonts/NotoSans-Regular.ttf").to_vec(),
        )),
    );
    fonts.font_data.insert(
        "noto-sc".into(),
        std::sync::Arc::new(eframe::egui::FontData::from_owned(
            include_bytes!("../../../assets/fonts/NotoSansSC-Regular.ttf").to_vec(),
        )),
    );
    let prop = fonts
        .families
        .entry(eframe::egui::FontFamily::Proportional)
        .or_default();
    prop.insert(0, "noto".into());
    prop.push("noto-sc".into());
    let mono = fonts
        .families
        .entry(eframe::egui::FontFamily::Monospace)
        .or_default();
    mono.push("noto".into());
    mono.push("noto-sc".into());
    ctx.set_fonts(fonts);
}

struct App {
    path: String,
    hash_all: bool,
    deep: bool,
    scan_open: bool,
    verify_indexes: bool,
    running: bool,
    cancel: Cancel,
    rx: Option<Receiver<Event>>,
    stage: String,
    progress: (u64, u64),
    log: VecDeque<String>,
    report: Option<std::sync::Arc<xbs_report::Report>>,
    report_file: Option<PathBuf>,
    error: Option<String>,
    saved_note: Option<String>,
    settings: Settings,
}

impl App {
    fn new(prefill: Option<String>) -> Self {
        let settings = Settings::load();
        let path = prefill
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| settings.last_folder.clone());
        Self {
            path,
            hash_all: false,
            deep: false,
            scan_open: false,
            verify_indexes: true,
            running: false,
            cancel: xbs_core::new_cancel(),
            rx: None,
            stage: String::new(),
            progress: (0, 0),
            log: VecDeque::new(),
            report: None,
            report_file: None,
            error: None,
            saved_note: None,
            settings,
        }
    }

    fn lang(&self) -> Lang {
        self.settings.lang_enum()
    }

    fn push_log(&mut self, s: String) {
        if self.log.len() >= 2000 {
            self.log.pop_front();
        }
        self.log.push_back(s);
    }

    fn start(&mut self) {
        let root = PathBuf::from(self.path.trim());
        if !root.is_dir() {
            self.error = Some(format!(
                "{}: {}",
                tr(self.lang(), "err_folder"),
                root.display()
            ));
            return;
        }
        self.settings.last_folder = self.path.clone();
        self.settings.save(Some(&root));
        self.error = None;
        self.report = None;
        self.report_file = None;
        self.saved_note = None;
        self.log.clear();
        self.running = true;
        self.cancel = xbs_core::new_cancel();
        let cancel = self.cancel.clone();
        let (tx, rx) = sync_channel(128);
        self.rx = Some(rx);
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.to_path_buf()))
            .unwrap_or_else(|| PathBuf::from("."));
        let work_dir = exe_dir.join("work");
        let report_file = work_dir.join("gui-report.json");
        self.report_file = Some(report_file.clone());
        let cfg = ScanConfig {
            root,
            hash_all: self.hash_all,
            deep_rds5: self.deep,
            scan_open: self.scan_open,
            verify_indexes: self.verify_indexes,
            indexes_dir: Some(pipeline::default_indexes_dir(&exe_dir)),
            extra_indexes: Vec::new(),
            out_json: Some(report_file),
            out_md: None,
            work_dir,
        };
        std::thread::spawn(move || {
            pipeline::run(&cfg, &cancel, &mut |ev| {
                if matches!(ev, Event::Progress { .. }) {
                    let _ = tx.try_send(ev);
                } else {
                    let _ = tx.send(ev);
                }
            });
        });
    }

    fn drain(&mut self) {
        let Some(rx) = self.rx.take() else { return };
        let mut disconnected = false;
        let lang = self.lang();
        for _ in 0..400 {
            match rx.try_recv() {
                Ok(Event::Stage(s)) => {
                    self.stage = crate::i18n::stage(lang, &s);
                    self.progress = (0, 0);
                    self.push_log(format!("== {} ==", self.stage));
                }
                Ok(Event::Progress { stage, done, total }) => {
                    self.stage = crate::i18n::stage(lang, &stage);
                    self.progress = (if total == 0 { done } else { done.min(total) }, total);
                }
                Ok(Event::Log(s)) => self.push_log(s),
                Ok(Event::Done(r)) => {
                    self.push_log(format!(
                        "{}: {} {}, {} {}",
                        tr(lang, "done"),
                        r.file_count,
                        tr(lang, "files"),
                        r.logical_bytes,
                        tr(lang, "size")
                    ));
                    self.report = Some(std::sync::Arc::new(*r));
                    self.running = false;
                }
                Ok(Event::Cancelled) => {
                    self.push_log(tr(lang, "cancelled").to_string());
                    self.running = false;
                }
                Ok(Event::Failed(s)) => {
                    let msg = format!("{}: {s}", tr(lang, "error"));
                    self.push_log(msg.clone());
                    self.error = Some(msg);
                    self.running = false;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    disconnected = true;
                    if self.running {
                        self.running = false;
                    }
                    break;
                }
            }
        }
        if !disconnected {
            self.rx = Some(rx);
        }
    }

    fn save_report(&mut self, markdown: bool) {
        let Some(report) = &self.report else { return };
        let name = if markdown { "report.md" } else { "report.json" };
        if let Some(dest) = rfd::FileDialog::new().set_file_name(name).save_file() {
            let data = if markdown {
                xbs_report::to_markdown(report).into_bytes()
            } else {
                serde_json::to_vec_pretty(report.as_ref()).unwrap()
            };
            match xbs_core::safe_path::write_outside(
                std::path::Path::new(&report.source_root),
                &dest,
                &data,
            ) {
                Ok(()) => {
                    self.saved_note =
                        Some(format!("{}: {}", tr(self.lang(), "saved"), dest.display()))
                }
                Err(e) => self.error = Some(format!("{}: {e}", tr(self.lang(), "err_save"))),
            }
        }
    }

    #[cfg(windows)]
    fn open_report(&mut self) {
        let Some(path) = self.report_file.as_ref() else {
            return;
        };
        let Some(system) = std::env::var_os("SystemRoot") else {
            return;
        };
        let editor = PathBuf::from(system).join("System32").join("notepad.exe");
        if let Err(e) = std::process::Command::new(editor).arg(path).spawn() {
            self.error = Some(format!("{}: {e}", tr(self.lang(), "error")));
        }
    }

    fn apply_theme(&self, ctx: &eframe::egui::Context) {
        use eframe::egui;
        let visuals = match self.settings.theme {
            Theme::Light => egui::Visuals::light(),
            Theme::Dark => egui::Visuals::dark(),
            Theme::System => match ctx.system_theme() {
                Some(egui::Theme::Light) => egui::Visuals::light(),
                _ => egui::Visuals::dark(),
            },
        };
        ctx.set_visuals(visuals);
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &eframe::egui::Context, _frame: &mut eframe::Frame) {
        self.drain();
        self.apply_theme(ctx);
        if self.running {
            ctx.request_repaint_after(std::time::Duration::from_millis(80));
        }
        let lang = self.lang();

        eframe::egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.heading(format!("XBOX-Inspector {}", env!("CARGO_PKG_VERSION")));
                ui.with_layout(
                    eframe::egui::Layout::right_to_left(eframe::egui::Align::Center),
                    |ui| {
                        // language selector (compact, right side)
                        let mut lang = self.settings.lang_enum();
                        eframe::egui::ComboBox::from_id_salt("lang")
                            .selected_text(lang.label())
                            .show_ui(ui, |ui| {
                                for l in Lang::ALL {
                                    if ui.selectable_label(lang == l, l.label()).clicked() {
                                        lang = l;
                                    }
                                }
                            });
                        if lang != self.settings.lang_enum() {
                            self.settings.lang = lang.code().to_string();
                            let selected = std::path::Path::new(self.path.trim());
                            self.settings.save(selected.is_dir().then_some(selected));
                        }
                        // theme selector
                        let theme_key = match self.settings.theme {
                            Theme::System => "theme_system",
                            Theme::Light => "theme_light",
                            Theme::Dark => "theme_dark",
                        };
                        let mut theme = self.settings.theme;
                        eframe::egui::ComboBox::from_id_salt("theme")
                            .selected_text(tr(lang, theme_key))
                            .show_ui(ui, |ui| {
                                for (t, k) in [
                                    (Theme::System, "theme_system"),
                                    (Theme::Light, "theme_light"),
                                    (Theme::Dark, "theme_dark"),
                                ] {
                                    if ui.selectable_label(theme == t, tr(lang, k)).clicked() {
                                        theme = t;
                                    }
                                }
                            });
                        if theme != self.settings.theme {
                            self.settings.theme = theme;
                            let selected = std::path::Path::new(self.path.trim());
                            self.settings.save(selected.is_dir().then_some(selected));
                        }
                    },
                );
            });
            ui.label(tr(lang, "subtitle"));
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label(tr(lang, "folder"));
                ui.add(
                    eframe::egui::TextEdit::singleline(&mut self.path)
                        .desired_width(560.0)
                        .hint_text("C:\\path\\to\\build"),
                );
                if ui.button(tr(lang, "browse")).clicked() {
                    if let Some(p) = rfd::FileDialog::new().pick_folder() {
                        self.path = p.to_string_lossy().to_string();
                    }
                }
            });
            ui.add_space(4.0);
            ui.horizontal_wrapped(|ui| {
                ui.checkbox(&mut self.verify_indexes, tr(lang, "opt_indexes"));
                ui.checkbox(&mut self.scan_open, tr(lang, "opt_scan"));
                ui.checkbox(&mut self.deep, tr(lang, "opt_deep"));
                ui.checkbox(&mut self.hash_all, tr(lang, "opt_hash"));
            });
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if self.running {
                    if ui.button(tr(lang, "cancel")).clicked() {
                        self.cancel
                            .store(true, std::sync::atomic::Ordering::Relaxed);
                        self.push_log(tr(lang, "cancelling").to_string());
                    }
                    let (done, total) = self.progress;
                    if total > 0 {
                        ui.add(
                            eframe::egui::ProgressBar::new(done as f32 / total as f32)
                                .desired_width(300.0)
                                .text(format!("{done}/{total}")),
                        );
                    } else {
                        ui.add(
                            eframe::egui::ProgressBar::new(0.0)
                                .desired_width(300.0)
                                .text("…"),
                        );
                    }
                    ui.label(&self.stage);
                } else if ui.button(tr(lang, "check")).clicked() {
                    self.start();
                }
            });
            ui.add_space(4.0);
        });

        eframe::egui::CentralPanel::default().show(ctx, |ui| {
            if let Some(e) = &self.error {
                ui.colored_label(eframe::egui::Color32::from_rgb(220, 80, 80), e);
            }
            if let Some(note) = &self.saved_note {
                ui.colored_label(eframe::egui::Color32::from_rgb(80, 180, 100), note);
            }
            if let Some(r) = self.report.clone() {
                ui.group(|ui| {
                    ui.heading(tr(lang, "summary"));
                    ui.label(format!(
                        "{}: {} · {}: {} ({})",
                        tr(lang, "files"),
                        r.file_count,
                        tr(lang, "size"),
                        r.logical_bytes,
                        xbs_core::fmt_bytes(r.logical_bytes)
                    ));
                    let pf = &r.runtime_preflight;
                    ui.label(format!(
                        "{}: {} — {}",
                        tr(lang, "exe_declared"),
                        pf.declared_executable.clone().unwrap_or_else(|| "—".into()),
                        if pf.executable_found {
                            tr(lang, "found")
                        } else {
                            tr(lang, "missing")
                        }
                    ));
                    ui.label(format!(
                        "TitleId: {} · StoreId: {} · v{}",
                        pf.title_id, pf.store_id, pf.package_version
                    ));
                    for b in &pf.blockers {
                        ui.colored_label(
                            eframe::egui::Color32::from_rgb(230, 170, 60),
                            format!("⚠ {b}"),
                        );
                    }
                    if !pf.launch_ready {
                        ui.colored_label(
                            eframe::egui::Color32::from_rgb(230, 170, 60),
                            tr(lang, "not_ready"),
                        );
                    }
                    let t = &r.resource_totals;
                    ui.label(format!(
                        "RPF9: {} · RDS5: {} (ETPF {}) · PE DLL: {} · Bink ✓: {}",
                        t.rpf9_containers,
                        t.rds5_stores,
                        t.rds5_descriptors,
                        t.pe_dlls,
                        t.bink_records_verified
                    ));
                    ui.label(format!(
                        "{}: {} · {}: {} · {}: {} · {}: {}",
                        tr(lang, "zlib_found"),
                        t.zlib_members_found,
                        tr(lang, "bundled_hash"),
                        t.bundled_ranges_verified_hash,
                        tr(lang, "additional_hash"),
                        t.additional_ranges_verified_hash,
                        tr(lang, "total_hash"),
                        t.ranges_verified_hash
                    ));
                    if !r.passes.is_empty() {
                        ui.collapsing(tr(lang, "passes"), |ui| {
                            for p in &r.passes {
                                let counters: Vec<String> =
                                    p.counters.iter().map(|(k, v)| format!("{k}={v}")).collect();
                                ui.label(format!(
                                    "{} [{}] {} — {}",
                                    p.name,
                                    p.mode,
                                    p.finished_utc,
                                    counters.join(", ")
                                ));
                            }
                        });
                    }
                    ui.horizontal(|ui| {
                        ui.label(tr(lang, "report"));
                        #[cfg(windows)]
                        if ui
                            .add(eframe::egui::Link::new(tr(lang, "open_report")))
                            .clicked()
                        {
                            self.open_report();
                        }
                        if ui
                            .add(eframe::egui::Link::new(tr(lang, "save_json")))
                            .clicked()
                        {
                            self.save_report(false);
                        }
                        if ui
                            .add(eframe::egui::Link::new(tr(lang, "save_md")))
                            .clicked()
                        {
                            self.save_report(true);
                        }
                    });
                });
                ui.add_space(6.0);
            }
            ui.heading(tr(lang, "log"));
            eframe::egui::ScrollArea::vertical()
                .stick_to_bottom(true)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.style_mut().override_font_id = Some(eframe::egui::FontId::monospace(12.0));
                    for line in &self.log {
                        ui.label(line);
                    }
                });
        });
    }
}
