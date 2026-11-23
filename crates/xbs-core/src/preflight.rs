//! Launch-readiness preflight. The inspector never substitutes a DLL or a test
//! program for the game, and never launches anything by itself in v0.2.0.

use crate::config::{AppxManifest, GameConfig};
use crate::inventory::InvFile;
use crate::pe::PeInfo;
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Clone, Serialize)]
pub struct RuntimePreflight {
    pub declared_executable: Option<String>,
    pub executable_found: bool,
    pub executable_path: Option<String>,
    pub title_id: String,
    pub store_id: String,
    pub package_version: String,
    pub target_device_family: String,
    pub pe_static: Option<PeInfo>,
    pub missing_dependencies: Vec<String>,
    pub launch_ready: bool,
    pub blockers: Vec<String>,
    pub compatibility_layer_status: String,
}

pub fn run(
    root: &Path,
    files: &[InvFile],
    cfg: Option<&GameConfig>,
    manifest: Option<&AppxManifest>,
) -> RuntimePreflight {
    let declared = cfg
        .and_then(|c| c.executables.first())
        .map(|e| e.name.clone())
        .or_else(|| manifest.map(|m| m.executable.clone()))
        .filter(|s| !s.is_empty());
    let family = cfg
        .and_then(|c| c.executables.first())
        .map(|e| e.target_device_family.clone())
        .unwrap_or_default();

    let mut pf = RuntimePreflight {
        declared_executable: declared.clone(),
        executable_found: false,
        executable_path: None,
        title_id: cfg.map(|c| c.title_id.clone()).unwrap_or_default(),
        store_id: cfg.map(|c| c.store_id.clone()).unwrap_or_default(),
        package_version: cfg
            .map(|c| c.identity_version.clone())
            .filter(|s| !s.is_empty())
            .or_else(|| manifest.map(|m| m.identity_version.clone()))
            .unwrap_or_default(),
        target_device_family: family,
        pe_static: None,
        missing_dependencies: Vec::new(),
        launch_ready: false,
        blockers: Vec::new(),
        compatibility_layer_status:
            "not_tested: XCL/ScarlettX are external layers; a full permitted package is required"
                .into(),
    };

    let Some(name) = declared else {
        pf.blockers
            .push("Конфигурация не объявляет исполняемый файл".into());
        return pf;
    };

    let found = files.iter().find(|f| f.rel.eq_ignore_ascii_case(&name));
    let Some(entry) = found else {
        pf.blockers.push(format!(
            "В манифесте указан исполняемый файл, отсутствующий в папке: {name}"
        ));
        return pf;
    };
    pf.executable_found = true;
    pf.executable_path = Some(entry.rel.clone());

    match crate::safe_path::resolve_within(root, &entry.rel)
        .and_then(|path| crate::pe::parse(&path))
    {
        Ok(pe) => {
            if pe.machine != 0x8664 {
                pf.blockers.push(format!(
                    "Неподдерживаемая машина PE для Scarlett: 0x{:04x} (ожидается x64)",
                    pe.machine
                ));
            }
            if pe.is_dll || !pe.entry_in_executable_section {
                pf.blockers
                    .push("PE без исполняемой точки входа — не игровой модуль".into());
            }
            let known: Vec<String> = files
                .iter()
                .filter(|f| matches!(f.kind, crate::formats::FileKind::PeDll))
                .map(|f| f.rel.rsplit('/').next().unwrap_or(&f.rel).to_lowercase())
                .collect();
            for imp in &pe.imports {
                let base = imp.rsplit(['/', '\\']).next().unwrap_or(imp).to_lowercase();
                if !known.contains(&base) && !is_system_dll(&base) {
                    pf.missing_dependencies.push(imp.clone());
                }
            }
            if !pf.missing_dependencies.is_empty() {
                pf.blockers.push(format!(
                    "Отсутствуют зависимости: {}",
                    pf.missing_dependencies.join(", ")
                ));
            }
            pf.pe_static = Some(pe);
        }
        Err(e) => {
            pf.blockers
                .push(format!("Статический разбор PE не удался: {e}"));
        }
    }

    // Even with a complete static picture, launching requires an explicit
    // permitted full package and a documented compatibility layer session.
    pf.blockers.push(
        "Тестовый запуск не выполнялся: требуется полный разрешённый пакет и явное разрешение пользователя".into(),
    );
    pf.launch_ready = false;
    pf
}

fn is_system_dll(name: &str) -> bool {
    const SYS: &[&str] = &[
        "kernel32.dll",
        "user32.dll",
        "gdi32.dll",
        "advapi32.dll",
        "shell32.dll",
        "ole32.dll",
        "oleaut32.dll",
        "ws2_32.dll",
        "winmm.dll",
        "version.dll",
        "bcrypt.dll",
        "ncrypt.dll",
        "crypt32.dll",
        "wintrust.dll",
        "dbghelp.dll",
        "dxgi.dll",
        "d3d11.dll",
        "d3d12.dll",
        "xinput1_4.dll",
        "xaudio2_9.dll",
        "winhttp.dll",
        "iphlpapi.dll",
        "secur32.dll",
        "userenv.dll",
        "profapi.dll",
        "setupapi.dll",
        "cfgmgr32.dll",
        "powrprof.dll",
        "propsys.dll",
        "shlwapi.dll",
        "msvcrt.dll",
        "ntdll.dll",
        "api-ms-win-",
        "ext-ms-win-",
        "d3dcompiler_47.dll",
        "dxcore.dll",
        "wininet.dll",
        "normaliz.dll",
        "wldap32.dll",
        "cryptbase.dll",
        "msasn1.dll",
        "gpapi.dll",
        "dwmapi.dll",
        "uxtheme.dll",
        "imm32.dll",
        "msctf.dll",
        "combase.dll",
        "rpcrt4.dll",
        "sspicli.dll",
        "cryptsp.dll",
        "windows.storage.dll",
        "kernel.appcore.dll",
        "devobj.dll",
        "drprov.dll",
        "ntmarta.dll",
        "winsta.dll",
        "xmlreader.dll",
    ];
    SYS.contains(&name) || name.starts_with("api-ms-win-") || name.starts_with("ext-ms-win-")
}
