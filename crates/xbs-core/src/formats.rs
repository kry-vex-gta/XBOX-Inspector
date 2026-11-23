use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FileKind {
    Rpf9,
    Rds5,
    PeDll,
    PeExecutable,
    PeNoEntry,
    Xvd,
    RegistryHive,
    Pri,
    Png,
    Xml,
    Bink,
    Empty,
    Unknown,
}

impl FileKind {
    pub fn label(self) -> &'static str {
        match self {
            FileKind::Rpf9 => "RPF9 container",
            FileKind::Rds5 => "RDS5 texture store",
            FileKind::PeDll => "PE DLL",
            FileKind::PeExecutable => "PE executable",
            FileKind::PeNoEntry => "PE without executable entry",
            FileKind::Xvd => "XVD disk image",
            FileKind::RegistryHive => "Registry hive (regf)",
            FileKind::Pri => "PRI resources (mrm_pri2)",
            FileKind::Png => "PNG image",
            FileKind::Xml => "XML text",
            FileKind::Bink => "Bink video",
            FileKind::Empty => "Empty file",
            FileKind::Unknown => "Unknown",
        }
    }
}

/// Classify by observed prefix bytes. PE files are refined by `pe::quick_classify`.
pub fn classify_prefix(p: &[u8], ext: &str) -> FileKind {
    if p.is_empty() {
        return FileKind::Empty;
    }
    if p.starts_with(b"9FPR") {
        return FileKind::Rpf9;
    }
    if p.starts_with(b"RDS5") {
        return FileKind::Rds5;
    }
    if p.starts_with(b"MZ") {
        return FileKind::PeExecutable; // refined later
    }
    if p.starts_with(b"regf") {
        return FileKind::RegistryHive;
    }
    if p.starts_with(b"mrm_pri2") {
        return FileKind::Pri;
    }
    if p.starts_with(&[0x89, b'P', b'N', b'G']) {
        return FileKind::Png;
    }
    if p.starts_with(b"KB2j") || p.starts_with(b"KB2n") {
        return FileKind::Bink;
    }
    let t = p.strip_prefix(&[0xEF, 0xBB, 0xBF][..]).unwrap_or(p);
    if t.starts_with(b"<?xml") || t.starts_with(b"<Package") || t.starts_with(b"<Game") {
        return FileKind::Xml;
    }
    if ext == "xvd" {
        return FileKind::Xvd;
    }
    FileKind::Unknown
}

/// Catalog state for container-like files. Deliberately does NOT claim an
/// encryption algorithm from entropy or coincidental bytes.
pub fn catalog_state(kind: FileKind) -> &'static str {
    match kind {
        FileKind::Rpf9 => "ENCRYPTED_OR_UNRESOLVED",
        FileKind::Xvd => "UNRESOLVED",
        FileKind::Rds5 => "OPEN_TABLE",
        FileKind::PeDll | FileKind::PeExecutable | FileKind::PeNoEntry => "OPEN_PE",
        FileKind::RegistryHive | FileKind::Pri | FileKind::Png | FileKind::Xml | FileKind::Bink => {
            "OPEN_FORMAT"
        }
        FileKind::Empty => "EMPTY",
        FileKind::Unknown => "UNRESOLVED",
    }
}