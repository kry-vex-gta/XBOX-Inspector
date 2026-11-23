//! Package configuration parsing (MicrosoftGame.Config + appxmanifest.xml).

use crate::{Error, Result};
use quick_xml::events::Event;
use quick_xml::Reader;
use serde::Serialize;

#[derive(Debug, Clone, Default, Serialize)]
pub struct ExecDecl {
    pub name: String,
    pub id: String,
    pub target_device_family: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct GameConfig {
    pub title_id: String,
    pub store_id: String,
    pub msa_app_id: String,
    pub identity_name: String,
    pub identity_version: String,
    pub executables: Vec<ExecDecl>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct AppxManifest {
    pub identity_name: String,
    pub identity_version: String,
    pub publisher: String,
    pub display_name: String,
    pub application_id: String,
    pub executable: String,
}

fn attr(e: &quick_xml::events::BytesStart, key: &[u8]) -> String {
    for a in e.attributes().flatten() {
        if a.key.as_ref() == key {
            return String::from_utf8_lossy(&a.value).to_string();
        }
    }
    String::new()
}

pub fn parse_game_config(text: &str) -> Result<GameConfig> {
    let mut r = Reader::from_str(text);
    let mut cfg = GameConfig::default();
    let mut stack: Vec<String> = Vec::new();
    let mut current = String::new();
    loop {
        match r.read_event() {
            Ok(Event::Start(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                if name == "Identity" {
                    cfg.identity_name = attr(&e, b"Name");
                    cfg.identity_version = attr(&e, b"Version");
                }
                if name == "Executable" {
                    cfg.executables.push(ExecDecl {
                        name: attr(&e, b"Name"),
                        id: attr(&e, b"Id"),
                        target_device_family: attr(&e, b"TargetDeviceFamily"),
                    });
                }
                current = name.clone();
                stack.push(name);
            }
            Ok(Event::Empty(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                if name == "Identity" {
                    cfg.identity_name = attr(&e, b"Name");
                    cfg.identity_version = attr(&e, b"Version");
                }
                if name == "Executable" {
                    cfg.executables.push(ExecDecl {
                        name: attr(&e, b"Name"),
                        id: attr(&e, b"Id"),
                        target_device_family: attr(&e, b"TargetDeviceFamily"),
                    });
                }
            }
            Ok(Event::Text(t)) => {
                let v = t.unescape().unwrap_or_default().trim().to_string();
                if !v.is_empty() {
                    match current.as_str() {
                        "TitleId" => cfg.title_id = v,
                        "StoreId" => cfg.store_id = v,
                        "MSAAppId" => cfg.msa_app_id = v,
                        _ => {}
                    }
                }
            }
            Ok(Event::End(_)) => {
                stack.pop();
                current = stack.last().cloned().unwrap_or_default();
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(Error::Format(format!("MicrosoftGame.Config XML: {e}"))),
            _ => {}
        }
    }
    Ok(cfg)
}

pub fn parse_appxmanifest(text: &str) -> Result<AppxManifest> {
    let mut r = Reader::from_str(text);
    let mut m = AppxManifest::default();
    let mut current = String::new();
    loop {
        match r.read_event() {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                match name.as_str() {
                    "Identity" => {
                        m.identity_name = attr(&e, b"Name");
                        m.identity_version = attr(&e, b"Version");
                        m.publisher = attr(&e, b"Publisher");
                    }
                    "Application" => {
                        m.application_id = attr(&e, b"Id");
                        m.executable = attr(&e, b"Executable");
                    }
                    _ => {}
                }
                current = name;
            }
            Ok(Event::Text(t)) => {
                let v = t.unescape().unwrap_or_default().trim().to_string();
                if current == "DisplayName" && m.display_name.is_empty() && !v.is_empty() {
                    m.display_name = v;
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(Error::Format(format!("appxmanifest XML: {e}"))),
            _ => {}
        }
    }
    Ok(m)
}