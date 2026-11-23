//! Persistent UI settings, stored OUTSIDE the game folder (%APPDATA%).

use crate::i18n::Lang;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Theme {
    System,
    Light,
    Dark,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub lang: String,
    pub theme: Theme,
    #[serde(default)]
    pub last_folder: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            lang: "ru".into(),
            theme: Theme::System,
            last_folder: String::new(),
        }
    }
}

impl Settings {
    pub fn lang_enum(&self) -> Lang {
        Lang::from_code(&self.lang).unwrap_or(Lang::Ru)
    }

    pub fn path() -> Option<PathBuf> {
        let base = std::env::var_os("APPDATA")?;
        Some(
            PathBuf::from(base)
                .join("XBOX-Inspector")
                .join("settings.json"),
        )
    }

    pub fn load() -> Settings {
        Self::path()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, selected_source: Option<&Path>) {
        let Some(path) = Self::path() else { return };
        let Ok(data) = serde_json::to_vec_pretty(self) else {
            return;
        };
        if selected_source
            .is_some_and(|root| xbs_core::safe_path::outside_source(root, &path).is_err())
        {
            return;
        }
        if let Some(dir) = path.parent() {
            if std::fs::create_dir_all(dir).is_err() {
                return;
            }
        }
        if let Some(root) = selected_source {
            let _ = xbs_core::safe_path::write_outside(root, &path, &data);
        } else {
            let _ = std::fs::write(path, data);
        }
    }
}
