use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize, Default)]
struct Config {
    vault_path: Option<String>,
    #[serde(default)]
    autostart_initialized: bool,
    #[serde(default)]
    discreet: bool,
    #[serde(default)]
    sync_dir: Option<String>,
    #[serde(default)]
    device_id: Option<String>,
}

fn load(config_file: &Path) -> Config {
    std::fs::read(config_file)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Config>(&bytes).ok())
        .unwrap_or_default()
}

fn save(config_file: &Path, config: &Config) -> Result<(), ()> {
    if let Some(parent) = config_file.parent() {
        std::fs::create_dir_all(parent).map_err(|_| ())?;
    }
    let json = serde_json::to_vec_pretty(config).map_err(|_| ())?;
    std::fs::write(config_file, json).map_err(|_| ())
}

pub fn vault_path(config_file: &Path, default_path: PathBuf) -> PathBuf {
    match load(config_file).vault_path {
        Some(path) => PathBuf::from(path),
        None => default_path,
    }
}

pub fn set_vault_path(config_file: &Path, vault: &Path) -> Result<(), ()> {
    let mut config = load(config_file);
    config.vault_path = Some(vault.to_string_lossy().into_owned());
    save(config_file, &config)
}

pub fn autostart_initialized(config_file: &Path) -> bool {
    load(config_file).autostart_initialized
}

pub fn discreet(config_file: &Path) -> bool {
    load(config_file).discreet
}

pub fn set_discreet(config_file: &Path, on: bool) -> Result<(), ()> {
    let mut config = load(config_file);
    config.discreet = on;
    save(config_file, &config)
}

pub fn mark_autostart_initialized(config_file: &Path) -> Result<(), ()> {
    let mut config = load(config_file);
    config.autostart_initialized = true;
    save(config_file, &config)
}

pub fn sync_dir(config_file: &Path) -> Option<String> {
    load(config_file).sync_dir
}

pub fn set_sync_dir(config_file: &Path, dir: Option<&Path>) -> Result<(), ()> {
    let mut config = load(config_file);
    config.sync_dir = dir.map(|p| p.to_string_lossy().into_owned());
    save(config_file, &config)
}

pub fn device_id_or(config_file: &Path, candidate: &str) -> String {
    let mut config = load(config_file);
    if let Some(id) = config.device_id {
        return id;
    }
    config.device_id = Some(candidate.to_string());
    let _ = save(config_file, &config);
    candidate.to_string()
}
