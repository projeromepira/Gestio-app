mod config;
mod crypto;
mod generator;
mod keywrap;
mod totp;
mod vault;

use generator::PasswordOptions;
use std::path::PathBuf;
use tauri::{AppHandle, Manager, State};
use tauri_plugin_clipboard_manager::ClipboardExt;
use tauri_plugin_dialog::DialogExt;
use totp::{TotpCode, TotpError, TotpInput, TotpMeta, TotpState};
use vault::{EntryInput, EntryMeta, EntryOrder, VaultError, VaultState};
use zeroize::Zeroize;

fn is_disguised(app: &AppHandle) -> bool {
    app.config().identifier == "com.notely.app"
}

fn vault_filename(app: &AppHandle) -> &'static str {
    if is_disguised(app) {
        "notes.dat"
    } else {
        "vault.gestio"
    }
}

fn totp_filename(app: &AppHandle) -> &'static str {
    if is_disguised(app) {
        "cache.dat"
    } else {
        "totp.gestio"
    }
}

fn brand_folder(app: &AppHandle) -> &'static str {
    if is_disguised(app) {
        "Notely"
    } else {
        "Gestio"
    }
}

fn totp_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|_| "e.internal".to_string())?;
    Ok(dir.join(totp_filename(app)))
}

fn totp_message(err: TotpError) -> String {
    match err {
        TotpError::AlreadyExists => "e.totpExists".into(),
        TotpError::NotFound => "e.totpNotFound".into(),
        TotpError::Locked => "e.totpLocked".into(),
        TotpError::WrongPassword => "e.wrongPassword".into(),
        TotpError::EntryNotFound => "e.entryNotFound".into(),
        TotpError::InvalidSecret => "e.invalidSecret".into(),
        TotpError::NoRecovery => "e.noRecovery".into(),
        TotpError::Corrupt => "e.totpCorrupt".into(),
        TotpError::Io | TotpError::Crypto => "e.internal".into(),
    }
}

#[tauri::command(async)]
fn totp_exists(app: AppHandle) -> Result<bool, String> {
    Ok(totp_path(&app)?.exists())
}

#[tauri::command(async)]
fn totp_is_unlocked(state: State<TotpState>) -> bool {
    state.is_unlocked()
}

#[tauri::command(async)]
fn create_totp(
    app: AppHandle,
    state: State<TotpState>,
    mut master_password: String,
    with_recovery: bool,
) -> Result<Option<String>, String> {
    let path = totp_path(&app)?;
    let res = state
        .create(&path, master_password.as_bytes(), with_recovery)
        .map_err(totp_message);
    master_password.zeroize();
    res
}

#[tauri::command(async)]
fn unlock_totp_recovery(
    app: AppHandle,
    state: State<TotpState>,
    mut recovery: String,
) -> Result<(), String> {
    let path = totp_path(&app)?;
    let res = state.unlock_recovery(&path, &recovery).map_err(totp_message);
    recovery.zeroize();
    res
}

#[tauri::command(async)]
fn reset_totp_master_password(
    app: AppHandle,
    state: State<TotpState>,
    mut new: String,
) -> Result<(), String> {
    let path = totp_path(&app)?;
    let res = state.reset_master_password(&path, new.as_bytes()).map_err(totp_message);
    new.zeroize();
    res
}

#[tauri::command(async)]
fn setup_totp_recovery(app: AppHandle, state: State<TotpState>) -> Result<String, String> {
    let path = totp_path(&app)?;
    state.setup_recovery(&path).map_err(totp_message)
}

#[tauri::command(async)]
fn remove_totp_recovery(app: AppHandle, state: State<TotpState>) -> Result<(), String> {
    let path = totp_path(&app)?;
    state.remove_recovery(&path).map_err(totp_message)
}

#[tauri::command(async)]
fn has_totp_recovery(state: State<TotpState>) -> bool {
    state.has_recovery()
}

#[tauri::command(async)]
fn totp_has_recovery(app: AppHandle) -> Result<bool, String> {
    Ok(totp::peek_has_recovery(&totp_path(&app)?))
}

#[tauri::command(async)]
fn unlock_totp(
    app: AppHandle,
    state: State<TotpState>,
    mut master_password: String,
) -> Result<(), String> {
    let path = totp_path(&app)?;
    let res = state.unlock(&path, master_password.as_bytes()).map_err(totp_message);
    master_password.zeroize();
    res
}

#[tauri::command(async)]
fn lock_totp(state: State<TotpState>) {
    state.lock();
}

#[tauri::command(async)]
fn change_totp_master_password(
    app: AppHandle,
    state: State<TotpState>,
    mut current: String,
    mut new: String,
) -> Result<(), String> {
    let path = totp_path(&app)?;
    let res = state
        .change_master_password(&path, current.as_bytes(), new.as_bytes())
        .map_err(totp_message);
    current.zeroize();
    new.zeroize();
    res
}

#[tauri::command(async)]
fn list_totp(state: State<TotpState>) -> Result<Vec<TotpMeta>, String> {
    state.list().map_err(totp_message)
}

#[tauri::command(async)]
fn add_totp(app: AppHandle, state: State<TotpState>, input: TotpInput) -> Result<String, String> {
    let path = totp_path(&app)?;
    state.add(&path, input).map_err(totp_message)
}

#[tauri::command(async)]
fn delete_totp(app: AppHandle, state: State<TotpState>, id: String) -> Result<(), String> {
    let path = totp_path(&app)?;
    state.delete(&path, &id).map_err(totp_message)
}

#[tauri::command(async)]
fn totp_codes(state: State<TotpState>) -> Result<Vec<TotpCode>, String> {
    state.codes().map_err(totp_message)
}

fn vault_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|_| "e.internal".to_string())?;
    Ok(config::vault_path(
        &dir.join("config.json"),
        dir.join(vault_filename(app)),
    ))
}

fn user_message(err: VaultError) -> String {
    match err {
        VaultError::AlreadyExists => "e.alreadyExists".into(),
        VaultError::NotFound => "e.notFound".into(),
        VaultError::Locked => "e.locked".into(),
        VaultError::WrongPassword => "e.wrongPassword".into(),
        VaultError::EntryNotFound => "e.entryNotFound".into(),
        VaultError::GroupExists => "e.groupExists".into(),
        VaultError::GroupNameEmpty => "e.groupNameEmpty".into(),
        VaultError::NoRecovery => "e.noRecovery".into(),
        VaultError::Corrupt => "e.corrupt".into(),
        VaultError::Io | VaultError::Crypto => "e.internal".into(),
    }
}

#[tauri::command(async)]
fn vault_exists(app: AppHandle) -> Result<bool, String> {
    Ok(vault_path(&app)?.exists())
}

#[tauri::command(async)]
fn vault_location(app: AppHandle) -> Result<String, String> {
    Ok(vault_path(&app)?.to_string_lossy().into_owned())
}

#[tauri::command(async)]
fn change_vault_location(app: AppHandle) -> Result<String, String> {
    let current = vault_path(&app)?;
    let picked = app.dialog().file().blocking_pick_folder();
    let Some(picked) = picked else {
        return Ok(current.to_string_lossy().into_owned());
    };
    let new_dir = picked.into_path().map_err(|_| "e.internal".to_string())?;
    let new_path = new_dir.join(brand_folder(&app)).join(vault_filename(&app));
    if new_path == current {
        return Ok(current.to_string_lossy().into_owned());
    }
    if new_path.exists() {
        return Err("e.vaultAtLocation".to_string());
    }
    if let Some(parent) = new_path.parent() {
        std::fs::create_dir_all(parent).map_err(|_| "e.internal".to_string())?;
    }
    if current.exists() {
        std::fs::copy(&current, &new_path).map_err(|_| "e.copyFailed".to_string())?;
    }
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|_| "e.internal".to_string())?;
    config::set_vault_path(&dir.join("config.json"), &new_path)
        .map_err(|_| "e.internal".to_string())?;
    if current.exists() {
        let _ = std::fs::remove_file(&current);
    }
    Ok(new_path.to_string_lossy().into_owned())
}

#[tauri::command(async)]
fn export_vault(app: AppHandle) -> Result<bool, String> {
    let current = vault_path(&app)?;
    if !current.exists() {
        return Err("e.notFound".to_string());
    }
    let picked = app
        .dialog()
        .file()
        .add_filter("Gestio", &["gestio"])
        .set_file_name("gestio-backup.gestio")
        .blocking_save_file();
    let Some(picked) = picked else {
        return Ok(false);
    };
    let dest = picked.into_path().map_err(|_| "e.internal".to_string())?;
    std::fs::copy(&current, &dest).map_err(|_| "e.copyFailed".to_string())?;
    Ok(true)
}

#[tauri::command(async)]
fn restore_vault(app: AppHandle, state: State<VaultState>) -> Result<bool, String> {
    let picked = app
        .dialog()
        .file()
        .add_filter("Gestio", &["gestio"])
        .blocking_pick_file();
    let Some(picked) = picked else {
        return Ok(false);
    };
    let src = picked.into_path().map_err(|_| "e.internal".to_string())?;
    let bytes = std::fs::read(&src).map_err(|_| "e.internal".to_string())?;
    if !vault::is_valid_backup(&bytes) {
        return Err("e.badBackup".to_string());
    }
    let current = vault_path(&app)?;
    if let Some(parent) = current.parent() {
        std::fs::create_dir_all(parent).map_err(|_| "e.internal".to_string())?;
    }
    let name = current
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("vault.gestio")
        .to_string();
    let backup = current.with_file_name(format!("{name}.bak"));
    if current.exists() {
        std::fs::copy(&current, &backup).map_err(|_| "e.internal".to_string())?;
    }
    let tmp = current.with_file_name(format!("{name}.tmp"));
    std::fs::write(&tmp, &bytes).map_err(|_| "e.internal".to_string())?;
    if std::fs::rename(&tmp, &current).is_err() {
        let _ = std::fs::remove_file(&tmp);
        let _ = std::fs::remove_file(&backup);
        return Err("e.internal".to_string());
    }
    let _ = std::fs::remove_file(&backup);
    state.lock();
    Ok(true)
}

#[derive(Clone, Copy)]
enum CsvField {
    Name,
    Username,
    Password,
    Url,
    Note,
    Group,
}

fn map_csv_header(h: &str) -> Option<CsvField> {
    match h.trim().to_lowercase().as_str() {
        "name" | "title" | "account" | "item name" | "entry name" => Some(CsvField::Name),
        "username" | "user" | "login_username" | "login name" | "email" | "e-mail" => {
            Some(CsvField::Username)
        }
        "password" | "pass" | "login_password" => Some(CsvField::Password),
        "url" | "uri" | "urls" | "website" | "login_uri" | "web site" | "link" => {
            Some(CsvField::Url)
        }
        "notes" | "note" | "extra" | "comments" | "comment" => Some(CsvField::Note),
        "folder" | "grouping" | "group" | "category" | "collection" | "collections" => {
            Some(CsvField::Group)
        }
        _ => None,
    }
}

fn parse_csv(bytes: &[u8]) -> Result<Vec<EntryInput>, String> {
    let mut reader = csv::ReaderBuilder::new().flexible(true).from_reader(bytes);
    let headers = reader.headers().map_err(|_| "e.csvInvalid".to_string())?.clone();
    let cols: Vec<Option<CsvField>> = headers.iter().map(map_csv_header).collect();
    if !cols.iter().any(|c| c.is_some()) {
        return Err("e.csvInvalid".to_string());
    }
    let mut out = Vec::new();
    for record in reader.records() {
        let record = match record {
            Ok(r) => r,
            Err(_) => continue,
        };
        let mut name = String::new();
        let mut username = String::new();
        let mut password = String::new();
        let mut url = String::new();
        let mut note = String::new();
        let mut group = String::new();
        for (i, val) in record.iter().enumerate() {
            match cols.get(i).copied().flatten() {
                Some(CsvField::Name) if name.is_empty() => name = val.to_string(),
                Some(CsvField::Username) if username.is_empty() => username = val.to_string(),
                Some(CsvField::Password) if password.is_empty() => password = val.to_string(),
                Some(CsvField::Url) if url.is_empty() => url = val.to_string(),
                Some(CsvField::Note) if note.is_empty() => note = val.to_string(),
                Some(CsvField::Group) if group.is_empty() => group = val.to_string(),
                _ => {}
            }
        }
        if name.is_empty()
            && username.is_empty()
            && password.is_empty()
            && url.is_empty()
            && note.is_empty()
        {
            continue;
        }
        if name.trim().is_empty() {
            name = if !username.is_empty() {
                username.clone()
            } else if !url.is_empty() {
                url.clone()
            } else {
                "Import".to_string()
            };
        }
        let kind = if password.is_empty() && username.is_empty() && !note.is_empty() {
            "note".to_string()
        } else {
            "login".to_string()
        };
        out.push(EntryInput {
            name: name.trim().to_string(),
            username,
            password,
            url: url.trim().to_string(),
            note,
            group: group.trim().to_string(),
            kind,
            fields: Vec::new(),
        });
    }
    Ok(out)
}

#[tauri::command(async)]
fn import_csv(app: AppHandle, state: State<VaultState>) -> Result<usize, String> {
    if !state.is_unlocked() {
        return Err("e.locked".to_string());
    }
    let picked = app
        .dialog()
        .file()
        .add_filter("CSV", &["csv"])
        .blocking_pick_file();
    let Some(picked) = picked else {
        return Ok(0);
    };
    let src = picked.into_path().map_err(|_| "e.internal".to_string())?;
    let size = std::fs::metadata(&src).map(|m| m.len()).unwrap_or(u64::MAX);
    if size > 10 * 1024 * 1024 {
        return Err("e.csvTooLarge".to_string());
    }
    let bytes = std::fs::read(&src).map_err(|_| "e.internal".to_string())?;
    let entries = parse_csv(&bytes)?;
    if entries.is_empty() {
        return Err("e.csvEmpty".to_string());
    }
    if entries.len() > 50000 {
        return Err("e.csvTooLarge".to_string());
    }
    let path = vault_path(&app)?;
    state.import(&path, entries).map_err(user_message)
}

#[tauri::command(async)]
fn create_vault(
    app: AppHandle,
    state: State<VaultState>,
    mut master_password: String,
    level: String,
    with_recovery: bool,
) -> Result<Option<String>, String> {
    let path = vault_path(&app)?;
    let res = state
        .create(&path, master_password.as_bytes(), &level, with_recovery)
        .map_err(user_message);
    master_password.zeroize();
    res
}

#[tauri::command(async)]
fn unlock_vault_recovery(
    app: AppHandle,
    state: State<VaultState>,
    mut recovery: String,
) -> Result<(), String> {
    let path = vault_path(&app)?;
    let res = state.unlock_recovery(&path, &recovery).map_err(user_message);
    recovery.zeroize();
    res
}

#[tauri::command(async)]
fn reset_master_password(
    app: AppHandle,
    state: State<VaultState>,
    mut new: String,
) -> Result<(), String> {
    let path = vault_path(&app)?;
    let res = state.reset_master_password(&path, new.as_bytes()).map_err(user_message);
    new.zeroize();
    res
}

#[tauri::command(async)]
fn setup_recovery(app: AppHandle, state: State<VaultState>) -> Result<String, String> {
    let path = vault_path(&app)?;
    state.setup_recovery(&path).map_err(user_message)
}

#[tauri::command(async)]
fn remove_recovery(app: AppHandle, state: State<VaultState>) -> Result<(), String> {
    let path = vault_path(&app)?;
    state.remove_recovery(&path).map_err(user_message)
}

#[tauri::command(async)]
fn has_recovery(state: State<VaultState>) -> bool {
    state.has_recovery()
}

#[tauri::command(async)]
fn vault_has_recovery(app: AppHandle) -> Result<bool, String> {
    Ok(vault::peek_has_recovery(&vault_path(&app)?))
}

#[tauri::command(async)]
fn vault_level(app: AppHandle, state: State<VaultState>) -> String {
    if let Some(level) = state.level() {
        return level;
    }
    match vault_path(&app) {
        Ok(path) => vault::peek_level(&path),
        Err(_) => "normal".to_string(),
    }
}

#[tauri::command(async)]
fn change_master_password(
    app: AppHandle,
    state: State<VaultState>,
    mut current: String,
    mut new: String,
) -> Result<(), String> {
    let path = vault_path(&app)?;
    let res = state
        .change_master_password(&path, current.as_bytes(), new.as_bytes())
        .map_err(user_message);
    current.zeroize();
    new.zeroize();
    res
}

fn level_icon_bytes(level: &str, theme: &str) -> &'static [u8] {
    match (level, theme) {
        ("fort", "light") => include_bytes!("../icons/level-fort-light.png"),
        ("parano", "light") => include_bytes!("../icons/level-parano-light.png"),
        (_, "light") => include_bytes!("../icons/level-normal-light.png"),
        ("fort", _) => include_bytes!("../icons/level-fort.png"),
        ("parano", _) => include_bytes!("../icons/level-parano.png"),
        _ => include_bytes!("../icons/level-normal.png"),
    }
}

#[tauri::command(async)]
fn set_level_icon(window: tauri::WebviewWindow, level: String, theme: String) -> Result<(), String> {
    let image = tauri::image::Image::from_bytes(level_icon_bytes(&level, &theme))
        .map_err(|_| "e.internal".to_string())?;
    window.set_icon(image).map_err(|_| "e.internal".to_string())
}

fn disguise_image(on: bool, level: &str, theme: &str) -> Result<tauri::image::Image<'static>, String> {
    let bytes: &[u8] = if on {
        include_bytes!("../icons/decoy.png")
    } else {
        level_icon_bytes(level, theme)
    };
    tauri::image::Image::from_bytes(bytes).map_err(|_| "e.internal".to_string())
}

fn apply_disguise(app: &AppHandle, on: bool, title: &str, level: &str, theme: &str) -> Result<(), String> {
    if let Some(window) = app.get_webview_window("main") {
        window
            .set_icon(disguise_image(on, level, theme)?)
            .map_err(|_| "e.internal".to_string())?;
        window.set_title(title).map_err(|_| "e.internal".to_string())?;
    }
    if let Some(tray) = app.tray_by_id("gestio-tray") {
        let _ = tray.set_icon(Some(disguise_image(on, level, theme)?));
        let _ = tray.set_tooltip(Some(title));
    }
    Ok(())
}

#[tauri::command(async)]
fn set_disguise(
    app: AppHandle,
    on: bool,
    title: String,
    level: String,
    theme: String,
) -> Result<(), String> {
    apply_disguise(&app, on, &title, &level, &theme)
}

#[tauri::command(async)]
fn set_discreet(app: AppHandle, on: bool) -> Result<(), String> {
    let dir = app.path().app_data_dir().map_err(|_| "e.internal".to_string())?;
    config::set_discreet(&dir.join("config.json"), on).map_err(|_| "e.internal".to_string())
}

fn is_discreet(app: &AppHandle) -> bool {
    match app.path().app_data_dir() {
        Ok(dir) => config::discreet(&dir.join("config.json")),
        Err(_) => false,
    }
}

#[tauri::command(async)]
fn app_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[derive(serde::Serialize)]
struct UpdateInfo {
    version: String,
    notes: String,
}

#[tauri::command]
async fn check_update(app: AppHandle) -> Result<Option<UpdateInfo>, String> {
    use tauri_plugin_updater::UpdaterExt;
    let updater = app.updater().map_err(|_| "e.updateCheck".to_string())?;
    match updater.check().await {
        Ok(Some(update)) => Ok(Some(UpdateInfo {
            version: update.version.clone(),
            notes: update.body.clone().unwrap_or_default(),
        })),
        Ok(None) => Ok(None),
        Err(_) => Err("e.updateCheck".to_string()),
    }
}

#[tauri::command]
async fn install_update(app: AppHandle) -> Result<(), String> {
    use tauri_plugin_updater::UpdaterExt;
    let updater = app.updater().map_err(|_| "e.updateCheck".to_string())?;
    let update = updater
        .check()
        .await
        .map_err(|_| "e.updateCheck".to_string())?
        .ok_or_else(|| "e.updateNone".to_string())?;
    update
        .download_and_install(|_chunk, _total| {}, || {})
        .await
        .map_err(|_| "e.updateInstall".to_string())?;
    app.restart();
}

#[tauri::command(async)]
fn get_autostart(app: AppHandle) -> bool {
    use tauri_plugin_autostart::ManagerExt;
    app.autolaunch().is_enabled().unwrap_or(false)
}

#[tauri::command(async)]
fn set_autostart(app: AppHandle, enabled: bool) -> Result<(), String> {
    use tauri_plugin_autostart::ManagerExt;
    let manager = app.autolaunch();
    let res = if enabled { manager.enable() } else { manager.disable() };
    res.map_err(|_| "e.internal".to_string())
}

#[tauri::command(async)]
fn update_tray_labels(labels: State<TrayLabels>, show: String, quit: String) {
    let _ = labels.show.set_text(show);
    let _ = labels.quit.set_text(quit);
}

#[tauri::command(async)]
fn change_level(
    app: AppHandle,
    state: State<VaultState>,
    mut master_password: String,
    level: String,
) -> Result<(), String> {
    let path = vault_path(&app)?;
    let res = state
        .change_level(&path, master_password.as_bytes(), &level)
        .map_err(user_message);
    master_password.zeroize();
    res
}

#[tauri::command(async)]
fn unlock_vault(
    app: AppHandle,
    state: State<VaultState>,
    mut master_password: String,
) -> Result<(), String> {
    let path = vault_path(&app)?;
    let res = state.unlock(&path, master_password.as_bytes()).map_err(user_message);
    master_password.zeroize();
    res
}

#[tauri::command(async)]
fn lock_vault(state: State<VaultState>) {
    state.lock();
}

#[tauri::command(async)]
fn is_unlocked(state: State<VaultState>) -> bool {
    state.is_unlocked()
}

#[tauri::command(async)]
fn list_entries(state: State<VaultState>) -> Result<Vec<EntryMeta>, String> {
    state.list_entries().map_err(user_message)
}

#[tauri::command(async)]
fn reveal_password(state: State<VaultState>, id: String) -> Result<String, String> {
    state.reveal_password(&id).map_err(user_message)
}

fn pwned_count(password: &[u8]) -> Result<i64, String> {
    use sha1::{Digest, Sha1};
    use std::fmt::Write as _;
    let mut hasher = Sha1::new();
    hasher.update(password);
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(40);
    for b in digest.iter() {
        let _ = write!(hex, "{b:02X}");
    }
    let (prefix, suffix) = hex.split_at(5);
    let url = format!("https://api.pwnedpasswords.com/range/{prefix}");
    let body = ureq::get(&url)
        .set("Add-Padding", "true")
        .call()
        .map_err(|_| "e.hibpFailed".to_string())?
        .into_string()
        .map_err(|_| "e.hibpUnreadable".to_string())?;
    for line in body.lines() {
        if let Some((suf, count)) = line.split_once(':') {
            if suf.eq_ignore_ascii_case(suffix) {
                return Ok(count.trim().parse().unwrap_or(0));
            }
        }
    }
    Ok(0)
}

#[tauri::command(async)]
fn check_pwned(state: State<VaultState>, id: String) -> Result<i64, String> {
    let mut password = state.reveal_password(&id).map_err(user_message)?;
    let result = pwned_count(password.as_bytes());
    password.zeroize();
    result
}

#[derive(serde::Serialize)]
struct PwnedResult {
    id: String,
    name: String,
    count: i64,
}

#[tauri::command(async)]
fn check_all_pwned(state: State<VaultState>) -> Result<Vec<PwnedResult>, String> {
    let secrets = state.entry_secrets().map_err(user_message)?;
    let mut results = Vec::new();
    for (id, name, password) in secrets {
        if password.is_empty() {
            continue;
        }
        let count = pwned_count(password.as_bytes())?;
        results.push(PwnedResult { id, name, count });
    }
    Ok(results)
}

#[tauri::command(async)]
fn add_entry(app: AppHandle, state: State<VaultState>, input: EntryInput) -> Result<String, String> {
    let path = vault_path(&app)?;
    state.add_entry(&path, input).map_err(user_message)
}

#[tauri::command(async)]
fn update_entry(
    app: AppHandle,
    state: State<VaultState>,
    id: String,
    input: EntryInput,
) -> Result<(), String> {
    let path = vault_path(&app)?;
    state.update_entry(&path, &id, input).map_err(user_message)
}

#[tauri::command(async)]
fn delete_entry(app: AppHandle, state: State<VaultState>, id: String) -> Result<(), String> {
    let path = vault_path(&app)?;
    state.delete_entry(&path, &id).map_err(user_message)
}

#[tauri::command(async)]
fn toggle_favorite(app: AppHandle, state: State<VaultState>, id: String) -> Result<bool, String> {
    let path = vault_path(&app)?;
    state.toggle_favorite(&path, &id).map_err(user_message)
}

#[tauri::command(async)]
fn list_groups(state: State<VaultState>) -> Result<Vec<String>, String> {
    state.list_groups().map_err(user_message)
}

#[tauri::command(async)]
fn list_group_favorites(state: State<VaultState>) -> Result<Vec<String>, String> {
    state.list_group_favorites().map_err(user_message)
}

#[tauri::command(async)]
fn toggle_group_favorite(
    app: AppHandle,
    state: State<VaultState>,
    name: String,
) -> Result<bool, String> {
    let path = vault_path(&app)?;
    state.toggle_group_favorite(&path, &name).map_err(user_message)
}

#[tauri::command(async)]
fn reorder_entries(
    app: AppHandle,
    state: State<VaultState>,
    order: Vec<EntryOrder>,
) -> Result<(), String> {
    let path = vault_path(&app)?;
    state.reorder_entries(&path, order).map_err(user_message)
}

#[tauri::command(async)]
fn reorder_groups(app: AppHandle, state: State<VaultState>, order: Vec<String>) -> Result<(), String> {
    let path = vault_path(&app)?;
    state.reorder_groups(&path, order).map_err(user_message)
}

#[tauri::command(async)]
fn create_group(app: AppHandle, state: State<VaultState>, name: String) -> Result<(), String> {
    let path = vault_path(&app)?;
    state.create_group(&path, &name).map_err(user_message)
}

#[tauri::command(async)]
fn rename_group(
    app: AppHandle,
    state: State<VaultState>,
    from: String,
    to: String,
) -> Result<(), String> {
    let path = vault_path(&app)?;
    state.rename_group(&path, &from, &to).map_err(user_message)
}

#[tauri::command(async)]
fn delete_group(app: AppHandle, state: State<VaultState>, name: String) -> Result<(), String> {
    let path = vault_path(&app)?;
    state.delete_group(&path, &name).map_err(user_message)
}

#[tauri::command(async)]
fn copy_password(app: AppHandle, state: State<VaultState>, id: String) -> Result<(), String> {
    let mut password = state.reveal_password(&id).map_err(user_message)?;
    let res = app
        .clipboard()
        .write_text(password.clone())
        .map_err(|_| "e.copyFailed".to_string());
    password.zeroize();
    res
}

#[tauri::command(async)]
fn copy_text(app: AppHandle, text: String) -> Result<(), String> {
    app.clipboard()
        .write_text(text)
        .map_err(|_| "e.copyFailed".to_string())
}

#[tauri::command(async)]
fn clear_clipboard(app: AppHandle) -> Result<(), String> {
    app.clipboard()
        .write_text(String::new())
        .map_err(|_| "e.internal".to_string())
}

#[derive(serde::Serialize)]
struct DupEntry {
    id: String,
    name: String,
}

fn is_weak(pw: &str) -> bool {
    let mut pool: u32 = 0;
    if pw.chars().any(|c| c.is_ascii_lowercase()) {
        pool += 26;
    }
    if pw.chars().any(|c| c.is_ascii_uppercase()) {
        pool += 26;
    }
    if pw.chars().any(|c| c.is_ascii_digit()) {
        pool += 10;
    }
    if pw.chars().any(|c| !c.is_ascii_alphanumeric()) {
        pool += 32;
    }
    let len = pw.chars().count();
    let entropy = len as f64 * (pool.max(1) as f64).log2();
    len < 8 || entropy < 40.0
}

#[tauri::command(async)]
fn find_weak(state: State<VaultState>) -> Result<Vec<DupEntry>, String> {
    let secrets = state.entry_secrets().map_err(user_message)?;
    let mut out = Vec::new();
    for (id, name, pw) in secrets {
        if !pw.is_empty() && is_weak(&pw) {
            out.push(DupEntry { id, name });
        }
    }
    Ok(out)
}

#[tauri::command(async)]
fn find_old(state: State<VaultState>, months: i64) -> Result<Vec<DupEntry>, String> {
    let old = state.find_old(months).map_err(user_message)?;
    Ok(old.into_iter().map(|(id, name)| DupEntry { id, name }).collect())
}

#[tauri::command(async)]
fn find_duplicates(state: State<VaultState>) -> Result<Vec<Vec<DupEntry>>, String> {
    use sha1::{Digest, Sha1};
    let secrets = state.entry_secrets().map_err(user_message)?;
    let mut map: std::collections::HashMap<Vec<u8>, Vec<DupEntry>> = std::collections::HashMap::new();
    for (id, name, pw) in secrets {
        if pw.is_empty() {
            continue;
        }
        let mut hasher = Sha1::new();
        hasher.update(pw.as_bytes());
        let key = hasher.finalize().to_vec();
        map.entry(key).or_default().push(DupEntry { id, name });
    }
    Ok(map.into_values().filter(|v| v.len() >= 2).collect())
}

#[tauri::command(async)]
fn regenerate_password(app: AppHandle, state: State<VaultState>, id: String) -> Result<String, String> {
    let options = PasswordOptions {
        length: 20,
        lowercase: true,
        uppercase: true,
        digits: true,
        symbols: true,
    };
    let password = generator::generate(&options).map_err(|_| "e.genFailed".to_string())?;
    let path = vault_path(&app)?;
    state.set_password(&path, &id, &password).map_err(user_message)?;
    Ok(password)
}

fn generator_message(e: generator::GeneratorError) -> String {
    match e {
        generator::GeneratorError::EmptyCharset => "e.genCharset".into(),
        generator::GeneratorError::InvalidLength => "e.genLength".into(),
        generator::GeneratorError::Random => "e.internal".into(),
    }
}

#[tauri::command(async)]
fn generate_password(options: PasswordOptions) -> Result<String, String> {
    generator::generate(&options).map_err(generator_message)
}

#[tauri::command(async)]
fn generate_passphrase(options: generator::PassphraseOptions) -> Result<String, String> {
    generator::generate_passphrase(&options).map_err(generator_message)
}

struct TrayLabels {
    show: tauri::menu::MenuItem<tauri::Wry>,
    quit: tauri::menu::MenuItem<tauri::Wry>,
}

fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

fn setup_tray(app: &tauri::App) -> tauri::Result<()> {
    use tauri::menu::{Menu, MenuItem};
    use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};

    let show = MenuItem::with_id(app, "tray-show", "Ouvrir Gestio", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "tray-quit", "Quitter", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &quit])?;

    let mut builder = TrayIconBuilder::with_id("gestio-tray")
        .tooltip("Gestio")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "tray-show" => show_main_window(app),
            "tray-quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main_window(tray.app_handle());
            }
        });
    if let Some(icon) = app.default_window_icon().cloned() {
        builder = builder.icon(icon);
    }
    builder.build(app)?;

    app.manage(TrayLabels { show, quit });
    Ok(())
}

fn ensure_autostart_default(app: &tauri::App) {
    use tauri_plugin_autostart::ManagerExt;
    let Ok(dir) = app.path().app_data_dir() else {
        return;
    };
    let config_file = dir.join("config.json");
    if !config::autostart_initialized(&config_file) {
        let _ = app.autolaunch().enable();
        let _ = config::mark_autostart_initialized(&config_file);
    }
}

#[cfg(windows)]
fn set_taskbar_identity() {
    use windows::core::PCWSTR;
    use windows::Win32::UI::Shell::SetCurrentProcessExplicitAppUserModelID;
    let id: Vec<u16> = "Notes.Desktop.App\0".encode_utf16().collect();
    unsafe {
        let _ = SetCurrentProcessExplicitAppUserModelID(PCWSTR(id.as_ptr()));
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    #[cfg(windows)]
    set_taskbar_identity();
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            show_main_window(app);
        }))
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            Some(vec!["--startup"]),
        ))
        .manage(VaultState::default())
        .manage(TotpState::default())
        .setup(|app| {
            setup_tray(app)?;
            ensure_autostart_default(app);
            if is_discreet(app.handle()) {
                let _ = apply_disguise(app.handle(), true, "Notely", "normal", "dark");
            }
            let started_at_boot = std::env::args().any(|arg| arg == "--startup");
            if !started_at_boot {
                show_main_window(app.handle());
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .invoke_handler(tauri::generate_handler![
            vault_exists,
            vault_location,
            change_vault_location,
            export_vault,
            restore_vault,
            import_csv,
            create_vault,
            vault_level,
            change_level,
            change_master_password,
            unlock_vault_recovery,
            reset_master_password,
            setup_recovery,
            remove_recovery,
            has_recovery,
            vault_has_recovery,
            set_level_icon,
            set_disguise,
            set_discreet,
            app_version,
            check_update,
            install_update,
            get_autostart,
            set_autostart,
            update_tray_labels,
            unlock_vault,
            lock_vault,
            is_unlocked,
            list_entries,
            reveal_password,
            add_entry,
            update_entry,
            delete_entry,
            toggle_favorite,
            check_pwned,
            check_all_pwned,
            find_duplicates,
            find_weak,
            find_old,
            regenerate_password,
            list_groups,
            list_group_favorites,
            toggle_group_favorite,
            reorder_entries,
            reorder_groups,
            create_group,
            rename_group,
            delete_group,
            generate_password,
            generate_passphrase,
            copy_password,
            copy_text,
            clear_clipboard,
            totp_exists,
            totp_is_unlocked,
            create_totp,
            unlock_totp,
            lock_totp,
            change_totp_master_password,
            unlock_totp_recovery,
            reset_totp_master_password,
            setup_totp_recovery,
            remove_totp_recovery,
            has_totp_recovery,
            totp_has_recovery,
            list_totp,
            add_totp,
            delete_totp,
            totp_codes
        ])
        .run(tauri::generate_context!())
        .expect("erreur au lancement de Gestio");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_csv_generic() {
        let csv = b"name,username,password,url,notes\nGitHub,jerome,s3cret,https://github.com,ma note\n";
        let out = parse_csv(csv).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "GitHub");
        assert_eq!(out[0].username, "jerome");
        assert_eq!(out[0].password, "s3cret");
        assert_eq!(out[0].url, "https://github.com");
        assert_eq!(out[0].note, "ma note");
        assert_eq!(out[0].kind, "login");
    }

    #[test]
    fn parse_csv_bitwarden_headers_and_folder() {
        let csv = b"folder,favorite,type,name,notes,login_uri,login_username,login_password\nPerso,,login,Steam,,https://steam.com,joueur,pw123\n";
        let out = parse_csv(csv).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "Steam");
        assert_eq!(out[0].username, "joueur");
        assert_eq!(out[0].password, "pw123");
        assert_eq!(out[0].url, "https://steam.com");
        assert_eq!(out[0].group, "Perso");
    }

    #[test]
    fn parse_csv_note_detection() {
        let csv = b"name,username,password,notes\nRecovery,,,codes ici\n";
        let out = parse_csv(csv).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, "note");
        assert_eq!(out[0].note, "codes ici");
    }

    #[test]
    fn parse_csv_rejects_unknown_columns() {
        let csv = b"col_a,col_b\nx,y\n";
        assert!(parse_csv(csv).is_err());
    }

    #[test]
    fn parse_csv_name_fallback() {
        let csv = b"name,username,password,url\n,,pw,https://x.com\n";
        let out = parse_csv(csv).unwrap();
        assert_eq!(out[0].name, "https://x.com");
    }
}
