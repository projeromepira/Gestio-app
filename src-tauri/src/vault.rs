use crate::crypto;
use crate::keywrap;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Mutex;
use zeroize::{Zeroize, Zeroizing};

pub const VAULT_VERSION: u32 = 2;

fn default_level() -> String {
    "normal".to_string()
}

#[derive(Deserialize)]
struct VaultFileV1 {
    #[serde(default = "default_level")]
    level: String,
    kdf_mem_kib: u32,
    kdf_iterations: u32,
    kdf_parallelism: u32,
    salt: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Serialize, Deserialize)]
struct VaultFileV2 {
    version: u32,
    #[serde(default = "default_level")]
    level: String,
    kdf_mem_kib: u32,
    kdf_iterations: u32,
    kdf_parallelism: u32,
    pw_salt: String,
    pw_nonce: String,
    pw_wrap: String,
    #[serde(default)]
    rec_salt: String,
    #[serde(default)]
    rec_nonce: String,
    #[serde(default)]
    rec_wrap: String,
    data_nonce: String,
    data_ct: String,
}

#[derive(Serialize, Deserialize, Default, Clone)]
struct VaultData {
    entries: Vec<Entry>,
    #[serde(default)]
    groups: Vec<String>,
    #[serde(default)]
    fav_groups: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct CustomField {
    pub label: String,
    pub value: String,
    #[serde(default)]
    pub secret: bool,
}

#[derive(Serialize, Deserialize, Clone)]
struct Entry {
    id: String,
    name: String,
    username: String,
    password: String,
    url: String,
    note: String,
    #[serde(default)]
    group: String,
    #[serde(default)]
    modified: i64,
    #[serde(default)]
    favorite: bool,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    fields: Vec<CustomField>,
    #[serde(default)]
    password_modified: i64,
}

#[derive(Deserialize)]
pub struct EntryInput {
    pub name: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub note: String,
    #[serde(default)]
    pub group: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub fields: Vec<CustomField>,
}

#[derive(Deserialize)]
pub struct EntryOrder {
    pub id: String,
    pub group: String,
}

#[derive(Serialize)]
pub struct EntryMeta {
    pub id: String,
    pub name: String,
    pub username: String,
    pub url: String,
    pub note: String,
    pub group: String,
    pub modified: i64,
    pub favorite: bool,
    pub kind: String,
    pub fields: Vec<CustomField>,
    pub password_modified: i64,
}

type Wrap = (Vec<u8>, Vec<u8>, Vec<u8>);

struct Unlocked {
    data_key: Zeroizing<[u8; crypto::KEY_LEN]>,
    level: String,
    mem_kib: u32,
    iterations: u32,
    parallelism: u32,
    pw: Wrap,
    rec: Option<Wrap>,
    data: VaultData,
}

#[derive(Default)]
pub struct VaultState {
    inner: Mutex<Option<Unlocked>>,
}

#[derive(Debug)]
pub enum VaultError {
    AlreadyExists,
    NotFound,
    Locked,
    WrongPassword,
    EntryNotFound,
    GroupExists,
    GroupNameEmpty,
    NoRecovery,
    Corrupt,
    Io,
    Crypto,
}

impl VaultState {
    pub fn is_unlocked(&self) -> bool {
        self.inner.lock().map(|g| g.is_some()).unwrap_or(false)
    }

    pub fn lock(&self) {
        if let Ok(mut guard) = self.inner.lock() {
            if let Some(unlocked) = guard.as_mut() {
                for entry in &mut unlocked.data.entries {
                    entry.password.zeroize();
                    entry.username.zeroize();
                    entry.note.zeroize();
                    for field in &mut entry.fields {
                        field.value.zeroize();
                    }
                }
            }
            *guard = None;
        }
    }

    pub fn level(&self) -> Option<String> {
        self.inner
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(|u| u.level.clone()))
    }

    pub fn create(
        &self,
        path: &Path,
        password: &[u8],
        level: &str,
        with_recovery: bool,
    ) -> Result<Option<String>, VaultError> {
        if path.exists() {
            return Err(VaultError::AlreadyExists);
        }
        let (mem_kib, iterations, parallelism) = crypto::level_params(level);
        let data_key = crypto::generate_key_bytes().map_err(|_| VaultError::Crypto)?;
        let pw = wrap_key(password, mem_kib, iterations, parallelism, &data_key)?;

        let (rec, code) = if with_recovery {
            let code = generate_recovery_code()?;
            let (rm, ri, rp) = recovery_params();
            let rec = wrap_key(normalize_recovery(&code).as_bytes(), rm, ri, rp, &data_key)?;
            (Some(rec), Some(code))
        } else {
            (None, None)
        };

        let unlocked = Unlocked {
            data_key,
            level: level.to_string(),
            mem_kib,
            iterations,
            parallelism,
            pw,
            rec,
            data: VaultData::default(),
        };
        write_vault(path, &unlocked)?;
        *self.inner.lock().map_err(|_| VaultError::Io)? = Some(unlocked);
        Ok(code)
    }

    pub fn unlock(&self, path: &Path, password: &[u8]) -> Result<(), VaultError> {
        let raw = read_raw(path)?;
        let unlocked = match read_version(&raw)? {
            1 => migrate_v1(path, password, &raw)?,
            2 => {
                let file: VaultFileV2 =
                    serde_json::from_slice(&raw).map_err(|_| VaultError::Corrupt)?;
                let pw = decode_wrap(&file.pw_salt, &file.pw_nonce, &file.pw_wrap)?;
                let data_key = unwrap_key(
                    password,
                    file.kdf_mem_kib,
                    file.kdf_iterations,
                    file.kdf_parallelism,
                    &pw,
                )?;
                build_unlocked(&file, data_key)?
            }
            _ => return Err(VaultError::Corrupt),
        };
        *self.inner.lock().map_err(|_| VaultError::Io)? = Some(unlocked);
        Ok(())
    }

    pub fn unlock_recovery(&self, path: &Path, recovery: &str) -> Result<(), VaultError> {
        let raw = read_raw(path)?;
        if read_version(&raw)? != 2 {
            return Err(VaultError::NoRecovery);
        }
        let file: VaultFileV2 = serde_json::from_slice(&raw).map_err(|_| VaultError::Corrupt)?;
        if file.rec_wrap.is_empty() {
            return Err(VaultError::NoRecovery);
        }
        let rec = decode_wrap(&file.rec_salt, &file.rec_nonce, &file.rec_wrap)?;
        let (rm, ri, rp) = recovery_params();
        let data_key = unwrap_key(normalize_recovery(recovery).as_bytes(), rm, ri, rp, &rec)?;
        let unlocked = build_unlocked(&file, data_key)?;
        *self.inner.lock().map_err(|_| VaultError::Io)? = Some(unlocked);
        Ok(())
    }

    pub fn has_recovery(&self) -> bool {
        self.inner
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(|u| u.rec.is_some()))
            .unwrap_or(false)
    }

    pub fn reset_master_password(&self, path: &Path, new: &[u8]) -> Result<(), VaultError> {
        let mut guard = self.inner.lock().map_err(|_| VaultError::Io)?;
        let unlocked = guard.as_mut().ok_or(VaultError::Locked)?;
        let new_pw = wrap_key(
            new,
            unlocked.mem_kib,
            unlocked.iterations,
            unlocked.parallelism,
            &unlocked.data_key,
        )?;
        let old = unlocked.pw.clone();
        unlocked.pw = new_pw;
        match write_vault(path, unlocked) {
            Ok(()) => Ok(()),
            Err(e) => {
                unlocked.pw = old;
                Err(e)
            }
        }
    }

    pub fn setup_recovery(&self, path: &Path) -> Result<String, VaultError> {
        let mut guard = self.inner.lock().map_err(|_| VaultError::Io)?;
        let unlocked = guard.as_mut().ok_or(VaultError::Locked)?;
        let code = generate_recovery_code()?;
        let (rm, ri, rp) = recovery_params();
        let rec = wrap_key(normalize_recovery(&code).as_bytes(), rm, ri, rp, &unlocked.data_key)?;
        let old = unlocked.rec.clone();
        unlocked.rec = Some(rec);
        match write_vault(path, unlocked) {
            Ok(()) => Ok(code),
            Err(e) => {
                unlocked.rec = old;
                Err(e)
            }
        }
    }

    pub fn remove_recovery(&self, path: &Path) -> Result<(), VaultError> {
        let mut guard = self.inner.lock().map_err(|_| VaultError::Io)?;
        let unlocked = guard.as_mut().ok_or(VaultError::Locked)?;
        let old = unlocked.rec.take();
        match write_vault(path, unlocked) {
            Ok(()) => Ok(()),
            Err(e) => {
                unlocked.rec = old;
                Err(e)
            }
        }
    }

    pub fn list_entries(&self) -> Result<Vec<EntryMeta>, VaultError> {
        let guard = self.inner.lock().map_err(|_| VaultError::Io)?;
        let unlocked = guard.as_ref().ok_or(VaultError::Locked)?;
        Ok(unlocked
            .data
            .entries
            .iter()
            .map(|e| EntryMeta {
                id: e.id.clone(),
                name: e.name.clone(),
                username: e.username.clone(),
                url: e.url.clone(),
                note: e.note.clone(),
                group: e.group.clone(),
                modified: e.modified,
                favorite: e.favorite,
                kind: e.kind.clone(),
                fields: e.fields.clone(),
                password_modified: e.password_modified,
            })
            .collect())
    }

    pub fn entry_secrets(&self) -> Result<Vec<(String, String, Zeroizing<String>)>, VaultError> {
        let guard = self.inner.lock().map_err(|_| VaultError::Io)?;
        let unlocked = guard.as_ref().ok_or(VaultError::Locked)?;
        Ok(unlocked
            .data
            .entries
            .iter()
            .map(|e| (e.id.clone(), e.name.clone(), Zeroizing::new(e.password.clone())))
            .collect())
    }

    pub fn reveal_password(&self, id: &str) -> Result<String, VaultError> {
        let guard = self.inner.lock().map_err(|_| VaultError::Io)?;
        let unlocked = guard.as_ref().ok_or(VaultError::Locked)?;
        unlocked
            .data
            .entries
            .iter()
            .find(|e| e.id == id)
            .map(|e| e.password.clone())
            .ok_or(VaultError::EntryNotFound)
    }

    pub fn set_password(&self, path: &Path, id: &str, password: &str) -> Result<(), VaultError> {
        let mut guard = self.inner.lock().map_err(|_| VaultError::Io)?;
        let unlocked = guard.as_mut().ok_or(VaultError::Locked)?;
        let index = unlocked
            .data
            .entries
            .iter()
            .position(|e| e.id == id)
            .ok_or(VaultError::EntryNotFound)?;
        let previous = unlocked.data.entries[index].clone();
        unlocked.data.entries[index].password = password.to_string();
        unlocked.data.entries[index].modified = now_secs();
        unlocked.data.entries[index].password_modified = now_secs();
        match save_unlocked(path, unlocked) {
            Ok(()) => Ok(()),
            Err(e) => {
                unlocked.data.entries[index] = previous;
                Err(e)
            }
        }
    }

    pub fn add_entry(&self, path: &Path, input: EntryInput) -> Result<String, VaultError> {
        let id = new_id()?;
        let mut guard = self.inner.lock().map_err(|_| VaultError::Io)?;
        let unlocked = guard.as_mut().ok_or(VaultError::Locked)?;
        unlocked.data.entries.push(Entry {
            id: id.clone(),
            name: input.name,
            username: input.username,
            password: input.password,
            url: input.url,
            note: input.note,
            group: input.group,
            modified: now_secs(),
            favorite: false,
            kind: input.kind,
            fields: input.fields,
            password_modified: now_secs(),
        });
        match save_unlocked(path, unlocked) {
            Ok(()) => Ok(id),
            Err(e) => {
                unlocked.data.entries.pop();
                Err(e)
            }
        }
    }

    pub fn update_entry(&self, path: &Path, id: &str, input: EntryInput) -> Result<(), VaultError> {
        let mut guard = self.inner.lock().map_err(|_| VaultError::Io)?;
        let unlocked = guard.as_mut().ok_or(VaultError::Locked)?;
        let index = unlocked
            .data
            .entries
            .iter()
            .position(|e| e.id == id)
            .ok_or(VaultError::EntryNotFound)?;
        let previous = unlocked.data.entries[index].clone();
        let password_modified = if input.password != previous.password {
            now_secs()
        } else {
            previous.password_modified
        };
        unlocked.data.entries[index] = Entry {
            id: id.to_string(),
            name: input.name,
            username: input.username,
            password: input.password,
            url: input.url,
            note: input.note,
            group: input.group,
            modified: now_secs(),
            favorite: previous.favorite,
            kind: input.kind,
            fields: input.fields,
            password_modified,
        };
        match save_unlocked(path, unlocked) {
            Ok(()) => Ok(()),
            Err(e) => {
                unlocked.data.entries[index] = previous;
                Err(e)
            }
        }
    }

    pub fn find_old(&self, months: i64) -> Result<Vec<(String, String)>, VaultError> {
        let guard = self.inner.lock().map_err(|_| VaultError::Io)?;
        let unlocked = guard.as_ref().ok_or(VaultError::Locked)?;
        if months <= 0 {
            return Ok(Vec::new());
        }
        let now = now_secs();
        let threshold = months.saturating_mul(2_592_000);
        Ok(unlocked
            .data
            .entries
            .iter()
            .filter(|e| !e.password.is_empty())
            .filter(|e| {
                let ts = if e.password_modified > 0 {
                    e.password_modified
                } else {
                    e.modified
                };
                ts > 0 && now - ts > threshold
            })
            .map(|e| (e.id.clone(), e.name.clone()))
            .collect())
    }

    pub fn import(&self, path: &Path, entries: Vec<EntryInput>) -> Result<usize, VaultError> {
        let mut guard = self.inner.lock().map_err(|_| VaultError::Io)?;
        let unlocked = guard.as_mut().ok_or(VaultError::Locked)?;
        let snapshot = unlocked.data.clone();
        let mut count = 0usize;
        for inp in entries {
            let id = new_id()?;
            if !inp.group.is_empty() && !unlocked.data.groups.iter().any(|g| *g == inp.group) {
                unlocked.data.groups.push(inp.group.clone());
            }
            unlocked.data.entries.push(Entry {
                id,
                name: inp.name,
                username: inp.username,
                password: inp.password,
                url: inp.url,
                note: inp.note,
                group: inp.group,
                modified: now_secs(),
                favorite: false,
                kind: inp.kind,
                fields: inp.fields,
                password_modified: now_secs(),
            });
            count += 1;
        }
        match save_unlocked(path, unlocked) {
            Ok(()) => Ok(count),
            Err(e) => {
                unlocked.data = snapshot;
                Err(e)
            }
        }
    }

    pub fn toggle_favorite(&self, path: &Path, id: &str) -> Result<bool, VaultError> {
        let mut guard = self.inner.lock().map_err(|_| VaultError::Io)?;
        let unlocked = guard.as_mut().ok_or(VaultError::Locked)?;
        let index = unlocked
            .data
            .entries
            .iter()
            .position(|e| e.id == id)
            .ok_or(VaultError::EntryNotFound)?;
        unlocked.data.entries[index].favorite = !unlocked.data.entries[index].favorite;
        let now = unlocked.data.entries[index].favorite;
        match save_unlocked(path, unlocked) {
            Ok(()) => Ok(now),
            Err(e) => {
                unlocked.data.entries[index].favorite = !now;
                Err(e)
            }
        }
    }

    pub fn delete_entry(&self, path: &Path, id: &str) -> Result<(), VaultError> {
        let mut guard = self.inner.lock().map_err(|_| VaultError::Io)?;
        let unlocked = guard.as_mut().ok_or(VaultError::Locked)?;
        let index = unlocked
            .data
            .entries
            .iter()
            .position(|e| e.id == id)
            .ok_or(VaultError::EntryNotFound)?;
        let removed = unlocked.data.entries.remove(index);
        match save_unlocked(path, unlocked) {
            Ok(()) => Ok(()),
            Err(e) => {
                unlocked.data.entries.insert(index, removed);
                Err(e)
            }
        }
    }

    pub fn change_level(
        &self,
        path: &Path,
        password: &[u8],
        new_level: &str,
    ) -> Result<(), VaultError> {
        let mut guard = self.inner.lock().map_err(|_| VaultError::Io)?;
        let unlocked = guard.as_mut().ok_or(VaultError::Locked)?;

        unwrap_key(
            password,
            unlocked.mem_kib,
            unlocked.iterations,
            unlocked.parallelism,
            &unlocked.pw,
        )?;

        let (mem_kib, iterations, parallelism) = crypto::level_params(new_level);
        let new_pw = wrap_key(password, mem_kib, iterations, parallelism, &unlocked.data_key)?;

        let snapshot = (
            unlocked.level.clone(),
            unlocked.mem_kib,
            unlocked.iterations,
            unlocked.parallelism,
            unlocked.pw.clone(),
        );
        unlocked.level = new_level.to_string();
        unlocked.mem_kib = mem_kib;
        unlocked.iterations = iterations;
        unlocked.parallelism = parallelism;
        unlocked.pw = new_pw;
        match write_vault(path, unlocked) {
            Ok(()) => Ok(()),
            Err(e) => {
                unlocked.level = snapshot.0;
                unlocked.mem_kib = snapshot.1;
                unlocked.iterations = snapshot.2;
                unlocked.parallelism = snapshot.3;
                unlocked.pw = snapshot.4;
                Err(e)
            }
        }
    }

    pub fn change_master_password(
        &self,
        path: &Path,
        current: &[u8],
        new: &[u8],
    ) -> Result<(), VaultError> {
        let mut guard = self.inner.lock().map_err(|_| VaultError::Io)?;
        let unlocked = guard.as_mut().ok_or(VaultError::Locked)?;

        unwrap_key(
            current,
            unlocked.mem_kib,
            unlocked.iterations,
            unlocked.parallelism,
            &unlocked.pw,
        )?;

        let new_pw = wrap_key(
            new,
            unlocked.mem_kib,
            unlocked.iterations,
            unlocked.parallelism,
            &unlocked.data_key,
        )?;
        let old = unlocked.pw.clone();
        unlocked.pw = new_pw;
        match write_vault(path, unlocked) {
            Ok(()) => Ok(()),
            Err(e) => {
                unlocked.pw = old;
                Err(e)
            }
        }
    }

    pub fn list_groups(&self) -> Result<Vec<String>, VaultError> {
        let guard = self.inner.lock().map_err(|_| VaultError::Io)?;
        let unlocked = guard.as_ref().ok_or(VaultError::Locked)?;
        Ok(unlocked.data.groups.clone())
    }

    pub fn create_group(&self, path: &Path, name: &str) -> Result<(), VaultError> {
        let name = name.trim();
        if name.is_empty() {
            return Err(VaultError::GroupNameEmpty);
        }
        let mut guard = self.inner.lock().map_err(|_| VaultError::Io)?;
        let unlocked = guard.as_mut().ok_or(VaultError::Locked)?;
        if unlocked.data.groups.iter().any(|g| g == name) {
            return Err(VaultError::GroupExists);
        }
        unlocked.data.groups.push(name.to_string());
        match save_unlocked(path, unlocked) {
            Ok(()) => Ok(()),
            Err(e) => {
                unlocked.data.groups.pop();
                Err(e)
            }
        }
    }

    pub fn rename_group(&self, path: &Path, from: &str, to: &str) -> Result<(), VaultError> {
        let to = to.trim();
        if to.is_empty() {
            return Err(VaultError::GroupNameEmpty);
        }
        let mut guard = self.inner.lock().map_err(|_| VaultError::Io)?;
        let unlocked = guard.as_mut().ok_or(VaultError::Locked)?;
        if to != from && unlocked.data.groups.iter().any(|g| g == to) {
            return Err(VaultError::GroupExists);
        }
        let Some(index) = unlocked.data.groups.iter().position(|g| g == from) else {
            return Ok(());
        };
        let snapshot = unlocked.data.clone();
        unlocked.data.groups[index] = to.to_string();
        for entry in unlocked.data.entries.iter_mut() {
            if entry.group == from {
                entry.group = to.to_string();
            }
        }
        for g in unlocked.data.fav_groups.iter_mut() {
            if g == from {
                *g = to.to_string();
            }
        }
        match save_unlocked(path, unlocked) {
            Ok(()) => Ok(()),
            Err(e) => {
                unlocked.data = snapshot;
                Err(e)
            }
        }
    }

    pub fn reorder_entries(&self, path: &Path, order: Vec<EntryOrder>) -> Result<(), VaultError> {
        let mut guard = self.inner.lock().map_err(|_| VaultError::Io)?;
        let unlocked = guard.as_mut().ok_or(VaultError::Locked)?;
        let snapshot = unlocked.data.clone();
        let old = std::mem::take(&mut unlocked.data.entries);
        let mut by_id: HashMap<String, Entry> =
            old.into_iter().map(|e| (e.id.clone(), e)).collect();
        let mut rebuilt = Vec::with_capacity(order.len());
        for item in &order {
            if let Some(mut e) = by_id.remove(&item.id) {
                e.group = item.group.clone();
                rebuilt.push(e);
            }
        }
        for e in by_id.into_values() {
            rebuilt.push(e);
        }
        unlocked.data.entries = rebuilt;
        match save_unlocked(path, unlocked) {
            Ok(()) => Ok(()),
            Err(e) => {
                unlocked.data = snapshot;
                Err(e)
            }
        }
    }

    pub fn reorder_groups(&self, path: &Path, order: Vec<String>) -> Result<(), VaultError> {
        let mut guard = self.inner.lock().map_err(|_| VaultError::Io)?;
        let unlocked = guard.as_mut().ok_or(VaultError::Locked)?;
        let snapshot = unlocked.data.clone();
        let current = std::mem::take(&mut unlocked.data.groups);
        let mut rebuilt: Vec<String> = order.into_iter().filter(|g| current.contains(g)).collect();
        for g in current {
            if !rebuilt.contains(&g) {
                rebuilt.push(g);
            }
        }
        unlocked.data.groups = rebuilt;
        match save_unlocked(path, unlocked) {
            Ok(()) => Ok(()),
            Err(e) => {
                unlocked.data = snapshot;
                Err(e)
            }
        }
    }

    pub fn delete_group(&self, path: &Path, name: &str) -> Result<(), VaultError> {
        let mut guard = self.inner.lock().map_err(|_| VaultError::Io)?;
        let unlocked = guard.as_mut().ok_or(VaultError::Locked)?;
        let Some(index) = unlocked.data.groups.iter().position(|g| g == name) else {
            return Ok(());
        };
        let snapshot = unlocked.data.clone();
        unlocked.data.groups.remove(index);
        unlocked.data.fav_groups.retain(|g| g != name);
        for entry in unlocked.data.entries.iter_mut() {
            if entry.group == name {
                entry.group = String::new();
            }
        }
        match save_unlocked(path, unlocked) {
            Ok(()) => Ok(()),
            Err(e) => {
                unlocked.data = snapshot;
                Err(e)
            }
        }
    }

    pub fn list_group_favorites(&self) -> Result<Vec<String>, VaultError> {
        let guard = self.inner.lock().map_err(|_| VaultError::Io)?;
        let unlocked = guard.as_ref().ok_or(VaultError::Locked)?;
        Ok(unlocked.data.fav_groups.clone())
    }

    pub fn toggle_group_favorite(&self, path: &Path, name: &str) -> Result<bool, VaultError> {
        let mut guard = self.inner.lock().map_err(|_| VaultError::Io)?;
        let unlocked = guard.as_mut().ok_or(VaultError::Locked)?;
        if !unlocked.data.groups.iter().any(|g| g == name) {
            return Err(VaultError::GroupNameEmpty);
        }
        let now = if let Some(pos) = unlocked.data.fav_groups.iter().position(|g| g == name) {
            unlocked.data.fav_groups.remove(pos);
            false
        } else {
            unlocked.data.fav_groups.push(name.to_string());
            true
        };
        match save_unlocked(path, unlocked) {
            Ok(()) => Ok(now),
            Err(e) => {
                if now {
                    unlocked.data.fav_groups.retain(|g| g != name);
                } else {
                    unlocked.data.fav_groups.push(name.to_string());
                }
                Err(e)
            }
        }
    }
}

fn new_id() -> Result<String, VaultError> {
    let bytes = crypto::generate_id_bytes().map_err(|_| VaultError::Crypto)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn now_secs() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn recovery_params() -> (u32, u32, u32) {
    keywrap::recovery_params()
}

fn wrap_key(
    secret: &[u8],
    mem_kib: u32,
    iterations: u32,
    parallelism: u32,
    data_key: &[u8; crypto::KEY_LEN],
) -> Result<Wrap, VaultError> {
    keywrap::wrap_key(secret, mem_kib, iterations, parallelism, data_key)
        .map_err(|_| VaultError::Crypto)
}

fn unwrap_key(
    secret: &[u8],
    mem_kib: u32,
    iterations: u32,
    parallelism: u32,
    wrap: &Wrap,
) -> Result<Zeroizing<[u8; crypto::KEY_LEN]>, VaultError> {
    keywrap::unwrap_key(secret, mem_kib, iterations, parallelism, wrap).map_err(|e| match e {
        keywrap::UnwrapError::Wrong => VaultError::WrongPassword,
        keywrap::UnwrapError::Corrupt => VaultError::Corrupt,
        keywrap::UnwrapError::Crypto => VaultError::Crypto,
    })
}

fn decode_wrap(salt: &str, nonce: &str, ct: &str) -> Result<Wrap, VaultError> {
    keywrap::decode_wrap(salt, nonce, ct).map_err(|_| VaultError::Corrupt)
}

fn build_unlocked(
    file: &VaultFileV2,
    data_key: Zeroizing<[u8; crypto::KEY_LEN]>,
) -> Result<Unlocked, VaultError> {
    let pw = decode_wrap(&file.pw_salt, &file.pw_nonce, &file.pw_wrap)?;
    let rec = if file.rec_wrap.is_empty() {
        None
    } else {
        Some(decode_wrap(&file.rec_salt, &file.rec_nonce, &file.rec_wrap)?)
    };
    let data_nonce = STANDARD.decode(&file.data_nonce).map_err(|_| VaultError::Corrupt)?;
    let data_ct = STANDARD.decode(&file.data_ct).map_err(|_| VaultError::Corrupt)?;
    let plaintext =
        crypto::decrypt(&data_key, &data_nonce, &data_ct).map_err(|_| VaultError::WrongPassword)?;
    let data: VaultData = serde_json::from_slice(&plaintext).map_err(|_| VaultError::Corrupt)?;
    Ok(Unlocked {
        data_key,
        level: file.level.clone(),
        mem_kib: file.kdf_mem_kib,
        iterations: file.kdf_iterations,
        parallelism: file.kdf_parallelism,
        pw,
        rec,
        data,
    })
}

fn migrate_v1(path: &Path, password: &[u8], raw: &[u8]) -> Result<Unlocked, VaultError> {
    let file: VaultFileV1 = serde_json::from_slice(raw).map_err(|_| VaultError::Corrupt)?;
    let salt = STANDARD.decode(&file.salt).map_err(|_| VaultError::Corrupt)?;
    let nonce = STANDARD.decode(&file.nonce).map_err(|_| VaultError::Corrupt)?;
    let ciphertext = STANDARD.decode(&file.ciphertext).map_err(|_| VaultError::Corrupt)?;
    let key = crypto::derive_key(
        password,
        &salt,
        file.kdf_mem_kib,
        file.kdf_iterations,
        file.kdf_parallelism,
    )
    .map_err(|_| VaultError::Crypto)?;
    let plaintext =
        crypto::decrypt(&key, &nonce, &ciphertext).map_err(|_| VaultError::WrongPassword)?;
    let data: VaultData = serde_json::from_slice(&plaintext).map_err(|_| VaultError::Corrupt)?;

    let data_key = crypto::generate_key_bytes().map_err(|_| VaultError::Crypto)?;
    let pw = wrap_key(
        password,
        file.kdf_mem_kib,
        file.kdf_iterations,
        file.kdf_parallelism,
        &data_key,
    )?;
    let unlocked = Unlocked {
        data_key,
        level: file.level.clone(),
        mem_kib: file.kdf_mem_kib,
        iterations: file.kdf_iterations,
        parallelism: file.kdf_parallelism,
        pw,
        rec: None,
        data,
    };
    write_vault(path, &unlocked)?;
    Ok(unlocked)
}

fn save_unlocked(path: &Path, unlocked: &Unlocked) -> Result<(), VaultError> {
    write_vault(path, unlocked)
}

fn write_vault(path: &Path, u: &Unlocked) -> Result<(), VaultError> {
    let plaintext = Zeroizing::new(serde_json::to_vec(&u.data).map_err(|_| VaultError::Io)?);
    let (data_nonce, data_ct) =
        crypto::encrypt(&u.data_key, &plaintext).map_err(|_| VaultError::Crypto)?;

    let (rec_salt, rec_nonce, rec_wrap) = match &u.rec {
        Some((s, n, w)) => (STANDARD.encode(s), STANDARD.encode(n), STANDARD.encode(w)),
        None => (String::new(), String::new(), String::new()),
    };

    let file = VaultFileV2 {
        version: VAULT_VERSION,
        level: u.level.clone(),
        kdf_mem_kib: u.mem_kib,
        kdf_iterations: u.iterations,
        kdf_parallelism: u.parallelism,
        pw_salt: STANDARD.encode(&u.pw.0),
        pw_nonce: STANDARD.encode(&u.pw.1),
        pw_wrap: STANDARD.encode(&u.pw.2),
        rec_salt,
        rec_nonce,
        rec_wrap,
        data_nonce: STANDARD.encode(data_nonce),
        data_ct: STANDARD.encode(data_ct),
    };
    let json = serde_json::to_vec_pretty(&file).map_err(|_| VaultError::Io)?;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|_| VaultError::Io)?;
    }

    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("vault.gestio");
    let tmp = path.with_file_name(format!("{name}.tmp"));
    fs::write(&tmp, &json).map_err(|_| VaultError::Io)?;
    fs::rename(&tmp, path).map_err(|_| VaultError::Io)?;
    Ok(())
}

fn read_raw(path: &Path) -> Result<Vec<u8>, VaultError> {
    if !path.exists() {
        return Err(VaultError::NotFound);
    }
    fs::read(path).map_err(|_| VaultError::Io)
}

fn read_version(raw: &[u8]) -> Result<u32, VaultError> {
    #[derive(Deserialize)]
    struct Peek {
        version: u32,
    }
    let peek: Peek = serde_json::from_slice(raw).map_err(|_| VaultError::Corrupt)?;
    Ok(peek.version)
}

fn generate_recovery_code() -> Result<String, VaultError> {
    keywrap::generate_recovery_code().map_err(|_| VaultError::Crypto)
}

fn normalize_recovery(input: &str) -> String {
    keywrap::normalize_recovery(input)
}

pub fn is_valid_backup(bytes: &[u8]) -> bool {
    #[derive(serde::Deserialize)]
    struct Peek {
        version: u32,
    }
    let Ok(peek) = serde_json::from_slice::<Peek>(bytes) else {
        return false;
    };
    match peek.version {
        1 => serde_json::from_slice::<VaultFileV1>(bytes).is_ok(),
        2 => serde_json::from_slice::<VaultFileV2>(bytes).is_ok(),
        _ => false,
    }
}

pub fn peek_level(path: &Path) -> String {
    read_raw(path)
        .ok()
        .and_then(|raw| serde_json::from_slice::<serde_json::Value>(&raw).ok())
        .and_then(|v| v.get("level").and_then(|l| l.as_str()).map(String::from))
        .unwrap_or_else(default_level)
}

pub fn peek_has_recovery(path: &Path) -> bool {
    read_raw(path)
        .ok()
        .and_then(|raw| serde_json::from_slice::<serde_json::Value>(&raw).ok())
        .and_then(|v| v.get("rec_wrap").and_then(|w| w.as_str()).map(|s| !s.is_empty()))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    fn temp_vault_path() -> std::path::PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let mut dir = std::env::temp_dir();
        dir.push(format!("gestio_test_{}_{}", std::process::id(), n));
        fs::create_dir_all(&dir).unwrap();
        dir.join("vault.gestio")
    }

    fn input(name: &str, username: &str, password: &str) -> EntryInput {
        EntryInput {
            name: name.to_string(),
            username: username.to_string(),
            password: password.to_string(),
            url: String::new(),
            note: String::new(),
            group: String::new(),
            kind: String::new(),
            fields: Vec::new(),
        }
    }

    fn input_in(name: &str, group: &str) -> EntryInput {
        EntryInput {
            name: name.to_string(),
            username: String::new(),
            password: String::new(),
            url: String::new(),
            note: String::new(),
            group: group.to_string(),
            kind: String::new(),
            fields: Vec::new(),
        }
    }

    #[test]
    fn is_valid_backup_accepts_real_rejects_garbage() {
        let path = temp_vault_path();
        let state = VaultState::default();
        state.create(&path, b"bon mot de passe long", "normal", false).unwrap();
        let bytes = fs::read(&path).unwrap();
        assert!(is_valid_backup(&bytes));
        assert!(!is_valid_backup(b"pas du json"));
        assert!(!is_valid_backup(b"{}"));
        assert!(!is_valid_backup(b"{\"version\":99}"));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn create_then_lock_then_unlock() {
        let path = temp_vault_path();
        let state = VaultState::default();
        state.create(&path, b"bon mot de passe long", "normal", false).unwrap();
        assert!(path.exists());
        assert!(state.is_unlocked());
        state.lock();
        assert!(!state.is_unlocked());
        state.unlock(&path, b"bon mot de passe long").unwrap();
        assert!(state.is_unlocked());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn wrong_master_password_rejected() {
        let path = temp_vault_path();
        let state = VaultState::default();
        state.create(&path, b"le bon mot de passe", "normal", false).unwrap();
        state.lock();
        let err = state.unlock(&path, b"le mauvais").unwrap_err();
        assert!(matches!(err, VaultError::WrongPassword));
        assert!(!state.is_unlocked());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn create_refuses_existing_vault() {
        let path = temp_vault_path();
        let state = VaultState::default();
        state.create(&path, b"mot de passe", "normal", false).unwrap();
        let err = state.create(&path, b"mot de passe", "normal", false).unwrap_err();
        assert!(matches!(err, VaultError::AlreadyExists));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn file_never_contains_the_master_password() {
        let path = temp_vault_path();
        let state = VaultState::default();
        state.create(&path, b"MARQUEUR_UNIQUE_12345", "normal", false).unwrap();
        let content = fs::read(&path).unwrap();
        let as_text = String::from_utf8_lossy(&content);
        assert!(!as_text.contains("MARQUEUR_UNIQUE_12345"));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn add_list_and_reveal() {
        let path = temp_vault_path();
        let state = VaultState::default();
        state.create(&path, b"maitre", "normal", false).unwrap();
        let id = state.add_entry(&path, input("GitHub", "jerome", "s3cret")).unwrap();
        let list = state.list_entries().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "GitHub");
        assert_eq!(list[0].username, "jerome");
        assert_eq!(state.reveal_password(&id).unwrap(), "s3cret");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn toggle_favorite_persists_and_survives_edit() {
        let path = temp_vault_path();
        let state = VaultState::default();
        state.create(&path, b"maitre", "normal", false).unwrap();
        let id = state.add_entry(&path, input("GitHub", "u", "p")).unwrap();
        assert!(!state.list_entries().unwrap()[0].favorite);
        assert!(state.toggle_favorite(&path, &id).unwrap());
        assert!(state.list_entries().unwrap()[0].favorite);
        state.update_entry(&path, &id, input("GitHub2", "u2", "p2")).unwrap();
        assert!(state.list_entries().unwrap()[0].favorite);
        state.lock();
        state.unlock(&path, b"maitre").unwrap();
        assert!(state.list_entries().unwrap()[0].favorite);
        assert!(!state.toggle_favorite(&path, &id).unwrap());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn note_kind_and_custom_fields_persist() {
        let path = temp_vault_path();
        let state = VaultState::default();
        state.create(&path, b"maitre", "normal", false).unwrap();
        let mut inp = input("Ma note", "", "");
        inp.kind = "note".to_string();
        inp.note = "texte secret".to_string();
        inp.fields = vec![
            CustomField {
                label: "PIN".to_string(),
                value: "4821".to_string(),
                secret: true,
            },
            CustomField {
                label: "Compte".to_string(),
                value: "FR76".to_string(),
                secret: false,
            },
        ];
        let id = state.add_entry(&path, inp).unwrap();
        state.lock();
        state.unlock(&path, b"maitre").unwrap();
        let meta = state.list_entries().unwrap();
        assert_eq!(meta[0].kind, "note");
        assert_eq!(meta[0].note, "texte secret");
        assert_eq!(meta[0].fields.len(), 2);
        assert_eq!(meta[0].fields[0].label, "PIN");
        assert_eq!(meta[0].fields[0].value, "4821");
        assert!(meta[0].fields[0].secret);
        assert!(!meta[0].fields[1].secret);

        let mut upd = input("Ma note 2", "", "");
        upd.kind = "note".to_string();
        upd.fields = vec![CustomField {
            label: "X".to_string(),
            value: "y".to_string(),
            secret: false,
        }];
        state.update_entry(&path, &id, upd).unwrap();
        let meta2 = state.list_entries().unwrap();
        assert_eq!(meta2[0].fields.len(), 1);
        assert_eq!(meta2[0].fields[0].label, "X");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn entries_persist_after_lock_and_unlock() {
        let path = temp_vault_path();
        let state = VaultState::default();
        state.create(&path, b"maitre", "normal", false).unwrap();
        let id = state.add_entry(&path, input("Steam", "joueur", "pw123")).unwrap();
        state.lock();
        state.unlock(&path, b"maitre").unwrap();
        let list = state.list_entries().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(state.reveal_password(&id).unwrap(), "pw123");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn update_and_delete_entry() {
        let path = temp_vault_path();
        let state = VaultState::default();
        state.create(&path, b"maitre", "normal", false).unwrap();
        let id = state.add_entry(&path, input("Nom", "user", "avant")).unwrap();
        state.update_entry(&path, &id, input("Nom2", "user2", "apres")).unwrap();
        assert_eq!(state.reveal_password(&id).unwrap(), "apres");
        assert_eq!(state.list_entries().unwrap()[0].name, "Nom2");
        state.delete_entry(&path, &id).unwrap();
        assert!(state.list_entries().unwrap().is_empty());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn stored_password_not_in_list_metadata() {
        let path = temp_vault_path();
        let state = VaultState::default();
        state.create(&path, b"maitre", "normal", false).unwrap();
        state.add_entry(&path, input("X", "u", "TOPSECRET")).unwrap();
        let json = serde_json::to_string(&state.list_entries().unwrap()).unwrap();
        assert!(!json.contains("TOPSECRET"));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn change_level_rekeys_and_persists() {
        let path = temp_vault_path();
        let state = VaultState::default();
        state.create(&path, b"maitre", "normal", false).unwrap();
        let id = state.add_entry(&path, input("Steam", "joueur", "pw123")).unwrap();
        state.change_level(&path, b"maitre", "parano").unwrap();
        assert_eq!(state.level().as_deref(), Some("parano"));
        state.lock();
        state.unlock(&path, b"maitre").unwrap();
        assert_eq!(state.level().as_deref(), Some("parano"));
        assert_eq!(state.reveal_password(&id).unwrap(), "pw123");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn change_level_rejects_wrong_password() {
        let path = temp_vault_path();
        let state = VaultState::default();
        state.create(&path, b"maitre", "normal", false).unwrap();
        let err = state.change_level(&path, b"pas le bon", "fort").unwrap_err();
        assert!(matches!(err, VaultError::WrongPassword));
        assert_eq!(state.level().as_deref(), Some("normal"));
        state.lock();
        state.unlock(&path, b"maitre").unwrap();
        assert_eq!(state.level().as_deref(), Some("normal"));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn groups_create_assign_and_persist() {
        let path = temp_vault_path();
        let state = VaultState::default();
        state.create(&path, b"maitre", "normal", false).unwrap();
        state.create_group(&path, "LoL").unwrap();
        state.add_entry(&path, input_in("Compte 1", "LoL")).unwrap();
        state.add_entry(&path, input_in("Compte 2", "LoL")).unwrap();
        state.lock();
        state.unlock(&path, b"maitre").unwrap();
        assert_eq!(state.list_groups().unwrap(), vec!["LoL".to_string()]);
        let in_lol = state
            .list_entries()
            .unwrap()
            .into_iter()
            .filter(|e| e.group == "LoL")
            .count();
        assert_eq!(in_lol, 2);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn create_group_rejects_empty_and_duplicate() {
        let path = temp_vault_path();
        let state = VaultState::default();
        state.create(&path, b"maitre", "normal", false).unwrap();
        assert!(matches!(
            state.create_group(&path, "   ").unwrap_err(),
            VaultError::GroupNameEmpty
        ));
        state.create_group(&path, "Perso").unwrap();
        assert!(matches!(
            state.create_group(&path, "Perso").unwrap_err(),
            VaultError::GroupExists
        ));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn reorder_groups_changes_order() {
        let path = temp_vault_path();
        let state = VaultState::default();
        state.create(&path, b"maitre", "normal", false).unwrap();
        state.create_group(&path, "A").unwrap();
        state.create_group(&path, "B").unwrap();
        state.create_group(&path, "C").unwrap();
        state
            .reorder_groups(&path, vec!["C".to_string(), "A".to_string(), "B".to_string()])
            .unwrap();
        state.lock();
        state.unlock(&path, b"maitre").unwrap();
        assert_eq!(
            state.list_groups().unwrap(),
            vec!["C".to_string(), "A".to_string(), "B".to_string()]
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn rename_group_updates_members() {
        let path = temp_vault_path();
        let state = VaultState::default();
        state.create(&path, b"maitre", "normal", false).unwrap();
        state.create_group(&path, "LoL").unwrap();
        state.add_entry(&path, input_in("Compte", "LoL")).unwrap();
        state.rename_group(&path, "LoL", "League").unwrap();
        assert_eq!(state.list_groups().unwrap(), vec!["League".to_string()]);
        assert_eq!(state.list_entries().unwrap()[0].group, "League");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn group_favorite_toggle_rename_delete() {
        let path = temp_vault_path();
        let state = VaultState::default();
        state.create(&path, b"maitre", "normal", false).unwrap();
        state.create_group(&path, "LoL").unwrap();
        assert!(state.list_group_favorites().unwrap().is_empty());
        assert!(state.toggle_group_favorite(&path, "LoL").unwrap());
        assert_eq!(state.list_group_favorites().unwrap(), vec!["LoL".to_string()]);
        state.rename_group(&path, "LoL", "League").unwrap();
        assert_eq!(state.list_group_favorites().unwrap(), vec!["League".to_string()]);
        state.lock();
        state.unlock(&path, b"maitre").unwrap();
        assert_eq!(state.list_group_favorites().unwrap(), vec!["League".to_string()]);
        assert!(!state.toggle_group_favorite(&path, "League").unwrap());
        assert!(state.list_group_favorites().unwrap().is_empty());
        state.toggle_group_favorite(&path, "League").unwrap();
        state.delete_group(&path, "League").unwrap();
        assert!(state.list_group_favorites().unwrap().is_empty());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn delete_group_ungroups_members() {
        let path = temp_vault_path();
        let state = VaultState::default();
        state.create(&path, b"maitre", "normal", false).unwrap();
        state.create_group(&path, "LoL").unwrap();
        state.add_entry(&path, input_in("Compte", "LoL")).unwrap();
        state.delete_group(&path, "LoL").unwrap();
        assert!(state.list_groups().unwrap().is_empty());
        assert_eq!(state.list_entries().unwrap()[0].group, "");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn set_password_updates_and_persists() {
        let path = temp_vault_path();
        let state = VaultState::default();
        state.create(&path, b"maitre", "normal", false).unwrap();
        let id = state.add_entry(&path, input("X", "u", "ancien")).unwrap();
        state.set_password(&path, &id, "nouveau-genere").unwrap();
        assert_eq!(state.reveal_password(&id).unwrap(), "nouveau-genere");
        state.lock();
        state.unlock(&path, b"maitre").unwrap();
        assert_eq!(state.reveal_password(&id).unwrap(), "nouveau-genere");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn reorder_and_regroup_entries() {
        let path = temp_vault_path();
        let state = VaultState::default();
        state.create(&path, b"maitre", "normal", false).unwrap();
        let a = state.add_entry(&path, input("A", "", "")).unwrap();
        let b = state.add_entry(&path, input("B", "", "")).unwrap();
        let c = state.add_entry(&path, input("C", "", "")).unwrap();
        state.create_group(&path, "G").unwrap();
        let order = vec![
            EntryOrder {
                id: c,
                group: "G".to_string(),
            },
            EntryOrder {
                id: a,
                group: String::new(),
            },
            EntryOrder {
                id: b,
                group: String::new(),
            },
        ];
        state.reorder_entries(&path, order).unwrap();
        state.lock();
        state.unlock(&path, b"maitre").unwrap();
        let list = state.list_entries().unwrap();
        assert_eq!(
            list.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(),
            vec!["C", "A", "B"]
        );
        assert_eq!(list[0].group, "G");
        assert_eq!(list[1].group, "");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn change_master_password_rekeys() {
        let path = temp_vault_path();
        let state = VaultState::default();
        state.create(&path, b"ancien mot de passe", "fort", false).unwrap();
        let id = state.add_entry(&path, input("X", "u", "secret")).unwrap();
        state.change_master_password(&path, b"ancien mot de passe", b"nouveau mot de passe").unwrap();
        state.lock();
        assert!(matches!(
            state.unlock(&path, b"ancien mot de passe").unwrap_err(),
            VaultError::WrongPassword
        ));
        state.unlock(&path, b"nouveau mot de passe").unwrap();
        assert_eq!(state.level().as_deref(), Some("fort"));
        assert_eq!(state.reveal_password(&id).unwrap(), "secret");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn change_master_password_rejects_wrong_current() {
        let path = temp_vault_path();
        let state = VaultState::default();
        state.create(&path, b"le bon", "normal", false).unwrap();
        assert!(matches!(
            state.change_master_password(&path, b"le mauvais", b"peu importe").unwrap_err(),
            VaultError::WrongPassword
        ));
        state.lock();
        state.unlock(&path, b"le bon").unwrap();
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn level_persists_after_lock_and_unlock() {
        let path = temp_vault_path();
        let state = VaultState::default();
        state.create(&path, b"maitre", "fort", false).unwrap();
        assert_eq!(state.level().as_deref(), Some("fort"));
        state.lock();
        assert_eq!(state.level(), None);
        state.unlock(&path, b"maitre").unwrap();
        assert_eq!(state.level().as_deref(), Some("fort"));
        let _ = fs::remove_file(&path);
    }

    fn write_v1(path: &Path, password: &[u8], data: &VaultData) {
        let (m, i, p) = crypto::level_params("normal");
        let salt = crypto::generate_salt().unwrap();
        let key = crypto::derive_key(password, &salt, m, i, p).unwrap();
        let plaintext = serde_json::to_vec(data).unwrap();
        let (nonce, ct) = crypto::encrypt(&key, &plaintext).unwrap();
        let json = serde_json::json!({
            "version": 1,
            "level": "fort",
            "kdf_mem_kib": m,
            "kdf_iterations": i,
            "kdf_parallelism": p,
            "salt": STANDARD.encode(salt),
            "nonce": STANDARD.encode(nonce),
            "ciphertext": STANDARD.encode(ct),
        });
        fs::write(path, serde_json::to_vec_pretty(&json).unwrap()).unwrap();
    }

    #[test]
    fn v1_vault_migrates_on_unlock() {
        let path = temp_vault_path();
        let mut data = VaultData::default();
        data.entries.push(Entry {
            id: "abc".into(),
            name: "Ancien".into(),
            username: "u".into(),
            password: "vieuxsecret".into(),
            url: String::new(),
            note: String::new(),
            group: String::new(),
            modified: 0,
            favorite: false,
            kind: String::new(),
            fields: Vec::new(),
            password_modified: 0,
        });
        write_v1(&path, b"mot de passe v1", &data);

        let state = VaultState::default();
        state.unlock(&path, b"mot de passe v1").unwrap();
        assert_eq!(state.reveal_password("abc").unwrap(), "vieuxsecret");
        assert_eq!(state.level().as_deref(), Some("fort"));

        let raw = fs::read(&path).unwrap();
        assert_eq!(read_version(&raw).unwrap(), 2);

        state.lock();
        state.unlock(&path, b"mot de passe v1").unwrap();
        assert_eq!(state.reveal_password("abc").unwrap(), "vieuxsecret");
        assert!(matches!(
            state.unlock(&path, b"mauvais").unwrap_err(),
            VaultError::WrongPassword
        ));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn recovery_code_unlocks_and_normalizes() {
        let path = temp_vault_path();
        let state = VaultState::default();
        let code = state
            .create(&path, b"maitre", "normal", true)
            .unwrap()
            .expect("code de secours attendu");
        let id = state.add_entry(&path, input("Compte", "u", "s3cret")).unwrap();
        state.lock();

        let messy = format!("  {}  ", code.to_lowercase().replace('-', " "));
        state.unlock_recovery(&path, &messy).unwrap();
        assert_eq!(state.reveal_password(&id).unwrap(), "s3cret");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn wrong_recovery_code_rejected() {
        let path = temp_vault_path();
        let state = VaultState::default();
        state.create(&path, b"maitre", "normal", true).unwrap();
        state.lock();
        assert!(matches!(
            state.unlock_recovery(&path, "AAAA-BBBB-CCCC-DDDD").unwrap_err(),
            VaultError::WrongPassword
        ));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn recovery_unavailable_when_not_set_up() {
        let path = temp_vault_path();
        let state = VaultState::default();
        state.create(&path, b"maitre", "normal", false).unwrap();
        assert!(!vault_has_recovery_at(&path));
        state.lock();
        assert!(matches!(
            state.unlock_recovery(&path, "AAAA-BBBB-CCCC-DDDD").unwrap_err(),
            VaultError::NoRecovery
        ));
        let _ = fs::remove_file(&path);
    }

    fn vault_has_recovery_at(path: &Path) -> bool {
        peek_has_recovery(path)
    }

    #[test]
    fn setup_recovery_after_creation() {
        let path = temp_vault_path();
        let state = VaultState::default();
        state.create(&path, b"maitre", "normal", false).unwrap();
        let id = state.add_entry(&path, input("Compte", "u", "abc")).unwrap();
        assert!(!state.has_recovery());
        let code = state.setup_recovery(&path).unwrap();
        assert!(state.has_recovery());
        assert!(peek_has_recovery(&path));
        state.lock();
        state.unlock_recovery(&path, &code).unwrap();
        assert_eq!(state.reveal_password(&id).unwrap(), "abc");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn reset_master_password_after_recovery() {
        let path = temp_vault_path();
        let state = VaultState::default();
        let code = state
            .create(&path, b"ancien maitre", "normal", true)
            .unwrap()
            .unwrap();
        let id = state.add_entry(&path, input("Compte", "u", "garde")).unwrap();
        state.lock();

        state.unlock_recovery(&path, &code).unwrap();
        state.reset_master_password(&path, b"nouveau maitre").unwrap();
        state.lock();

        assert!(matches!(
            state.unlock(&path, b"ancien maitre").unwrap_err(),
            VaultError::WrongPassword
        ));
        state.unlock(&path, b"nouveau maitre").unwrap();
        assert_eq!(state.reveal_password(&id).unwrap(), "garde");
        state.lock();
        state.unlock_recovery(&path, &code).unwrap();
        assert_eq!(state.reveal_password(&id).unwrap(), "garde");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn change_level_keeps_data_and_recovery() {
        let path = temp_vault_path();
        let state = VaultState::default();
        let code = state
            .create(&path, b"maitre", "normal", true)
            .unwrap()
            .unwrap();
        let id = state.add_entry(&path, input("Compte", "u", "intact")).unwrap();
        state.change_level(&path, b"maitre", "parano").unwrap();
        assert_eq!(state.level().as_deref(), Some("parano"));
        state.lock();
        state.unlock(&path, b"maitre").unwrap();
        assert_eq!(state.reveal_password(&id).unwrap(), "intact");
        state.lock();
        state.unlock_recovery(&path, &code).unwrap();
        assert_eq!(state.reveal_password(&id).unwrap(), "intact");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn recovery_code_absent_from_file() {
        let path = temp_vault_path();
        let state = VaultState::default();
        let code = state
            .create(&path, b"maitre", "normal", true)
            .unwrap()
            .unwrap();
        let content = fs::read(&path).unwrap();
        let as_text = String::from_utf8_lossy(&content);
        assert!(!as_text.contains(&code));
        let normalized = normalize_recovery(&code);
        assert!(!as_text.contains(&normalized));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn remove_recovery_disables_it() {
        let path = temp_vault_path();
        let state = VaultState::default();
        let code = state
            .create(&path, b"maitre", "normal", true)
            .unwrap()
            .unwrap();
        state.remove_recovery(&path).unwrap();
        assert!(!state.has_recovery());
        assert!(!peek_has_recovery(&path));
        state.lock();
        assert!(matches!(
            state.unlock_recovery(&path, &code).unwrap_err(),
            VaultError::NoRecovery
        ));
        state.unlock(&path, b"maitre").unwrap();
        let _ = fs::remove_file(&path);
    }
}
