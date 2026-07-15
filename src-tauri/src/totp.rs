use crate::crypto;
use crate::keywrap::{self, Wrap};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use std::fs;
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, Zeroizing};

pub const TOTP_VERSION: u32 = 2;

type HmacSha1 = Hmac<Sha1>;

#[derive(Deserialize)]
struct TotpFileV1 {
    kdf_mem_kib: u32,
    kdf_iterations: u32,
    kdf_parallelism: u32,
    salt: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Serialize, Deserialize)]
struct TotpFileV2 {
    version: u32,
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
struct TotpData {
    entries: Vec<TotpEntry>,
}

#[derive(Serialize, Deserialize, Clone)]
struct TotpEntry {
    id: String,
    label: String,
    issuer: String,
    secret: String,
    digits: u32,
    period: u32,
}

#[derive(Deserialize)]
pub struct TotpInput {
    pub label: String,
    pub issuer: String,
    pub secret: String,
    pub digits: u32,
    pub period: u32,
}

#[derive(Serialize)]
pub struct TotpMeta {
    pub id: String,
    pub label: String,
    pub issuer: String,
}

#[derive(Serialize)]
pub struct TotpCode {
    pub id: String,
    pub code: String,
    pub remaining: u32,
    pub period: u32,
}

struct Unlocked {
    data_key: Zeroizing<[u8; crypto::KEY_LEN]>,
    mem_kib: u32,
    iterations: u32,
    parallelism: u32,
    pw: Wrap,
    rec: Option<Wrap>,
    data: TotpData,
}

#[derive(Default)]
pub struct TotpState {
    inner: Mutex<Option<Unlocked>>,
}

#[derive(Debug)]
pub enum TotpError {
    AlreadyExists,
    NotFound,
    Locked,
    WrongPassword,
    EntryNotFound,
    InvalidSecret,
    NoRecovery,
    Corrupt,
    Io,
    Crypto,
}

impl TotpState {
    pub fn is_unlocked(&self) -> bool {
        self.inner.lock().map(|g| g.is_some()).unwrap_or(false)
    }

    pub fn lock(&self) {
        if let Ok(mut guard) = self.inner.lock() {
            if let Some(unlocked) = guard.as_mut() {
                for entry in &mut unlocked.data.entries {
                    entry.secret.zeroize();
                }
            }
            *guard = None;
        }
    }

    pub fn create(
        &self,
        path: &Path,
        password: &[u8],
        with_recovery: bool,
    ) -> Result<Option<String>, TotpError> {
        if path.exists() {
            return Err(TotpError::AlreadyExists);
        }
        let mem_kib = crypto::KDF_MEM_KIB;
        let iterations = crypto::KDF_ITERATIONS;
        let parallelism = crypto::KDF_PARALLELISM;
        let data_key = crypto::generate_key_bytes().map_err(|_| TotpError::Crypto)?;
        let pw = wrap_key(password, mem_kib, iterations, parallelism, &data_key)?;

        let (rec, code) = if with_recovery {
            let code = generate_recovery_code()?;
            let (rm, ri, rp) = keywrap::recovery_params();
            let rec = wrap_key(normalize_recovery(&code).as_bytes(), rm, ri, rp, &data_key)?;
            (Some(rec), Some(code))
        } else {
            (None, None)
        };

        let unlocked = Unlocked {
            data_key,
            mem_kib,
            iterations,
            parallelism,
            pw,
            rec,
            data: TotpData::default(),
        };
        write_totp(path, &unlocked)?;
        *self.inner.lock().map_err(|_| TotpError::Io)? = Some(unlocked);
        Ok(code)
    }

    pub fn unlock(&self, path: &Path, password: &[u8]) -> Result<(), TotpError> {
        let raw = read_raw(path)?;
        let unlocked = match read_version(&raw)? {
            1 => migrate_v1(path, password, &raw)?,
            2 => {
                let file: TotpFileV2 =
                    serde_json::from_slice(&raw).map_err(|_| TotpError::Corrupt)?;
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
            _ => return Err(TotpError::Corrupt),
        };
        *self.inner.lock().map_err(|_| TotpError::Io)? = Some(unlocked);
        Ok(())
    }

    pub fn unlock_recovery(&self, path: &Path, recovery: &str) -> Result<(), TotpError> {
        let raw = read_raw(path)?;
        if read_version(&raw)? != 2 {
            return Err(TotpError::NoRecovery);
        }
        let file: TotpFileV2 = serde_json::from_slice(&raw).map_err(|_| TotpError::Corrupt)?;
        if file.rec_wrap.is_empty() {
            return Err(TotpError::NoRecovery);
        }
        let rec = decode_wrap(&file.rec_salt, &file.rec_nonce, &file.rec_wrap)?;
        let (rm, ri, rp) = keywrap::recovery_params();
        let data_key = unwrap_key(normalize_recovery(recovery).as_bytes(), rm, ri, rp, &rec)?;
        let unlocked = build_unlocked(&file, data_key)?;
        *self.inner.lock().map_err(|_| TotpError::Io)? = Some(unlocked);
        Ok(())
    }

    pub fn has_recovery(&self) -> bool {
        self.inner
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(|u| u.rec.is_some()))
            .unwrap_or(false)
    }

    pub fn change_master_password(
        &self,
        path: &Path,
        current: &[u8],
        new: &[u8],
    ) -> Result<(), TotpError> {
        let mut guard = self.inner.lock().map_err(|_| TotpError::Io)?;
        let unlocked = guard.as_mut().ok_or(TotpError::Locked)?;

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
        match write_totp(path, unlocked) {
            Ok(()) => Ok(()),
            Err(e) => {
                unlocked.pw = old;
                Err(e)
            }
        }
    }

    pub fn reset_master_password(&self, path: &Path, new: &[u8]) -> Result<(), TotpError> {
        let mut guard = self.inner.lock().map_err(|_| TotpError::Io)?;
        let unlocked = guard.as_mut().ok_or(TotpError::Locked)?;
        let new_pw = wrap_key(
            new,
            unlocked.mem_kib,
            unlocked.iterations,
            unlocked.parallelism,
            &unlocked.data_key,
        )?;
        let old = unlocked.pw.clone();
        unlocked.pw = new_pw;
        match write_totp(path, unlocked) {
            Ok(()) => Ok(()),
            Err(e) => {
                unlocked.pw = old;
                Err(e)
            }
        }
    }

    pub fn setup_recovery(&self, path: &Path) -> Result<String, TotpError> {
        let mut guard = self.inner.lock().map_err(|_| TotpError::Io)?;
        let unlocked = guard.as_mut().ok_or(TotpError::Locked)?;
        let code = generate_recovery_code()?;
        let (rm, ri, rp) = keywrap::recovery_params();
        let rec = wrap_key(normalize_recovery(&code).as_bytes(), rm, ri, rp, &unlocked.data_key)?;
        let old = unlocked.rec.clone();
        unlocked.rec = Some(rec);
        match write_totp(path, unlocked) {
            Ok(()) => Ok(code),
            Err(e) => {
                unlocked.rec = old;
                Err(e)
            }
        }
    }

    pub fn remove_recovery(&self, path: &Path) -> Result<(), TotpError> {
        let mut guard = self.inner.lock().map_err(|_| TotpError::Io)?;
        let unlocked = guard.as_mut().ok_or(TotpError::Locked)?;
        let old = unlocked.rec.take();
        match write_totp(path, unlocked) {
            Ok(()) => Ok(()),
            Err(e) => {
                unlocked.rec = old;
                Err(e)
            }
        }
    }

    pub fn list(&self) -> Result<Vec<TotpMeta>, TotpError> {
        let guard = self.inner.lock().map_err(|_| TotpError::Io)?;
        let unlocked = guard.as_ref().ok_or(TotpError::Locked)?;
        Ok(unlocked
            .data
            .entries
            .iter()
            .map(|e| TotpMeta {
                id: e.id.clone(),
                label: e.label.clone(),
                issuer: e.issuer.clone(),
            })
            .collect())
    }

    pub fn add(&self, path: &Path, input: TotpInput) -> Result<String, TotpError> {
        let secret = normalize_secret(&input.secret);
        if base32_decode(&secret).map(|k| k.is_empty()).unwrap_or(true) {
            return Err(TotpError::InvalidSecret);
        }
        let digits = input.digits.clamp(6, 8);
        let period = if input.period == 0 { 30 } else { input.period.clamp(5, 300) };
        let id = new_id()?;
        let mut guard = self.inner.lock().map_err(|_| TotpError::Io)?;
        let unlocked = guard.as_mut().ok_or(TotpError::Locked)?;
        unlocked.data.entries.push(TotpEntry {
            id: id.clone(),
            label: input.label,
            issuer: input.issuer,
            secret,
            digits,
            period,
        });
        match save_unlocked(path, unlocked) {
            Ok(()) => Ok(id),
            Err(e) => {
                unlocked.data.entries.pop();
                Err(e)
            }
        }
    }

    pub fn delete(&self, path: &Path, id: &str) -> Result<(), TotpError> {
        let mut guard = self.inner.lock().map_err(|_| TotpError::Io)?;
        let unlocked = guard.as_mut().ok_or(TotpError::Locked)?;
        let index = unlocked
            .data
            .entries
            .iter()
            .position(|e| e.id == id)
            .ok_or(TotpError::EntryNotFound)?;
        let removed = unlocked.data.entries.remove(index);
        match save_unlocked(path, unlocked) {
            Ok(()) => Ok(()),
            Err(e) => {
                unlocked.data.entries.insert(index, removed);
                Err(e)
            }
        }
    }

    pub fn codes(&self) -> Result<Vec<TotpCode>, TotpError> {
        let guard = self.inner.lock().map_err(|_| TotpError::Io)?;
        let unlocked = guard.as_ref().ok_or(TotpError::Locked)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Ok(unlocked
            .data
            .entries
            .iter()
            .map(|e| {
                let period = if e.period == 0 { 30 } else { e.period.clamp(5, 300) };
                let digits = e.digits.clamp(6, 8);
                let code = generate_code(&e.secret, digits, period, now)
                    .unwrap_or_else(|| "-".repeat(digits as usize));
                let remaining = period - (now % period as u64) as u32;
                TotpCode {
                    id: e.id.clone(),
                    code,
                    remaining,
                    period,
                }
            })
            .collect())
    }
}

fn normalize_secret(secret: &str) -> String {
    secret
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect::<String>()
        .to_ascii_uppercase()
}

fn base32_decode(input: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut bits: u32 = 0;
    let mut nbits: u32 = 0;
    let mut out = Vec::new();
    for c in input.chars() {
        if c == '=' {
            continue;
        }
        let upper = c.to_ascii_uppercase() as u8;
        let value = ALPHABET.iter().position(|&x| x == upper)? as u32;
        bits = (bits << 5) | value;
        nbits += 5;
        if nbits >= 8 {
            nbits -= 8;
            out.push((bits >> nbits) as u8);
        }
    }
    Some(out)
}

fn hmac_sha1(key: &[u8], message: &[u8]) -> [u8; 20] {
    let mut mac = HmacSha1::new_from_slice(key).expect("HMAC accepte toute longueur de clef");
    mac.update(message);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 20];
    out.copy_from_slice(&result);
    out
}

fn generate_code(secret: &str, digits: u32, period: u32, unix: u64) -> Option<String> {
    let digits = digits.clamp(6, 8);
    let key = base32_decode(secret)?;
    if key.is_empty() {
        return None;
    }
    let counter = unix / period.max(1) as u64;
    let hmac = hmac_sha1(&key, &counter.to_be_bytes());
    let offset = (hmac[19] & 0x0f) as usize;
    let binary = ((hmac[offset] as u32 & 0x7f) << 24)
        | ((hmac[offset + 1] as u32) << 16)
        | ((hmac[offset + 2] as u32) << 8)
        | (hmac[offset + 3] as u32);
    let modulo = 10u32.checked_pow(digits)?;
    Some(format!("{:0width$}", binary % modulo, width = digits as usize))
}

fn new_id() -> Result<String, TotpError> {
    let bytes = crypto::generate_id_bytes().map_err(|_| TotpError::Crypto)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn wrap_key(
    secret: &[u8],
    mem_kib: u32,
    iterations: u32,
    parallelism: u32,
    data_key: &[u8; crypto::KEY_LEN],
) -> Result<Wrap, TotpError> {
    keywrap::wrap_key(secret, mem_kib, iterations, parallelism, data_key)
        .map_err(|_| TotpError::Crypto)
}

fn unwrap_key(
    secret: &[u8],
    mem_kib: u32,
    iterations: u32,
    parallelism: u32,
    wrap: &Wrap,
) -> Result<Zeroizing<[u8; crypto::KEY_LEN]>, TotpError> {
    keywrap::unwrap_key(secret, mem_kib, iterations, parallelism, wrap).map_err(|e| match e {
        keywrap::UnwrapError::Wrong => TotpError::WrongPassword,
        keywrap::UnwrapError::Corrupt => TotpError::Corrupt,
        keywrap::UnwrapError::Crypto => TotpError::Crypto,
    })
}

fn decode_wrap(salt: &str, nonce: &str, ct: &str) -> Result<Wrap, TotpError> {
    keywrap::decode_wrap(salt, nonce, ct).map_err(|_| TotpError::Corrupt)
}

fn generate_recovery_code() -> Result<String, TotpError> {
    keywrap::generate_recovery_code().map_err(|_| TotpError::Crypto)
}

fn normalize_recovery(input: &str) -> String {
    keywrap::normalize_recovery(input)
}

fn build_unlocked(
    file: &TotpFileV2,
    data_key: Zeroizing<[u8; crypto::KEY_LEN]>,
) -> Result<Unlocked, TotpError> {
    let pw = decode_wrap(&file.pw_salt, &file.pw_nonce, &file.pw_wrap)?;
    let rec = if file.rec_wrap.is_empty() {
        None
    } else {
        Some(decode_wrap(&file.rec_salt, &file.rec_nonce, &file.rec_wrap)?)
    };
    let data_nonce = STANDARD.decode(&file.data_nonce).map_err(|_| TotpError::Corrupt)?;
    let data_ct = STANDARD.decode(&file.data_ct).map_err(|_| TotpError::Corrupt)?;
    let plaintext =
        crypto::decrypt(&data_key, &data_nonce, &data_ct).map_err(|_| TotpError::WrongPassword)?;
    let data: TotpData = serde_json::from_slice(&plaintext).map_err(|_| TotpError::Corrupt)?;
    Ok(Unlocked {
        data_key,
        mem_kib: file.kdf_mem_kib,
        iterations: file.kdf_iterations,
        parallelism: file.kdf_parallelism,
        pw,
        rec,
        data,
    })
}

fn migrate_v1(path: &Path, password: &[u8], raw: &[u8]) -> Result<Unlocked, TotpError> {
    let file: TotpFileV1 = serde_json::from_slice(raw).map_err(|_| TotpError::Corrupt)?;
    let salt = STANDARD.decode(&file.salt).map_err(|_| TotpError::Corrupt)?;
    let nonce = STANDARD.decode(&file.nonce).map_err(|_| TotpError::Corrupt)?;
    let ciphertext = STANDARD.decode(&file.ciphertext).map_err(|_| TotpError::Corrupt)?;
    let key = crypto::derive_key(
        password,
        &salt,
        file.kdf_mem_kib,
        file.kdf_iterations,
        file.kdf_parallelism,
    )
    .map_err(|_| TotpError::Crypto)?;
    let plaintext =
        crypto::decrypt(&key, &nonce, &ciphertext).map_err(|_| TotpError::WrongPassword)?;
    let data: TotpData = serde_json::from_slice(&plaintext).map_err(|_| TotpError::Corrupt)?;

    let data_key = crypto::generate_key_bytes().map_err(|_| TotpError::Crypto)?;
    let pw = wrap_key(
        password,
        file.kdf_mem_kib,
        file.kdf_iterations,
        file.kdf_parallelism,
        &data_key,
    )?;
    let unlocked = Unlocked {
        data_key,
        mem_kib: file.kdf_mem_kib,
        iterations: file.kdf_iterations,
        parallelism: file.kdf_parallelism,
        pw,
        rec: None,
        data,
    };
    write_totp(path, &unlocked)?;
    Ok(unlocked)
}

fn save_unlocked(path: &Path, unlocked: &Unlocked) -> Result<(), TotpError> {
    write_totp(path, unlocked)
}

fn write_totp(path: &Path, u: &Unlocked) -> Result<(), TotpError> {
    let plaintext = Zeroizing::new(serde_json::to_vec(&u.data).map_err(|_| TotpError::Io)?);
    let (data_nonce, data_ct) =
        crypto::encrypt(&u.data_key, &plaintext).map_err(|_| TotpError::Crypto)?;

    let (rec_salt, rec_nonce, rec_wrap) = match &u.rec {
        Some(rec) => keywrap::encode_wrap(rec),
        None => (String::new(), String::new(), String::new()),
    };
    let (pw_salt, pw_nonce, pw_wrap) = keywrap::encode_wrap(&u.pw);

    let file = TotpFileV2 {
        version: TOTP_VERSION,
        kdf_mem_kib: u.mem_kib,
        kdf_iterations: u.iterations,
        kdf_parallelism: u.parallelism,
        pw_salt,
        pw_nonce,
        pw_wrap,
        rec_salt,
        rec_nonce,
        rec_wrap,
        data_nonce: STANDARD.encode(data_nonce),
        data_ct: STANDARD.encode(data_ct),
    };
    let json = serde_json::to_vec_pretty(&file).map_err(|_| TotpError::Io)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|_| TotpError::Io)?;
    }
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("totp.gestio");
    let tmp = path.with_file_name(format!("{name}.tmp"));
    fs::write(&tmp, &json).map_err(|_| TotpError::Io)?;
    fs::rename(&tmp, path).map_err(|_| TotpError::Io)?;
    Ok(())
}

fn read_raw(path: &Path) -> Result<Vec<u8>, TotpError> {
    if !path.exists() {
        return Err(TotpError::NotFound);
    }
    fs::read(path).map_err(|_| TotpError::Io)
}

fn read_version(raw: &[u8]) -> Result<u32, TotpError> {
    #[derive(Deserialize)]
    struct Peek {
        version: u32,
    }
    let peek: Peek = serde_json::from_slice(raw).map_err(|_| TotpError::Corrupt)?;
    Ok(peek.version)
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

    fn temp_totp_path() -> std::path::PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let mut dir = std::env::temp_dir();
        dir.push(format!("gestio_totp_test_{}_{}", std::process::id(), n));
        fs::create_dir_all(&dir).unwrap();
        dir.join("totp.gestio")
    }

    fn input(label: &str, secret: &str) -> TotpInput {
        TotpInput {
            label: label.to_string(),
            issuer: String::new(),
            secret: secret.to_string(),
            digits: 6,
            period: 30,
        }
    }

    #[test]
    fn rfc6238_vector_sha1() {
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        assert_eq!(generate_code(secret, 8, 30, 59).unwrap(), "94287082");
        assert_eq!(generate_code(secret, 6, 30, 59).unwrap(), "287082");
        assert_eq!(generate_code(secret, 8, 30, 1111111109).unwrap(), "07081804");
    }

    #[test]
    fn generate_code_never_panics_on_abnormal_digits() {
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        assert_eq!(generate_code(secret, 4_000_000_000, 30, 59).unwrap().len(), 8);
        assert_eq!(generate_code(secret, 0, 0, 59).unwrap().len(), 6);
        assert_eq!(generate_code(secret, 15, 300, 59).unwrap().len(), 8);
    }

    #[test]
    fn create_add_and_codes() {
        let path = temp_totp_path();
        let state = TotpState::default();
        state.create(&path, b"mot de passe totp", false).unwrap();
        let id = state
            .add(&path, input("OVH", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"))
            .unwrap();
        state.lock();
        state.unlock(&path, b"mot de passe totp").unwrap();
        let list = state.list().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].label, "OVH");
        let codes = state.codes().unwrap();
        assert_eq!(codes.len(), 1);
        assert_eq!(codes[0].code.len(), 6);
        assert_eq!(codes[0].id, id);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn rejects_invalid_secret() {
        let path = temp_totp_path();
        let state = TotpState::default();
        state.create(&path, b"pw", false).unwrap();
        assert!(matches!(
            state.add(&path, input("X", "pas du base32 !!!")).unwrap_err(),
            TotpError::InvalidSecret
        ));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn wrong_password_rejected() {
        let path = temp_totp_path();
        let state = TotpState::default();
        state.create(&path, b"le bon", false).unwrap();
        state.lock();
        assert!(matches!(
            state.unlock(&path, b"le mauvais").unwrap_err(),
            TotpError::WrongPassword
        ));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn change_master_password_rekeys() {
        let path = temp_totp_path();
        let state = TotpState::default();
        state.create(&path, b"ancien totp", false).unwrap();
        let id = state
            .add(&path, input("OVH", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"))
            .unwrap();
        state.change_master_password(&path, b"ancien totp", b"nouveau totp").unwrap();
        state.lock();
        assert!(matches!(
            state.unlock(&path, b"ancien totp").unwrap_err(),
            TotpError::WrongPassword
        ));
        state.unlock(&path, b"nouveau totp").unwrap();
        assert_eq!(state.list().unwrap()[0].id, id);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn change_master_password_rejects_wrong_current() {
        let path = temp_totp_path();
        let state = TotpState::default();
        state.create(&path, b"le bon totp", false).unwrap();
        assert!(matches!(
            state.change_master_password(&path, b"le mauvais", b"peu importe").unwrap_err(),
            TotpError::WrongPassword
        ));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn secret_never_in_file() {
        let path = temp_totp_path();
        let state = TotpState::default();
        state.create(&path, b"pw", false).unwrap();
        state
            .add(&path, input("X", "MARQUEURBASE32GEZDGNBVGY3TQOJQ"))
            .unwrap();
        let content = fs::read(&path).unwrap();
        let text = String::from_utf8_lossy(&content);
        assert!(!text.contains("MARQUEURBASE32"));
        let _ = fs::remove_file(&path);
    }

    fn write_v1(path: &Path, password: &[u8], data: &TotpData) {
        let (m, i, p) = (
            crypto::KDF_MEM_KIB,
            crypto::KDF_ITERATIONS,
            crypto::KDF_PARALLELISM,
        );
        let salt = crypto::generate_salt().unwrap();
        let key = crypto::derive_key(password, &salt, m, i, p).unwrap();
        let plaintext = serde_json::to_vec(data).unwrap();
        let (nonce, ct) = crypto::encrypt(&key, &plaintext).unwrap();
        let json = serde_json::json!({
            "version": 1,
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
    fn v1_totp_migrates_on_unlock() {
        let path = temp_totp_path();
        let mut data = TotpData::default();
        data.entries.push(TotpEntry {
            id: "abc".into(),
            label: "OVH".into(),
            issuer: String::new(),
            secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into(),
            digits: 6,
            period: 30,
        });
        write_v1(&path, b"mot de passe v1", &data);

        let state = TotpState::default();
        state.unlock(&path, b"mot de passe v1").unwrap();
        assert_eq!(state.list().unwrap()[0].label, "OVH");

        let raw = fs::read(&path).unwrap();
        assert_eq!(read_version(&raw).unwrap(), 2);

        state.lock();
        state.unlock(&path, b"mot de passe v1").unwrap();
        assert_eq!(state.codes().unwrap()[0].code.len(), 6);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn recovery_unlocks_and_resets() {
        let path = temp_totp_path();
        let state = TotpState::default();
        let code = state
            .create(&path, b"ancien totp", true)
            .unwrap()
            .expect("code attendu");
        let id = state
            .add(&path, input("OVH", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"))
            .unwrap();
        state.lock();

        let messy = format!("  {}  ", code.to_lowercase().replace('-', " "));
        state.unlock_recovery(&path, &messy).unwrap();
        state.reset_master_password(&path, b"nouveau totp").unwrap();
        state.lock();

        assert!(matches!(
            state.unlock(&path, b"ancien totp").unwrap_err(),
            TotpError::WrongPassword
        ));
        state.unlock(&path, b"nouveau totp").unwrap();
        assert_eq!(state.list().unwrap()[0].id, id);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn recovery_unavailable_when_not_set_up() {
        let path = temp_totp_path();
        let state = TotpState::default();
        state.create(&path, b"pw", false).unwrap();
        assert!(!peek_has_recovery(&path));
        state.lock();
        assert!(matches!(
            state.unlock_recovery(&path, "AAAA-BBBB-CCCC-DDDD").unwrap_err(),
            TotpError::NoRecovery
        ));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn setup_and_remove_recovery() {
        let path = temp_totp_path();
        let state = TotpState::default();
        state.create(&path, b"pw", false).unwrap();
        assert!(!state.has_recovery());
        let code = state.setup_recovery(&path).unwrap();
        assert!(state.has_recovery());
        assert!(peek_has_recovery(&path));
        state.remove_recovery(&path).unwrap();
        assert!(!state.has_recovery());
        state.lock();
        assert!(matches!(
            state.unlock_recovery(&path, &code).unwrap_err(),
            TotpError::NoRecovery
        ));
        let _ = fs::remove_file(&path);
    }
}
