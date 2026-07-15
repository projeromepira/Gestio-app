use crate::crypto;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use zeroize::Zeroizing;

pub type Wrap = (Vec<u8>, Vec<u8>, Vec<u8>);

pub enum UnwrapError {
    Wrong,
    Crypto,
    Corrupt,
}

pub fn recovery_params() -> (u32, u32, u32) {
    (
        crypto::KDF_MEM_KIB,
        crypto::KDF_ITERATIONS,
        crypto::KDF_PARALLELISM,
    )
}

pub fn wrap_key(
    secret: &[u8],
    mem_kib: u32,
    iterations: u32,
    parallelism: u32,
    data_key: &[u8; crypto::KEY_LEN],
) -> Result<Wrap, ()> {
    let salt = crypto::generate_salt().map_err(|_| ())?;
    let derived =
        crypto::derive_key(secret, &salt, mem_kib, iterations, parallelism).map_err(|_| ())?;
    let (nonce, wrap) = crypto::encrypt(&derived, data_key).map_err(|_| ())?;
    Ok((salt.to_vec(), nonce, wrap))
}

pub fn unwrap_key(
    secret: &[u8],
    mem_kib: u32,
    iterations: u32,
    parallelism: u32,
    wrap: &Wrap,
) -> Result<Zeroizing<[u8; crypto::KEY_LEN]>, UnwrapError> {
    let derived = crypto::derive_key(secret, &wrap.0, mem_kib, iterations, parallelism)
        .map_err(|_| UnwrapError::Crypto)?;
    let plain = crypto::decrypt(&derived, &wrap.1, &wrap.2).map_err(|_| UnwrapError::Wrong)?;
    if plain.len() != crypto::KEY_LEN {
        return Err(UnwrapError::Corrupt);
    }
    let mut out = Zeroizing::new([0u8; crypto::KEY_LEN]);
    out.copy_from_slice(&plain);
    Ok(out)
}

pub fn decode_wrap(salt: &str, nonce: &str, ct: &str) -> Result<Wrap, ()> {
    Ok((
        STANDARD.decode(salt).map_err(|_| ())?,
        STANDARD.decode(nonce).map_err(|_| ())?,
        STANDARD.decode(ct).map_err(|_| ())?,
    ))
}

pub fn encode_wrap(wrap: &Wrap) -> (String, String, String) {
    (
        STANDARD.encode(&wrap.0),
        STANDARD.encode(&wrap.1),
        STANDARD.encode(&wrap.2),
    )
}

fn base32_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let mut bits: u32 = 0;
    let mut nbits: u32 = 0;
    for &b in data {
        bits = (bits << 8) | b as u32;
        nbits += 8;
        while nbits >= 5 {
            nbits -= 5;
            out.push(ALPHABET[((bits >> nbits) & 31) as usize] as char);
        }
    }
    if nbits > 0 {
        out.push(ALPHABET[((bits << (5 - nbits)) & 31) as usize] as char);
    }
    out
}

pub fn generate_recovery_code() -> Result<String, ()> {
    let bytes = crypto::generate_recovery_bytes().map_err(|_| ())?;
    let raw = base32_encode(&bytes);
    let mut out = String::new();
    for (i, c) in raw.chars().enumerate() {
        if i > 0 && i % 4 == 0 {
            out.push('-');
        }
        out.push(c);
    }
    Ok(out)
}

pub fn normalize_recovery(input: &str) -> String {
    input
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_uppercase()
}
