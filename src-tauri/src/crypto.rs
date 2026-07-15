use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

pub const KDF_MEM_KIB: u32 = 65536;
pub const KDF_ITERATIONS: u32 = 3;
pub const KDF_PARALLELISM: u32 = 1;

pub const KEY_LEN: usize = 32;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;

#[derive(Debug, PartialEq)]
pub enum CryptoError {
    Kdf,
    Encrypt,
    Decrypt,
    Random,
}

fn generate_bytes<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut buf = [0u8; N];
    getrandom::getrandom(&mut buf).map_err(|_| CryptoError::Random)?;
    Ok(buf)
}

pub fn generate_salt() -> Result<[u8; SALT_LEN], CryptoError> {
    generate_bytes()
}

pub fn generate_id_bytes() -> Result<[u8; 12], CryptoError> {
    generate_bytes()
}

pub fn generate_key_bytes() -> Result<Zeroizing<[u8; KEY_LEN]>, CryptoError> {
    Ok(Zeroizing::new(generate_bytes::<KEY_LEN>()?))
}

pub fn generate_recovery_bytes() -> Result<[u8; 20], CryptoError> {
    generate_bytes()
}

pub fn level_params(level: &str) -> (u32, u32, u32) {
    match level {
        "fort" => (262144, 4, 1),
        "parano" => (524288, 5, 1),
        _ => (KDF_MEM_KIB, KDF_ITERATIONS, KDF_PARALLELISM),
    }
}

pub fn derive_key(
    password: &[u8],
    salt: &[u8],
    mem_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<Zeroizing<[u8; KEY_LEN]>, CryptoError> {
    if mem_kib > 524288 || iterations > 10 || parallelism > 4 {
        return Err(CryptoError::Kdf);
    }
    let params =
        Params::new(mem_kib, iterations, parallelism, Some(KEY_LEN)).map_err(|_| CryptoError::Kdf)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(password, salt, key.as_mut_slice())
        .map_err(|_| CryptoError::Kdf)?;
    Ok(key)
}

pub fn encrypt(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let nonce = generate_bytes::<NONCE_LEN>()?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .map_err(|_| CryptoError::Encrypt)?;
    Ok((nonce.to_vec(), ciphertext))
}

pub fn decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if nonce.len() != NONCE_LEN {
        return Err(CryptoError::Decrypt);
    }
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let plaintext = cipher
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .map_err(|_| CryptoError::Decrypt)?;
    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_from(pw: &[u8]) -> Zeroizing<[u8; KEY_LEN]> {
        derive_key(pw, b"0123456789abcdef", KDF_MEM_KIB, KDF_ITERATIONS, KDF_PARALLELISM).unwrap()
    }

    #[test]
    fn roundtrip() {
        let key = key_from(b"correct horse battery");
        let (nonce, ct) = encrypt(&key, b"donnees secretes").unwrap();
        let pt = decrypt(&key, &nonce, &ct).unwrap();
        assert_eq!(pt.as_slice(), b"donnees secretes");
    }

    #[test]
    fn wrong_password_fails() {
        let (nonce, ct) = encrypt(&key_from(b"bon mot de passe"), b"x").unwrap();
        let res = decrypt(&key_from(b"mauvais mot de passe"), &nonce, &ct);
        assert_eq!(res.unwrap_err(), CryptoError::Decrypt);
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = key_from(b"bon mot de passe");
        let (nonce, mut ct) = encrypt(&key, b"x").unwrap();
        ct[0] ^= 0xff;
        assert_eq!(decrypt(&key, &nonce, &ct).unwrap_err(), CryptoError::Decrypt);
    }
}
