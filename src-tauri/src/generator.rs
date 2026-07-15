use serde::Deserialize;

#[derive(Deserialize)]
pub struct PasswordOptions {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
}

#[derive(Debug, PartialEq)]
pub enum GeneratorError {
    EmptyCharset,
    InvalidLength,
    Random,
}

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.?";

const WORDLIST_EN: &str = include_str!("wordlist_en.txt");

#[derive(Deserialize)]
pub struct PassphraseOptions {
    pub words: usize,
    pub separator: String,
    pub capitalize: bool,
    pub number: bool,
}

pub fn generate_passphrase(options: &PassphraseOptions) -> Result<String, GeneratorError> {
    if options.words == 0 || options.words > 32 {
        return Err(GeneratorError::InvalidLength);
    }
    let words: Vec<&str> = WORDLIST_EN.lines().filter(|l| !l.is_empty()).collect();
    if words.is_empty() {
        return Err(GeneratorError::EmptyCharset);
    }
    let mut parts: Vec<String> = Vec::with_capacity(options.words);
    for _ in 0..options.words {
        let word = words[uniform_index_large(words.len())?];
        if options.capitalize {
            let mut chars = word.chars();
            let capped = match chars.next() {
                Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
                None => String::new(),
            };
            parts.push(capped);
        } else {
            parts.push(word.to_string());
        }
    }
    let mut out = parts.join(&options.separator);
    if options.number {
        let digit = uniform_index_large(10)?;
        out.push_str(&options.separator);
        out.push_str(&digit.to_string());
    }
    Ok(out)
}

fn uniform_index_large(n: usize) -> Result<usize, GeneratorError> {
    let limit = 65536 - (65536 % n);
    loop {
        let mut bytes = [0u8; 2];
        getrandom::getrandom(&mut bytes).map_err(|_| GeneratorError::Random)?;
        let value = u16::from_le_bytes(bytes) as usize;
        if value < limit {
            return Ok(value % n);
        }
    }
}

pub fn generate(options: &PasswordOptions) -> Result<String, GeneratorError> {
    if options.length == 0 || options.length > 256 {
        return Err(GeneratorError::InvalidLength);
    }

    let mut charset: Vec<u8> = Vec::new();
    if options.lowercase {
        charset.extend_from_slice(LOWER);
    }
    if options.uppercase {
        charset.extend_from_slice(UPPER);
    }
    if options.digits {
        charset.extend_from_slice(DIGITS);
    }
    if options.symbols {
        charset.extend_from_slice(SYMBOLS);
    }
    if charset.is_empty() {
        return Err(GeneratorError::EmptyCharset);
    }

    let mut out = String::with_capacity(options.length);
    for _ in 0..options.length {
        let index = uniform_index(charset.len())?;
        out.push(charset[index] as char);
    }
    Ok(out)
}

fn uniform_index(n: usize) -> Result<usize, GeneratorError> {
    let limit = 256 - (256 % n);
    loop {
        let mut byte = [0u8; 1];
        getrandom::getrandom(&mut byte).map_err(|_| GeneratorError::Random)?;
        let value = byte[0] as usize;
        if value < limit {
            return Ok(value % n);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(length: usize, lo: bool, up: bool, di: bool, sy: bool) -> PasswordOptions {
        PasswordOptions {
            length,
            lowercase: lo,
            uppercase: up,
            digits: di,
            symbols: sy,
        }
    }

    #[test]
    fn length_respected() {
        let pw = generate(&opts(20, true, true, true, true)).unwrap();
        assert_eq!(pw.chars().count(), 20);
    }

    #[test]
    fn empty_charset_fails() {
        assert_eq!(
            generate(&opts(10, false, false, false, false)).unwrap_err(),
            GeneratorError::EmptyCharset
        );
    }

    #[test]
    fn invalid_length_fails() {
        assert_eq!(
            generate(&opts(0, true, false, false, false)).unwrap_err(),
            GeneratorError::InvalidLength
        );
    }

    #[test]
    fn only_digits() {
        let pw = generate(&opts(80, false, false, true, false)).unwrap();
        assert!(pw.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn only_lowercase() {
        let pw = generate(&opts(80, true, false, false, false)).unwrap();
        assert!(pw.chars().all(|c| c.is_ascii_lowercase()));
    }

    fn phrase(words: usize, sep: &str, cap: bool, num: bool) -> PassphraseOptions {
        PassphraseOptions {
            words,
            separator: sep.to_string(),
            capitalize: cap,
            number: num,
        }
    }

    #[test]
    fn passphrase_word_count() {
        let p = generate_passphrase(&phrase(5, "-", false, false)).unwrap();
        assert_eq!(p.split('-').count(), 5);
    }

    #[test]
    fn passphrase_number_appended() {
        let p = generate_passphrase(&phrase(4, "-", false, true)).unwrap();
        let parts: Vec<&str> = p.split('-').collect();
        assert_eq!(parts.len(), 5);
        assert!(parts[4].chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn passphrase_capitalize() {
        let p = generate_passphrase(&phrase(6, " ", true, false)).unwrap();
        assert!(p.split(' ').all(|w| w.chars().next().unwrap().is_ascii_uppercase()));
    }

    #[test]
    fn passphrase_zero_words_fails() {
        assert_eq!(
            generate_passphrase(&phrase(0, "-", false, false)).unwrap_err(),
            GeneratorError::InvalidLength
        );
    }

    #[test]
    fn passphrase_words_from_list() {
        let p = generate_passphrase(&phrase(8, "-", false, false)).unwrap();
        assert!(p.split('-').all(|w| w.chars().all(|c| c.is_ascii_lowercase())));
    }
}
