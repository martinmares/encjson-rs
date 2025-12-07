use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use mini_monocypher::{
    ErrorKind, crypto_aead_lock, crypto_aead_unlock, crypto_blake2b, crypto_x25519,
};
use rand::rand_core::TryRngCore;
use rand::rngs::OsRng;
use regex::Regex;
use thiserror::Error;

const API_VERSION: &str = "2.0";

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const MAC_LEN: usize = 16;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("hex decode error: {0}")]
    Hex(#[from] hex::FromHexError),

    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("AEAD decrypt error: {0:?}")]
    AeadDecrypt(ErrorKind),

    #[error("invalid data: {0}")]
    Invalid(String),

    #[error("utf8 error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
}

/// Symetrický box – drží derivovaný 32B klíč pro AEAD.
pub struct SecureBox {
    key: [u8; KEY_LEN],
}

impl SecureBox {
    /// Vytvoří SecureBox ze 64-hex private a public klíče.
    ///
    /// shared_key = Blake2b( X25519(priv, pub) )  (32B)
    pub fn new_from_hex(private_hex: &str, public_hex: &str) -> Result<Self, CryptoError> {
        let priv_vec = hex::decode(private_hex)?;
        let pub_vec = hex::decode(public_hex)?;

        if priv_vec.len() != KEY_LEN || pub_vec.len() != KEY_LEN {
            return Err(CryptoError::Invalid(
                "key length must be 32 bytes (64 hex chars)".into(),
            ));
        }

        let mut priv_arr = [0u8; KEY_LEN];
        let mut pub_arr = [0u8; KEY_LEN];
        priv_arr.copy_from_slice(&priv_vec);
        pub_arr.copy_from_slice(&pub_vec);

        // X25519
        let mut shared_secret = [0u8; KEY_LEN];
        crypto_x25519(&mut shared_secret, &priv_arr, &pub_arr);

        // Blake2b KDF -> 32B symetrický klíč
        let mut key = [0u8; KEY_LEN];
        crypto_blake2b(&mut key, &shared_secret);

        Ok(SecureBox { key })
    }

    /// Vrací true, pokud je string ve formátu EncJson[@api=...:@box=...]
    fn is_encrypted(val: &str) -> bool {
        lazy_static::lazy_static! {
            static ref ENCJSON_RE: Regex =
                Regex::new(r"(?i)^EncJson\[@api=(.*):@box=(.*)\]$").unwrap();
        }
        ENCJSON_RE.is_match(val)
    }

    /// Získá jen obsah @box=... nebo vrátí celý string, pokud pattern nesedí.
    fn extract_box(val: &str) -> &str {
        lazy_static::lazy_static! {
            static ref ENCJSON_RE: Regex =
                Regex::new(r"(?i)^EncJson\[@api=(.*):@box=(.*)\]$").unwrap();
        }
        ENCJSON_RE
            .captures(val)
            .and_then(|cap| cap.get(2))
            .map(|m| m.as_str())
            .unwrap_or(val)
    }

    /// Zašifruje hodnotu (string pro JSON). Pokud už je EncJson[…], nechá ji být.
    pub fn encrypt_value(&self, val: &str) -> Result<String, CryptoError> {
        if Self::is_encrypted(val) {
            // už zašifrované - chováme se stejně jako původní encjson
            return Ok(val.to_string());
        }

        let plaintext = val.as_bytes();

        // náhodný nonce 24 B
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.try_fill_bytes(&mut nonce).expect("OS RNG failed");

        // ciphertext a MAC
        let mut cipher = vec![0u8; plaintext.len()];
        let mut mac = [0u8; MAC_LEN];

        crypto_aead_lock(
            &mut cipher,
            &mut mac,
            &self.key,
            &nonce,
            None, // žádné AAD
            plaintext,
        );

        // nonce || cipher || mac
        let mut buf = Vec::with_capacity(NONCE_LEN + cipher.len() + MAC_LEN);
        buf.extend_from_slice(&nonce);
        buf.extend_from_slice(&cipher);
        buf.extend_from_slice(&mac);

        let b64 = B64.encode(&buf);

        Ok(format!("EncJson[@api={}:@box={}]", API_VERSION, b64))
    }

    /// Dešifruje hodnotu. Pokud není ve formátu EncJson[…], vrací původní string.
    pub fn decrypt_value(&self, val: &str) -> Result<String, CryptoError> {
        if !Self::is_encrypted(val) {
            return Ok(val.to_string());
        }

        let box_b64 = Self::extract_box(val);
        let bytes = B64.decode(box_b64)?;

        if bytes.len() < NONCE_LEN + MAC_LEN {
            return Err(CryptoError::Invalid(
                "ciphertext too short (nonce+cipher+mac)".into(),
            ));
        }

        let nonce_slice = &bytes[..NONCE_LEN];
        let cipher_slice = &bytes[NONCE_LEN..bytes.len() - MAC_LEN];
        let mac_slice = &bytes[bytes.len() - MAC_LEN..];

        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(nonce_slice);

        let mut mac = [0u8; MAC_LEN];
        mac.copy_from_slice(mac_slice);

        let mut plain = vec![0u8; cipher_slice.len()];

        crypto_aead_unlock(&mut plain, &mac, &self.key, &nonce, None, cipher_slice)
            .map_err(CryptoError::AeadDecrypt)?;

        let s = String::from_utf8(plain)?;
        Ok(s)
    }
}

/// Generuje náhodný pair (private, public) ve formě hex stringů.
pub fn generate_key_pair() -> (String, String) {
    let mut priv_bytes = [0u8; KEY_LEN];
    let mut pub_bytes = [0u8; KEY_LEN];

    OsRng
        .try_fill_bytes(&mut priv_bytes)
        .expect("OS RNG failed");
    OsRng.try_fill_bytes(&mut pub_bytes).expect("OS RNG failed");

    let priv_hex = hex::encode(priv_bytes);
    let pub_hex = hex::encode(pub_bytes);

    (priv_hex, pub_hex)
}

#[cfg(test)]
mod tests {
    use super::*;

    // tvoje ukázkové klíče z dotazu
    const PUBLIC_KEY: &str = "4c016009ce7246bebb08ec6856e76839a5c690cf01b30357914020aac9eebc8b";
    const PRIVATE_KEY: &str = "24e55b25c598d4df78387de983b455144e197e3e63239d0c1fc92f862bbd7c0c";

    #[test]
    fn roundtrip_encrypt_decrypt_with_example_keys() {
        let sb = SecureBox::new_from_hex(PRIVATE_KEY, PUBLIC_KEY).unwrap();
        let plain = "tajne-heslo-do-db";

        let enc = sb.encrypt_value(plain).unwrap();
        assert!(enc.starts_with("EncJson[@api=2.0:@box="));
        assert!(enc.ends_with(']'));

        let dec = sb.decrypt_value(&enc).unwrap();
        assert_eq!(dec, plain);
    }

    #[test]
    fn already_encrypted_is_left_untouched() {
        let sb = SecureBox::new_from_hex(PRIVATE_KEY, PUBLIC_KEY).unwrap();
        let already = "EncJson[@api=2.0:@box=abc]";
        let enc = sb.encrypt_value(already).unwrap();
        assert_eq!(enc, already);
    }

    #[test]
    fn plain_string_is_passthrough_on_decrypt() {
        let sb = SecureBox::new_from_hex(PRIVATE_KEY, PUBLIC_KEY).unwrap();
        let plain = "hello";
        let dec = sb.decrypt_value(plain).unwrap();
        assert_eq!(dec, plain);
    }
}
