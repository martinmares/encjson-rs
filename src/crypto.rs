use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use blake2::{Blake2b512, Digest};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use lazy_static::lazy_static;
use rand::rand_core::TryRngCore;
use rand::rngs::OsRng;
use regex::Regex;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

const API_VERSION: &str = "2.0";

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const MAC_LEN: usize = 16; // Poly1305 tag length

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid hex-encoded key: {0}")]
    Hex(#[from] hex::FromHexError),

    #[error("invalid EncJson payload (base64 decode failed): {0}")]
    Base64(#[from] base64::DecodeError),

    #[error(
        "decryption failed: ciphertext may be corrupted, use a wrong key, or come from an incompatible encjson version"
    )]
    AeadDecrypt,

    #[error("invalid data: {0}")]
    Invalid(String),

    #[error("invalid UTF-8 in decrypted value: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
}

/// Symmetric "box" derived from a static X25519 keypair.
pub struct SecureBox {
    key: [u8; KEY_LEN],
}

impl SecureBox {
    /// Create SecureBox from 64-hex private and public keys.
    ///
    /// Derives a 32-byte symmetric key as:
    ///   shared = X25519(private, public)
    ///   key    = Blake2b(shared)[0..32]
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

        let secret = StaticSecret::from(priv_arr);
        let public = PublicKey::from(pub_arr);

        let shared = secret.diffie_hellman(&public);
        let shared_bytes = shared.as_bytes();

        // Blake2b KDF -> 32B symmetric key
        let digest = Blake2b512::digest(shared_bytes);
        let mut key = [0u8; KEY_LEN];
        key.copy_from_slice(&digest[..KEY_LEN]);

        Ok(SecureBox { key })
    }

    /// Returns true if the string is in EncJson[@api=...:@box=...] format.
    fn is_encrypted(val: &str) -> bool {
        lazy_static! {
            static ref ENCJSON_RE: Regex =
                Regex::new(r"(?i)^EncJson\[@api=(.*):@box=(.*)\]$").unwrap();
        }
        ENCJSON_RE.is_match(val)
    }

    /// Extracts only the @box=... payload, or returns the whole string if pattern does not match.
    fn extract_box(val: &str) -> &str {
        lazy_static! {
            static ref ENCJSON_RE: Regex =
                Regex::new(r"(?i)^EncJson\[@api=(.*):@box=(.*)\]$").unwrap();
        }
        ENCJSON_RE
            .captures(val)
            .and_then(|cap| cap.get(2))
            .map(|m| m.as_str())
            .unwrap_or(val)
    }

    /// Encrypts a string value for JSON.
    ///
    /// If the value is already in EncJson[...] format, it is returned unchanged.
    pub fn encrypt_value(&self, val: &str) -> Result<String, CryptoError> {
        if Self::is_encrypted(val) {
            // already encrypted – behave like the original tool
            return Ok(val.to_string());
        }

        let plaintext = val.as_bytes();

        // random 24-byte nonce
        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng
            .try_fill_bytes(&mut nonce_bytes)
            .expect("OS RNG failed");

        let cipher = XChaCha20Poly1305::new_from_slice(&self.key)
            .map_err(|_| CryptoError::Invalid("invalid key length".into()))?;
        let nonce = XNonce::from_slice(&nonce_bytes);

        // ciphertext || tag (Poly1305, 16 bytes)
        let mut ct_and_tag = cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| CryptoError::Invalid("encryption failed".into()))?;

        if ct_and_tag.len() < MAC_LEN {
            return Err(CryptoError::Invalid(
                "ciphertext too short (missing tag)".into(),
            ));
        }

        // Split into ciphertext and tag to keep the layout: nonce || ciphertext || mac
        let tag = ct_and_tag.split_off(ct_and_tag.len() - MAC_LEN);
        let ct = ct_and_tag;

        let mut buf = Vec::with_capacity(NONCE_LEN + ct.len() + MAC_LEN);
        buf.extend_from_slice(&nonce_bytes);
        buf.extend_from_slice(&ct);
        buf.extend_from_slice(&tag);

        let b64 = B64.encode(&buf);

        Ok(format!("EncJson[@api={}:@box={}]", API_VERSION, b64))
    }

    /// Decrypts a value. If it is not in EncJson[...] format, returns the original string.
    pub fn decrypt_value(&self, val: &str) -> Result<String, CryptoError> {
        if !Self::is_encrypted(val) {
            return Ok(val.to_string());
        }

        let box_b64 = Self::extract_box(val);
        let bytes = B64.decode(box_b64)?;

        if bytes.len() < NONCE_LEN + MAC_LEN {
            return Err(CryptoError::Invalid(
                "ciphertext too short (nonce+cipher+tag)".into(),
            ));
        }

        let nonce_slice = &bytes[..NONCE_LEN];
        let cipher_slice = &bytes[NONCE_LEN..bytes.len() - MAC_LEN];
        let tag_slice = &bytes[bytes.len() - MAC_LEN..];

        let mut ct_and_tag = Vec::with_capacity(cipher_slice.len() + MAC_LEN);
        ct_and_tag.extend_from_slice(cipher_slice);
        ct_and_tag.extend_from_slice(tag_slice);

        let cipher = XChaCha20Poly1305::new_from_slice(&self.key)
            .map_err(|_| CryptoError::Invalid("invalid key length".into()))?;
        let nonce = XNonce::from_slice(nonce_slice);

        let plain_bytes = cipher
            .decrypt(nonce, ct_and_tag.as_ref())
            .map_err(|_| CryptoError::AeadDecrypt)?;

        let s = String::from_utf8(plain_bytes)?;
        Ok(s)
    }
}

/// Generate a random (private, public) pair as 64-hex strings.
///
/// NOTE: This does *not* derive the public key from the private key on the
/// X25519 curve. It generates two independent random 32-byte values, to stay
/// compatible with the original `encjson` design.
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

    // example keys from the original discussion
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
