use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use blake2::{Blake2b512, Digest};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use lazy_static::lazy_static;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use rand::Rng;
use rand_core::OsRng;
use regex::Regex;
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::recipient::{
    KeyComponentPrivate, KeyComponentPublic, LocalKeyFileV3, LocalMlKem768Keypair,
    LocalX25519Keypair, PrivateBundle, PublicBundle, RecipientKeyV3, V3Envelope, compute_key_id,
};

const API_VERSION: &str = "2.0";
const API_VERSION_V3: &str = "3.0";

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

/// Hybrid v3 box derived from X25519 + ML-KEM-768 using HKDF-SHA256.
pub struct HybridSecureBox {
    bundle: LocalKeyFileV3,
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
            // already encrypted - behave like the original tool
            return Ok(val.to_string());
        }

        let plaintext = val.as_bytes();

        // random 24-byte nonce
        let mut nonce_bytes = [0u8; NONCE_LEN];
        let mut rng = rand::rng();
        rng.fill_bytes(&mut nonce_bytes);

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

impl HybridSecureBox {
    pub fn from_bundle(bundle: LocalKeyFileV3) -> Self {
        Self { bundle }
    }

    pub fn recipient_key(&self) -> RecipientKeyV3 {
        self.bundle.to_recipient_key()
    }

    pub fn encrypt_value(&self, val: &str) -> Result<String, CryptoError> {
        if SecureBox::is_encrypted(val) {
            return Ok(val.to_string());
        }

        let plaintext = val.as_bytes();
        let recipient = self.recipient_key();

        let recipient_x25519_bytes = decode_fixed_hex_32(&recipient.x25519_public_hex)?;
        let recipient_x25519_public = PublicKey::from(recipient_x25519_bytes);

        let recipient_mlkem_public_bytes = B64.decode(recipient.mlkem768_public_b64)?;
        let recipient_mlkem_public_encoded =
            ml_kem::Encoded::<<MlKem768 as KemCore>::EncapsulationKey>::try_from(
                recipient_mlkem_public_bytes.as_slice(),
            )
            .map_err(|_| CryptoError::Invalid("invalid ML-KEM public key length".into()))?;
        let recipient_mlkem_public =
            <MlKem768 as KemCore>::EncapsulationKey::from_bytes(&recipient_mlkem_public_encoded);

        let mut rng = OsRng;

        let mut eph_secret_bytes = [0u8; KEY_LEN];
        use rand_core::RngCore;
        rng.fill_bytes(&mut eph_secret_bytes);
        let eph_secret = StaticSecret::from(eph_secret_bytes);
        let eph_public = PublicKey::from(&eph_secret);
        let x25519_shared = eph_secret.diffie_hellman(&recipient_x25519_public);

        let (kem_ciphertext, kem_shared) = recipient_mlkem_public
            .encapsulate(&mut rng)
            .map_err(|_| CryptoError::Invalid("ML-KEM encapsulation failed".into()))?;

        let key = derive_v3_key(
            x25519_shared.as_bytes(),
            kem_shared.as_ref(),
            recipient.key_id.as_bytes(),
        )?;

        let mut nonce_bytes = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut nonce_bytes);
        let cipher = XChaCha20Poly1305::new_from_slice(&key)
            .map_err(|_| CryptoError::Invalid("invalid derived key length".into()))?;
        let nonce = XNonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| CryptoError::Invalid("encryption failed".into()))?;

        let kem_ct_bytes: &[u8] = kem_ciphertext.as_ref();
        let envelope = V3Envelope {
            version: 3,
            kex: "mlkem768+x25519".to_string(),
            kdf: "hkdf-sha256".to_string(),
            aead: "xchacha20poly1305".to_string(),
            epk_x25519_b64: B64.encode(eph_public.as_bytes()),
            kem_ct_b64: B64.encode(kem_ct_bytes),
            nonce_b64: B64.encode(nonce_bytes),
            ciphertext_b64: B64.encode(ciphertext),
        };

        let payload = serde_json::to_vec(&envelope)
            .map_err(|e| CryptoError::Invalid(format!("failed to encode v3 envelope: {e}")))?;
        Ok(format!(
            "EncJson[@api={}:@box={}]",
            API_VERSION_V3,
            B64.encode(payload)
        ))
    }

    pub fn decrypt_value(&self, val: &str) -> Result<String, CryptoError> {
        if !SecureBox::is_encrypted(val) {
            return Ok(val.to_string());
        }
        let box_b64 = SecureBox::extract_box(val);
        let payload = B64.decode(box_b64)?;
        let envelope: V3Envelope = serde_json::from_slice(&payload)
            .map_err(|e| CryptoError::Invalid(format!("invalid v3 envelope JSON: {e}")))?;

        if envelope.version != 3 {
            return Err(CryptoError::Invalid(
                "unsupported v3 envelope version".to_string(),
            ));
        }
        if envelope.kex != "mlkem768+x25519" {
            return Err(CryptoError::Invalid("unsupported v3 kex".to_string()));
        }
        if envelope.kdf != "hkdf-sha256" {
            return Err(CryptoError::Invalid("unsupported v3 kdf".to_string()));
        }
        if envelope.aead != "xchacha20poly1305" {
            return Err(CryptoError::Invalid("unsupported v3 aead".to_string()));
        }

        let eph_public_bytes = B64.decode(envelope.epk_x25519_b64)?;
        let eph_public = PublicKey::from(
            <[u8; KEY_LEN]>::try_from(eph_public_bytes.as_slice())
                .map_err(|_| CryptoError::Invalid("invalid ephemeral x25519 public key".into()))?,
        );

        let private_x25519_bytes = decode_fixed_hex_32(&self.bundle.x25519.private_hex)?;
        let private_x25519 = StaticSecret::from(private_x25519_bytes);
        let x25519_shared = private_x25519.diffie_hellman(&eph_public);

        let kem_ct_bytes = B64.decode(envelope.kem_ct_b64)?;
        let kem_ciphertext = ml_kem::Ciphertext::<MlKem768>::try_from(kem_ct_bytes.as_slice())
            .map_err(|_| CryptoError::Invalid("invalid ML-KEM ciphertext length".into()))?;

        let decapsulation_key_bytes = B64.decode(&self.bundle.mlkem768.private_b64)?;
        let decapsulation_key_encoded =
            ml_kem::Encoded::<<MlKem768 as KemCore>::DecapsulationKey>::try_from(
                decapsulation_key_bytes.as_slice(),
            )
            .map_err(|_| CryptoError::Invalid("invalid ML-KEM private key length".into()))?;
        let decapsulation_key =
            <MlKem768 as KemCore>::DecapsulationKey::from_bytes(&decapsulation_key_encoded);

        let kem_shared = decapsulation_key
            .decapsulate(&kem_ciphertext)
            .map_err(|_| CryptoError::Invalid("ML-KEM decapsulation failed".into()))?;

        let key = derive_v3_key(
            x25519_shared.as_bytes(),
            kem_shared.as_ref(),
            self.bundle.key_id.as_bytes(),
        )?;

        let nonce_bytes = B64.decode(envelope.nonce_b64)?;
        let nonce_bytes: &[u8; 24] = nonce_bytes
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::Invalid("invalid v3 nonce length".into()))?;
        let nonce = XNonce::from_slice(nonce_bytes);
        let ciphertext = B64.decode(envelope.ciphertext_b64)?;

        let cipher = XChaCha20Poly1305::new_from_slice(&key)
            .map_err(|_| CryptoError::Invalid("invalid derived key length".into()))?;
        let plain_bytes = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|_| CryptoError::AeadDecrypt)?;
        Ok(String::from_utf8(plain_bytes)?)
    }
}

/// Generate a legacy random (private, public) pair as 64-hex strings.
///
/// This keeps backward compatibility with old behavior where both values were
/// generated independently and may not be curve-consistent.
pub fn generate_key_pair() -> (String, String) {
    let mut priv_bytes = [0u8; KEY_LEN];
    let mut pub_bytes = [0u8; KEY_LEN];

    let mut rng = rand::rng();
    rng.fill_bytes(&mut priv_bytes);
    rng.fill_bytes(&mut pub_bytes);

    let priv_hex = hex::encode(priv_bytes);
    let pub_hex = hex::encode(pub_bytes);

    (priv_hex, pub_hex)
}

/// Generate a curve-consistent (private, public) X25519 pair as 64-hex strings.
pub fn generate_pair_consistent_key_pair() -> (String, String) {
    let mut priv_bytes = [0u8; KEY_LEN];
    let mut rng = rand::rng();
    rng.fill_bytes(&mut priv_bytes);

    let secret = StaticSecret::from(priv_bytes);
    let public = PublicKey::from(&secret);

    let priv_hex = hex::encode(priv_bytes);
    let pub_hex = hex::encode(public.as_bytes());
    (priv_hex, pub_hex)
}

pub fn generate_v3_key_bundle() -> Result<LocalKeyFileV3, CryptoError> {
    let mut rng = OsRng;

    let mut x25519_private_bytes = [0u8; KEY_LEN];
    use rand_core::RngCore;
    rng.fill_bytes(&mut x25519_private_bytes);
    let x25519_secret = StaticSecret::from(x25519_private_bytes);
    let x25519_public = PublicKey::from(&x25519_secret);

    let (mlkem_private, mlkem_public) = MlKem768::generate(&mut rng);

    let mut public_bundle = PublicBundle {
        version: 3,
        key_id: String::new(),
        algorithm: "ml-kem-768+x25519".to_string(),
        components: vec![
            KeyComponentPublic {
                role: "kex".to_string(),
                algorithm: "x25519".to_string(),
                encoding: "hex".to_string(),
                public: hex::encode(x25519_public.as_bytes()),
            },
            KeyComponentPublic {
                role: "kex".to_string(),
                algorithm: "ml-kem-768".to_string(),
                encoding: "base64".to_string(),
                public: B64.encode(mlkem_public.as_bytes().as_slice()),
            },
        ],
    };
    let key_id =
        compute_key_id(&public_bundle).map_err(|e| CryptoError::Invalid(e.to_string()))?;
    public_bundle.key_id = key_id.clone();

    let _private_bundle = PrivateBundle {
        version: 3,
        key_id: key_id.clone(),
        algorithm: "ml-kem-768+x25519".to_string(),
        components: vec![
            KeyComponentPrivate {
                role: "kex".to_string(),
                algorithm: "x25519".to_string(),
                encoding: "hex".to_string(),
                private: hex::encode(x25519_private_bytes),
            },
            KeyComponentPrivate {
                role: "kex".to_string(),
                algorithm: "ml-kem-768".to_string(),
                encoding: "base64".to_string(),
                private: B64.encode(mlkem_private.as_bytes().as_slice()),
            },
        ],
    };

    Ok(LocalKeyFileV3 {
        version: 3,
        key_id,
        algorithm: "ml-kem-768+x25519".to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        x25519: LocalX25519Keypair {
            public_hex: public_bundle.components[0].public.clone(),
            private_hex: hex::encode(x25519_private_bytes),
        },
        mlkem768: LocalMlKem768Keypair {
            public_b64: public_bundle.components[1].public.clone(),
            private_b64: B64.encode(mlkem_private.as_bytes().as_slice()),
        },
    })
}

fn derive_v3_key(
    x25519_shared: &[u8],
    kem_shared: &[u8],
    key_context: &[u8],
) -> Result<[u8; KEY_LEN], CryptoError> {
    let mut ikm = Vec::with_capacity(x25519_shared.len() + kem_shared.len());
    ikm.extend_from_slice(x25519_shared);
    ikm.extend_from_slice(kem_shared);

    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut key = [0u8; KEY_LEN];
    hk.expand(key_context, &mut key)
        .map_err(|_| CryptoError::Invalid("HKDF expansion failed".into()))?;
    Ok(key)
}

fn decode_fixed_hex_32(value: &str) -> Result<[u8; KEY_LEN], CryptoError> {
    let vec = hex::decode(value)?;
    if vec.len() != KEY_LEN {
        return Err(CryptoError::Invalid(
            "expected 32-byte hex value".to_string(),
        ));
    }
    let mut out = [0u8; KEY_LEN];
    out.copy_from_slice(&vec);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_sources::derive_public_hex_from_private;
    use base64::engine::general_purpose::STANDARD as B64_STD;
    use serde_json::Value;

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

    #[test]
    fn generate_pair_consistent_key_pair_is_consistent() {
        let (private_hex, public_hex) = generate_pair_consistent_key_pair();
        let derived = derive_public_hex_from_private(&private_hex).unwrap();
        assert_eq!(derived, public_hex);
    }

    #[test]
    fn generate_v3_key_bundle_has_stable_shape() {
        let bundle = generate_v3_key_bundle().unwrap();
        assert_eq!(bundle.version, 3);
        assert_eq!(bundle.algorithm, "ml-kem-768+x25519");
        assert_eq!(bundle.key_id.len(), 64);
        assert_eq!(bundle.x25519.public_hex.len(), 64);
        assert_eq!(bundle.x25519.private_hex.len(), 64);
        assert!(!bundle.mlkem768.public_b64.is_empty());
        assert!(!bundle.mlkem768.private_b64.is_empty());
    }

    #[test]
    fn v3_roundtrip_encrypt_decrypt() {
        let bundle = generate_v3_key_bundle().unwrap();
        let hybrid = HybridSecureBox::from_bundle(bundle);
        let plain = "tajne-heslo-do-db";

        let enc = hybrid.encrypt_value(plain).unwrap();
        assert!(enc.starts_with("EncJson[@api=3.0:@box="));
        let dec = hybrid.decrypt_value(&enc).unwrap();
        assert_eq!(dec, plain);
    }

    #[test]
    fn v3_decrypt_with_wrong_bundle_fails() {
        let sender_bundle = generate_v3_key_bundle().unwrap();
        let other_bundle = generate_v3_key_bundle().unwrap();
        let sender = HybridSecureBox::from_bundle(sender_bundle);
        let other = HybridSecureBox::from_bundle(other_bundle);

        let enc = sender.encrypt_value("tajne").unwrap();
        let err = other.decrypt_value(&enc).unwrap_err().to_string();
        assert!(
            err.contains("decryption failed")
                || err.contains("decapsulation")
                || err.contains("ciphertext")
        );
    }

    #[test]
    fn v3_decrypt_rejects_tampered_envelope() {
        let bundle = generate_v3_key_bundle().unwrap();
        let hybrid = HybridSecureBox::from_bundle(bundle);
        let enc = hybrid.encrypt_value("tajne").unwrap();

        let box_b64 = SecureBox::extract_box(&enc);
        let bytes = B64_STD.decode(box_b64).unwrap();
        let mut envelope: Value = serde_json::from_slice(&bytes).unwrap();
        envelope["kdf"] = Value::String("wrong-kdf".to_string());
        let tampered = format!(
            "EncJson[@api=3.0:@box={}]",
            B64_STD.encode(serde_json::to_vec(&envelope).unwrap())
        );

        let err = hybrid.decrypt_value(&tampered).unwrap_err().to_string();
        assert!(err.contains("unsupported v3 kdf"));
    }
}
