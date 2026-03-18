use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::error::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipientKeyV3 {
    pub version: u32,
    pub key_id: String,
    pub algorithm: String,
    pub x25519_public_hex: String,
    pub mlkem768_public_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyComponentPublic {
    pub role: String,
    pub algorithm: String,
    pub encoding: String,
    pub public: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyComponentPrivate {
    pub role: String,
    pub algorithm: String,
    pub encoding: String,
    pub private: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicBundle {
    pub version: u32,
    pub key_id: String,
    pub algorithm: String,
    pub components: Vec<KeyComponentPublic>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateBundle {
    pub version: u32,
    pub key_id: String,
    pub algorithm: String,
    pub components: Vec<KeyComponentPrivate>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalKeyFileV3 {
    pub version: u32,
    pub key_id: String,
    pub algorithm: String,
    pub created_at: String,
    pub x25519: LocalX25519Keypair,
    pub mlkem768: LocalMlKem768Keypair,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalX25519Keypair {
    pub public_hex: String,
    pub private_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalMlKem768Keypair {
    pub public_b64: String,
    pub private_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct V3Envelope {
    pub version: u32,
    pub kex: String,
    pub kdf: String,
    pub aead: String,
    pub epk_x25519_b64: String,
    pub kem_ct_b64: String,
    pub nonce_b64: String,
    pub ciphertext_b64: String,
}

impl RecipientKeyV3 {
    pub fn to_public_bundle(&self) -> PublicBundle {
        PublicBundle {
            version: self.version,
            key_id: self.key_id.clone(),
            algorithm: self.algorithm.clone(),
            components: vec![
                KeyComponentPublic {
                    role: "kex".to_string(),
                    algorithm: "x25519".to_string(),
                    encoding: "hex".to_string(),
                    public: self.x25519_public_hex.clone(),
                },
                KeyComponentPublic {
                    role: "kex".to_string(),
                    algorithm: "ml-kem-768".to_string(),
                    encoding: "base64".to_string(),
                    public: self.mlkem768_public_b64.clone(),
                },
            ],
        }
    }
}

impl LocalKeyFileV3 {
    pub fn to_recipient_key(&self) -> RecipientKeyV3 {
        RecipientKeyV3 {
            version: self.version,
            key_id: self.key_id.clone(),
            algorithm: self.algorithm.clone(),
            x25519_public_hex: self.x25519.public_hex.clone(),
            mlkem768_public_b64: self.mlkem768.public_b64.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecipientMetadata {
    LegacyPublicKey(String),
    RecipientKeyV3(RecipientKeyV3),
}

impl RecipientMetadata {
    pub fn parse(root: &Value) -> Result<Self, Error> {
        let has_public_key = root.get("_public_key").is_some();
        let has_recipient_key = root.get("_recipient_key").is_some();

        if has_public_key && has_recipient_key {
            return Err(Error::InvalidRecipientMetadata(
                "JSON must not contain both `_public_key` and `_recipient_key`".to_string(),
            ));
        }

        if let Some(pk) = root.get("_public_key").and_then(Value::as_str) {
            if pk.len() != 64 || !pk.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(Error::InvalidPublicKey);
            }
            return Ok(Self::LegacyPublicKey(pk.to_string()));
        }

        if let Some(recipient) = root.get("_recipient_key") {
            let parsed: RecipientKeyV3 = serde_json::from_value(recipient.clone()).map_err(|e| {
                Error::InvalidRecipientMetadata(format!(
                    "invalid `_recipient_key` structure: {e}"
                ))
            })?;

            if parsed.version != 3 {
                return Err(Error::InvalidRecipientMetadata(
                    "`_recipient_key.version` must be 3".to_string(),
                ));
            }
            if parsed.key_id.trim().is_empty() {
                return Err(Error::InvalidRecipientMetadata(
                    "`_recipient_key.key_id` must not be empty".to_string(),
                ));
            }
            if parsed.algorithm.trim().is_empty() {
                return Err(Error::InvalidRecipientMetadata(
                    "`_recipient_key.algorithm` must not be empty".to_string(),
                ));
            }
            if parsed.x25519_public_hex.len() != 64
                || !parsed
                    .x25519_public_hex
                    .chars()
                    .all(|c| c.is_ascii_hexdigit())
            {
                return Err(Error::InvalidRecipientMetadata(
                    "`_recipient_key.x25519_public_hex` must be 64 hex chars".to_string(),
                ));
            }
            if parsed.mlkem768_public_b64.trim().is_empty() {
                return Err(Error::InvalidRecipientMetadata(
                    "`_recipient_key.mlkem768_public_b64` must not be empty".to_string(),
                ));
            }

            return Ok(Self::RecipientKeyV3(parsed));
        }

        Err(Error::MissingRecipientMetadata)
    }

    pub fn legacy_public_key(&self) -> Option<&str> {
        match self {
            Self::LegacyPublicKey(pk) => Some(pk),
            Self::RecipientKeyV3(_) => None,
        }
    }

    pub fn key_id(&self) -> Option<&str> {
        match self {
            Self::LegacyPublicKey(_) => None,
            Self::RecipientKeyV3(recipient) => Some(&recipient.key_id),
        }
    }
}

pub fn compute_key_id(public_bundle: &PublicBundle) -> Result<String, Error> {
    let mut normalized = public_bundle.clone();
    normalized.key_id.clear();
    let bytes = serde_json::to_vec(&normalized)?;
    let digest = Sha256::digest(bytes);
    Ok(hex::encode(digest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_legacy_public_key() {
        let root = json!({
            "_public_key": "4c016009ce7246bebb08ec6856e76839a5c690cf01b30357914020aac9eebc8b"
        });

        let parsed = RecipientMetadata::parse(&root).unwrap();
        assert_eq!(
            parsed.legacy_public_key(),
            Some("4c016009ce7246bebb08ec6856e76839a5c690cf01b30357914020aac9eebc8b")
        );
    }

    #[test]
    fn parses_v3_recipient_key() {
        let root = json!({
            "_recipient_key": {
                "version": 3,
                "key_id": "7f2cb4f7c1c8f1d4b3c0f0d0f6a9b7e2d4c1e8a7b9c3d2e1f0a4b6c8d9e0f123",
                "algorithm": "ml-kem-768+x25519",
                "x25519_public_hex": "4c016009ce7246bebb08ec6856e76839a5c690cf01b30357914020aac9eebc8b",
                "mlkem768_public_b64": "ZmFrZS1iYXNlNjQ="
            }
        });

        let parsed = RecipientMetadata::parse(&root).unwrap();
        assert_eq!(
            parsed.key_id(),
            Some("7f2cb4f7c1c8f1d4b3c0f0d0f6a9b7e2d4c1e8a7b9c3d2e1f0a4b6c8d9e0f123")
        );
    }

    #[test]
    fn rejects_mixed_metadata() {
        let root = json!({
            "_public_key": "4c016009ce7246bebb08ec6856e76839a5c690cf01b30357914020aac9eebc8b",
            "_recipient_key": {
                "version": 3,
                "key_id": "7f2cb4f7c1c8f1d4b3c0f0d0f6a9b7e2d4c1e8a7b9c3d2e1f0a4b6c8d9e0f123",
                "algorithm": "ml-kem-768+x25519",
                "x25519_public_hex": "4c016009ce7246bebb08ec6856e76839a5c690cf01b30357914020aac9eebc8b",
                "mlkem768_public_b64": "ZmFrZS1iYXNlNjQ="
            }
        });

        let err = RecipientMetadata::parse(&root).unwrap_err().to_string();
        assert!(err.contains("must not contain both"));
    }

    #[test]
    fn computes_stable_key_id_from_public_bundle() {
        let recipient = RecipientKeyV3 {
            version: 3,
            key_id: "ignored".to_string(),
            algorithm: "ml-kem-768+x25519".to_string(),
            x25519_public_hex:
                "4c016009ce7246bebb08ec6856e76839a5c690cf01b30357914020aac9eebc8b".to_string(),
            mlkem768_public_b64: "ZmFrZS1iYXNlNjQ=".to_string(),
        };

        let key_id_a = compute_key_id(&recipient.to_public_bundle()).unwrap();
        let key_id_b = compute_key_id(&recipient.to_public_bundle()).unwrap();

        assert_eq!(key_id_a, key_id_b);
        assert_eq!(key_id_a.len(), 64);
    }

    #[test]
    fn rejects_invalid_v3_recipient_key_shape() {
        let root = json!({
            "_recipient_key": {
                "version": 3,
                "key_id": "abc",
                "algorithm": "ml-kem-768+x25519",
                "x25519_public_hex": "short",
                "mlkem768_public_b64": ""
            }
        });

        let err = RecipientMetadata::parse(&root).unwrap_err().to_string();
        assert!(err.contains("x25519_public_hex") || err.contains("must not be empty"));
    }
}
