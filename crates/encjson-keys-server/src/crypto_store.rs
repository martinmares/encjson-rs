use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Generate, Nonce},
};
use base64::Engine;
use rand::Rng;
use sha2::Digest;
use x25519_dalek::{PublicKey, StaticSecret};

pub(crate) const ENC_PREFIX: &str = "encjson:aesgcm:";

pub(crate) fn public_from_private_hex(private_hex: &str) -> anyhow::Result<String> {
    let bytes = hex::decode(private_hex).map_err(|_| anyhow::anyhow!("invalid private_hex"))?;
    if bytes.len() != 32 {
        return Err(anyhow::anyhow!("invalid private_hex length"));
    }
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&bytes);
    let secret = StaticSecret::from(key_bytes);
    let public = PublicKey::from(&secret);
    Ok(hex::encode(public.as_bytes()))
}

pub(crate) fn random_token() -> String {
    let mut buf = [0u8; 32];
    rand::rng().fill_bytes(&mut buf);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

pub(crate) fn encrypt_private_hex(secret: &str, plaintext: &str) -> anyhow::Result<String> {
    let key = encryption_key(secret);
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let nonce = Nonce::<Aes256Gcm>::generate();
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|_| anyhow::anyhow!("encrypt failed"))?;
    let mut buf = Vec::with_capacity(nonce.len() + ciphertext.len());
    buf.extend_from_slice(&nonce);
    buf.extend_from_slice(&ciphertext);
    let b64 = base64::engine::general_purpose::STANDARD.encode(buf);
    Ok(format!("{ENC_PREFIX}{b64}"))
}

pub(crate) fn decrypt_private_hex(secret: &str, stored: &str) -> anyhow::Result<String> {
    if let Some(rest) = stored.strip_prefix(ENC_PREFIX) {
        let key = encryption_key(secret);
        let raw = base64::engine::general_purpose::STANDARD
            .decode(rest)
            .map_err(|_| anyhow::anyhow!("decrypt failed"))?;
        if raw.len() < 13 {
            return Err(anyhow::anyhow!("decrypt failed"));
        }
        let (nonce, ciphertext) = raw.split_at(12);
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let nonce =
            Nonce::<Aes256Gcm>::try_from(nonce).map_err(|_| anyhow::anyhow!("decrypt failed"))?;
        let plaintext = cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|_| anyhow::anyhow!("decrypt failed"))?;
        return Ok(String::from_utf8(plaintext)?);
    }
    Ok(stored.to_string())
}

fn encryption_key(secret: &str) -> [u8; 32] {
    let hash = sha2::Sha256::digest(secret.as_bytes());
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash);
    key
}
