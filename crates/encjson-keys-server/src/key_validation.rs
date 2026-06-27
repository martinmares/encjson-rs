use encjson_core::recipient::{PrivateBundle, PublicBundle, compute_key_id};

pub(crate) fn is_hex_64(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit())
}

fn extract_x25519_public_hex(bundle: &PublicBundle) -> anyhow::Result<String> {
    bundle
        .components
        .iter()
        .find(|component| component.role == "kex" && component.algorithm == "x25519")
        .map(|component| component.public.clone())
        .filter(|value| is_hex_64(value))
        .ok_or_else(|| anyhow::anyhow!("public_bundle is missing x25519 public component"))
}

pub(crate) fn validate_v3_bundles(
    key_id: &str,
    version: u32,
    algorithm: &str,
    public_bundle: &PublicBundle,
    private_bundle: &PrivateBundle,
) -> anyhow::Result<String> {
    if version != 3 {
        return Err(anyhow::anyhow!("version must be 3"));
    }
    if public_bundle.version != 3 || private_bundle.version != 3 {
        return Err(anyhow::anyhow!("bundle version must be 3"));
    }
    if public_bundle.key_id != key_id || private_bundle.key_id != key_id {
        return Err(anyhow::anyhow!("bundle key_id mismatch"));
    }
    if public_bundle.algorithm != algorithm || private_bundle.algorithm != algorithm {
        return Err(anyhow::anyhow!("bundle algorithm mismatch"));
    }
    let computed = compute_key_id(public_bundle)?;
    if computed != key_id {
        return Err(anyhow::anyhow!("key_id does not match public_bundle"));
    }
    extract_x25519_public_hex(public_bundle)
}
