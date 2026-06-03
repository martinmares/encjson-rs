use std::collections::HashMap;
use std::fmt;
use std::io::Read;
use std::path::Path;

use reqwest::blocking::ClientBuilder;
use reqwest::{Certificate, Identity};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeySourceKind {
    Env,
    Dir,
    RemoteMtls,
    Vault,
    Conjur,
    Cli,
}

impl KeySourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            KeySourceKind::Env => "env",
            KeySourceKind::Dir => "dir",
            KeySourceKind::RemoteMtls => "remote-mtls",
            KeySourceKind::Vault => "vault",
            KeySourceKind::Conjur => "conjur",
            KeySourceKind::Cli => "cli",
        }
    }
}

impl fmt::Display for KeySourceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for KeySourceKind {
    type Err = KeySourceError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "env" => Ok(KeySourceKind::Env),
            "dir" => Ok(KeySourceKind::Dir),
            "remote-mtls" => Ok(KeySourceKind::RemoteMtls),
            "vault" => Ok(KeySourceKind::Vault),
            "conjur" => Ok(KeySourceKind::Conjur),
            "cli" => Ok(KeySourceKind::Cli),
            _ => Err(KeySourceError::InvalidKeyMaterial {
                reason: "unknown key source kind",
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyContext {
    pub tenant: String,
    pub env: String,
}

impl PolicyContext {
    pub fn new(tenant: impl Into<String>, env: impl Into<String>) -> Result<Self, KeySourceError> {
        let tenant = tenant.into();
        let env = env.into();
        if tenant.trim().is_empty() {
            return Err(KeySourceError::ContextRequired { field: "tenant" });
        }
        if env.trim().is_empty() {
            return Err(KeySourceError::ContextRequired { field: "env" });
        }
        Ok(Self { tenant, env })
    }
}

pub fn require_policy_context(
    tenant: Option<&str>,
    env: Option<&str>,
) -> Result<PolicyContext, KeySourceError> {
    PolicyContext::new(
        tenant.unwrap_or_default().to_string(),
        env.unwrap_or_default().to_string(),
    )
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoadedKeyPair {
    pub public_hex: String,
    pub private_hex: String,
}

impl fmt::Debug for LoadedKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoadedKeyPair")
            .field("public_hex", &self.public_hex)
            .field("private_hex", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum KeySourceError {
    #[error("missing required configuration: {name}")]
    MissingConfig { name: &'static str },

    #[error("key source is unavailable: {kind}")]
    SourceUnavailable { kind: KeySourceKind },

    #[error("invalid key material: {reason}")]
    InvalidKeyMaterial { reason: &'static str },

    #[error("missing required policy context field: {field}")]
    ContextRequired { field: &'static str },

    #[error("insecure key input is disabled: {reason}")]
    InsecureInputDisallowed { reason: &'static str },
}

#[derive(Debug, Clone)]
pub struct KeySourceOptions {
    pub kind: KeySourceKind,
    pub keydir: Option<String>,
    pub remote_mtls: Option<RemoteMtlsConfig>,
    pub vault: Option<VaultConfig>,
    pub conjur: Option<ConjurConfig>,
}

#[derive(Debug, Clone, Default)]
pub struct CliKeyInput {
    pub public_key: Option<String>,
    pub private_key: Option<String>,
    pub private_key_file: Option<String>,
    pub private_key_fd: Option<i32>,
    pub private_key_stdin: bool,
    pub allow_insecure_cli_private_key: bool,
}

#[derive(Debug, Clone)]
pub struct RemoteMtlsConfig {
    pub url: String,
    pub client_cert_path: String,
    pub client_key_path: String,
    pub ca_cert_path: Option<String>,
}

#[derive(Debug, Clone)]
pub struct VaultConfig {
    pub addr: String,
    pub path: String,
    pub token: String,
    pub public_field: Option<String>,
    pub private_field: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ConjurConfig {
    pub appliance_url: String,
    pub account: String,
    pub authn_login: String,
    pub authn_api_key: String,
    pub public_variable_id: String,
    pub private_variable_id: String,
    pub ca_cert_path: Option<String>,
}

const CANON_PUBLIC: &str = "ENCJSON_PUBLIC_KEY";
const CANON_PRIVATE: &str = "ENCJSON_PRIVATE_KEY";
const LEGACY_PUBLIC: &str = "SECRET_PUBLIC_KEY";
const LEGACY_PRIVATE: &str = "SECRET_PRIVATE_KEY";

pub fn validate_hex_64(value: &str) -> Result<(), KeySourceError> {
    if value.len() != 64 {
        return Err(KeySourceError::InvalidKeyMaterial {
            reason: "expected 64 hex characters",
        });
    }
    if !value.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(KeySourceError::InvalidKeyMaterial {
            reason: "contains non-hex characters",
        });
    }
    Ok(())
}

pub fn derive_public_hex_from_private(private_hex: &str) -> Result<String, KeySourceError> {
    validate_hex_64(private_hex)?;

    let bytes = hex::decode(private_hex).map_err(|_| KeySourceError::InvalidKeyMaterial {
        reason: "private key decode failed",
    })?;
    if bytes.len() != 32 {
        return Err(KeySourceError::InvalidKeyMaterial {
            reason: "private key must be 32 bytes",
        });
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    let secret = StaticSecret::from(arr);
    let public = PublicKey::from(&secret);
    Ok(hex::encode(public.as_bytes()))
}

pub fn validate_key_pair(public_hex: &str, private_hex: &str) -> Result<(), KeySourceError> {
    validate_hex_64(public_hex)?;
    validate_hex_64(private_hex)?;

    let derived = derive_public_hex_from_private(private_hex)?;
    if !derived.eq_ignore_ascii_case(public_hex) {
        return Err(KeySourceError::InvalidKeyMaterial {
            reason: "public key does not match private key",
        });
    }
    Ok(())
}

pub fn load_from_env() -> Result<LoadedKeyPair, KeySourceError> {
    let vars = std::env::vars().collect::<HashMap<_, _>>();
    load_from_env_map(&vars)
}

pub fn load_from_env_map(vars: &HashMap<String, String>) -> Result<LoadedKeyPair, KeySourceError> {
    let public_hex = vars
        .get(CANON_PUBLIC)
        .or_else(|| vars.get(LEGACY_PUBLIC))
        .cloned()
        .ok_or(KeySourceError::MissingConfig {
            name: "ENCJSON_PUBLIC_KEY (or SECRET_PUBLIC_KEY)",
        })?;

    let private_hex = vars
        .get(CANON_PRIVATE)
        .or_else(|| vars.get(LEGACY_PRIVATE))
        .cloned()
        .ok_or(KeySourceError::MissingConfig {
            name: "ENCJSON_PRIVATE_KEY (or SECRET_PRIVATE_KEY)",
        })?;

    validate_key_pair(&public_hex, &private_hex)?;
    Ok(LoadedKeyPair {
        public_hex,
        private_hex,
    })
}

pub fn load_from_dir(dir: &Path) -> Result<LoadedKeyPair, KeySourceError> {
    let public_path = dir.join("public.key");
    let private_path = dir.join("private.key");

    let public_hex = std::fs::read_to_string(&public_path)
        .map_err(|_| KeySourceError::MissingConfig { name: "public.key" })?
        .trim()
        .to_string();
    let private_hex = std::fs::read_to_string(&private_path)
        .map_err(|_| KeySourceError::MissingConfig {
            name: "private.key",
        })?
        .trim()
        .to_string();

    validate_key_pair(&public_hex, &private_hex)?;
    Ok(LoadedKeyPair {
        public_hex,
        private_hex,
    })
}

pub fn load_from_source(options: &KeySourceOptions) -> Result<LoadedKeyPair, KeySourceError> {
    match options.kind {
        KeySourceKind::Env => load_from_env(),
        KeySourceKind::Dir => {
            let keydir = options
                .keydir
                .as_ref()
                .ok_or(KeySourceError::MissingConfig {
                    name: "ENCJSON_KEYDIR",
                })?;
            load_from_dir(Path::new(keydir))
        }
        KeySourceKind::RemoteMtls => {
            let cfg = options
                .remote_mtls
                .as_ref()
                .ok_or(KeySourceError::MissingConfig {
                    name: "remote-mtls config",
                })?;
            load_from_remote_mtls(cfg)
        }
        KeySourceKind::Vault => {
            let cfg = options
                .vault
                .as_ref()
                .ok_or(KeySourceError::MissingConfig {
                    name: "vault config",
                })?;
            load_from_vault(cfg)
        }
        KeySourceKind::Conjur => {
            let cfg = options
                .conjur
                .as_ref()
                .ok_or(KeySourceError::MissingConfig {
                    name: "conjur config",
                })?;
            load_from_conjur(cfg)
        }
        KeySourceKind::Cli => Err(KeySourceError::SourceUnavailable {
            kind: KeySourceKind::Cli,
        }),
    }
}

pub fn load_from_cli(input: &CliKeyInput) -> Result<LoadedKeyPair, KeySourceError> {
    let public_hex = input
        .public_key
        .clone()
        .ok_or(KeySourceError::MissingConfig {
            name: "--public-key",
        })?;

    let mut value_sources = 0u8;
    if input.private_key.is_some() {
        value_sources += 1;
    }
    if input.private_key_file.is_some() {
        value_sources += 1;
    }
    if input.private_key_fd.is_some() {
        value_sources += 1;
    }
    if input.private_key_stdin {
        value_sources += 1;
    }
    if value_sources == 0 {
        return Err(KeySourceError::MissingConfig {
            name: "one of --private-key-file/--private-key-fd/--private-key-stdin (or insecure --private-key)",
        });
    }
    if value_sources > 1 {
        return Err(KeySourceError::InvalidKeyMaterial {
            reason: "multiple private key input sources provided",
        });
    }

    let private_hex = if let Some(raw) = &input.private_key {
        if !input.allow_insecure_cli_private_key {
            return Err(KeySourceError::InsecureInputDisallowed {
                reason: "raw --private-key requires --allow-insecure-cli-private-key",
            });
        }
        raw.clone()
    } else if let Some(path) = &input.private_key_file {
        read_secret_from_path(Path::new(path))?
    } else if let Some(fd) = input.private_key_fd {
        read_secret_from_fd(fd)?
    } else {
        read_secret_from_stdin()?
    };

    validate_key_pair(&public_hex, &private_hex)?;
    Ok(LoadedKeyPair {
        public_hex,
        private_hex,
    })
}

fn read_secret_from_path(path: &Path) -> Result<String, KeySourceError> {
    let content = std::fs::read_to_string(path).map_err(|_| KeySourceError::MissingConfig {
        name: "--private-key-file",
    })?;
    Ok(content.trim().to_string())
}

fn read_secret_from_fd(fd: i32) -> Result<String, KeySourceError> {
    #[cfg(unix)]
    {
        let path = format!("/dev/fd/{fd}");
        read_secret_from_path(Path::new(&path))
    }
    #[cfg(not(unix))]
    {
        let _ = fd;
        Err(KeySourceError::SourceUnavailable {
            kind: KeySourceKind::Cli,
        })
    }
}

fn read_secret_from_stdin() -> Result<String, KeySourceError> {
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .map_err(|_| KeySourceError::MissingConfig {
            name: "--private-key-stdin",
        })?;
    Ok(input.trim().to_string())
}

pub fn load_from_remote_mtls(cfg: &RemoteMtlsConfig) -> Result<LoadedKeyPair, KeySourceError> {
    if cfg.url.trim().is_empty() {
        return Err(KeySourceError::MissingConfig {
            name: "ENCJSON_REMOTE_KEYS_URL",
        });
    }
    if cfg.client_cert_path.trim().is_empty() {
        return Err(KeySourceError::MissingConfig {
            name: "ENCJSON_REMOTE_TLS_CERT_FILE",
        });
    }
    if cfg.client_key_path.trim().is_empty() {
        return Err(KeySourceError::MissingConfig {
            name: "ENCJSON_REMOTE_TLS_KEY_FILE",
        });
    }

    let cert_pem =
        std::fs::read(&cfg.client_cert_path).map_err(|_| KeySourceError::MissingConfig {
            name: "ENCJSON_REMOTE_TLS_CERT_FILE",
        })?;
    let key_pem =
        std::fs::read(&cfg.client_key_path).map_err(|_| KeySourceError::MissingConfig {
            name: "ENCJSON_REMOTE_TLS_KEY_FILE",
        })?;

    let mut identity_pem = Vec::with_capacity(cert_pem.len() + key_pem.len() + 1);
    identity_pem.extend_from_slice(&cert_pem);
    identity_pem.push(b'\n');
    identity_pem.extend_from_slice(&key_pem);

    let identity =
        Identity::from_pem(&identity_pem).map_err(|_| KeySourceError::InvalidKeyMaterial {
            reason: "invalid remote mTLS identity PEM",
        })?;

    let mut builder = ClientBuilder::new().identity(identity);
    if let Some(ca_path) = &cfg.ca_cert_path {
        let ca_pem = std::fs::read(ca_path).map_err(|_| KeySourceError::MissingConfig {
            name: "ENCJSON_REMOTE_TLS_CA_FILE",
        })?;
        let ca =
            Certificate::from_pem(&ca_pem).map_err(|_| KeySourceError::InvalidKeyMaterial {
                reason: "invalid remote mTLS CA PEM",
            })?;
        builder = builder.add_root_certificate(ca);
    }

    let client = builder
        .build()
        .map_err(|_| KeySourceError::SourceUnavailable {
            kind: KeySourceKind::RemoteMtls,
        })?;

    let resp =
        client
            .get(cfg.url.trim())
            .send()
            .map_err(|_| KeySourceError::SourceUnavailable {
                kind: KeySourceKind::RemoteMtls,
            })?;
    if !resp.status().is_success() {
        return Err(KeySourceError::SourceUnavailable {
            kind: KeySourceKind::RemoteMtls,
        });
    }

    let payload: Value = resp
        .json()
        .map_err(|_| KeySourceError::InvalidKeyMaterial {
            reason: "invalid remote JSON payload",
        })?;
    parse_remote_payload(&payload)
}

pub fn load_from_vault(cfg: &VaultConfig) -> Result<LoadedKeyPair, KeySourceError> {
    if cfg.addr.trim().is_empty() {
        return Err(KeySourceError::MissingConfig {
            name: "ENCJSON_VAULT_ADDR",
        });
    }
    if cfg.path.trim().is_empty() {
        return Err(KeySourceError::MissingConfig {
            name: "ENCJSON_VAULT_PATH",
        });
    }
    if cfg.token.trim().is_empty() {
        return Err(KeySourceError::MissingConfig {
            name: "ENCJSON_VAULT_TOKEN",
        });
    }

    let public_field = cfg
        .public_field
        .as_deref()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or("public-key");
    let private_field = cfg
        .private_field
        .as_deref()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or("private-key");

    let addr = cfg.addr.trim_end_matches('/');
    let path = cfg.path.trim_start_matches('/');
    let url = format!("{addr}/v1/{path}");

    let resp = reqwest::blocking::Client::new()
        .get(url)
        .header("X-Vault-Token", cfg.token.trim())
        .send()
        .map_err(|_| KeySourceError::SourceUnavailable {
            kind: KeySourceKind::Vault,
        })?;
    if !resp.status().is_success() {
        return Err(KeySourceError::SourceUnavailable {
            kind: KeySourceKind::Vault,
        });
    }

    let payload: Value = resp
        .json()
        .map_err(|_| KeySourceError::InvalidKeyMaterial {
            reason: "invalid vault JSON payload",
        })?;
    parse_vault_payload(&payload, public_field, private_field)
}

pub fn load_from_conjur(cfg: &ConjurConfig) -> Result<LoadedKeyPair, KeySourceError> {
    if cfg.appliance_url.trim().is_empty() {
        return Err(KeySourceError::MissingConfig {
            name: "ENCJSON_CONJUR_APPLIANCE_URL",
        });
    }
    if cfg.account.trim().is_empty() {
        return Err(KeySourceError::MissingConfig {
            name: "ENCJSON_CONJUR_ACCOUNT",
        });
    }
    if cfg.authn_login.trim().is_empty() {
        return Err(KeySourceError::MissingConfig {
            name: "ENCJSON_CONJUR_AUTHN_LOGIN",
        });
    }
    if cfg.authn_api_key.trim().is_empty() {
        return Err(KeySourceError::MissingConfig {
            name: "ENCJSON_CONJUR_AUTHN_API_KEY",
        });
    }
    if cfg.public_variable_id.trim().is_empty() {
        return Err(KeySourceError::MissingConfig {
            name: "ENCJSON_CONJUR_PUBLIC_VARIABLE_ID",
        });
    }
    if cfg.private_variable_id.trim().is_empty() {
        return Err(KeySourceError::MissingConfig {
            name: "ENCJSON_CONJUR_PRIVATE_VARIABLE_ID",
        });
    }

    let mut builder = ClientBuilder::new();
    if let Some(ca_path) = &cfg.ca_cert_path {
        let ca_pem = std::fs::read(ca_path).map_err(|_| KeySourceError::MissingConfig {
            name: "ENCJSON_CONJUR_CA_CERT_FILE",
        })?;
        let ca =
            Certificate::from_pem(&ca_pem).map_err(|_| KeySourceError::InvalidKeyMaterial {
                reason: "invalid conjur CA PEM",
            })?;
        builder = builder.add_root_certificate(ca);
    }
    let client = builder
        .build()
        .map_err(|_| KeySourceError::SourceUnavailable {
            kind: KeySourceKind::Conjur,
        })?;

    let base = cfg.appliance_url.trim_end_matches('/');
    let login = cfg.authn_login.trim();
    let account = cfg.account.trim();
    let auth_url = format!("{base}/authn/{account}/{login}/authenticate");
    let token_resp = client
        .post(auth_url)
        .header("Content-Type", "text/plain")
        .body(cfg.authn_api_key.trim().to_string())
        .send()
        .map_err(|_| KeySourceError::SourceUnavailable {
            kind: KeySourceKind::Conjur,
        })?;
    if !token_resp.status().is_success() {
        return Err(KeySourceError::SourceUnavailable {
            kind: KeySourceKind::Conjur,
        });
    }
    let token = token_resp
        .text()
        .map_err(|_| KeySourceError::SourceUnavailable {
            kind: KeySourceKind::Conjur,
        })?
        .trim()
        .to_string();
    if token.is_empty() {
        return Err(KeySourceError::InvalidKeyMaterial {
            reason: "conjur auth token is empty",
        });
    }

    let authz = format!("Token token=\"{token}\"");
    let public_url = format!(
        "{base}/secrets/{account}/variable/{}",
        cfg.public_variable_id.trim()
    );
    let private_url = format!(
        "{base}/secrets/{account}/variable/{}",
        cfg.private_variable_id.trim()
    );
    let public_hex = client
        .get(public_url)
        .header("Authorization", authz.clone())
        .send()
        .map_err(|_| KeySourceError::SourceUnavailable {
            kind: KeySourceKind::Conjur,
        })?
        .error_for_status()
        .map_err(|_| KeySourceError::SourceUnavailable {
            kind: KeySourceKind::Conjur,
        })?
        .text()
        .map_err(|_| KeySourceError::SourceUnavailable {
            kind: KeySourceKind::Conjur,
        })?
        .trim()
        .to_string();
    let private_hex = client
        .get(private_url)
        .header("Authorization", authz)
        .send()
        .map_err(|_| KeySourceError::SourceUnavailable {
            kind: KeySourceKind::Conjur,
        })?
        .error_for_status()
        .map_err(|_| KeySourceError::SourceUnavailable {
            kind: KeySourceKind::Conjur,
        })?
        .text()
        .map_err(|_| KeySourceError::SourceUnavailable {
            kind: KeySourceKind::Conjur,
        })?
        .trim()
        .to_string();

    validate_key_pair(&public_hex, &private_hex)?;
    Ok(LoadedKeyPair {
        public_hex,
        private_hex,
    })
}

fn parse_remote_payload(payload: &Value) -> Result<LoadedKeyPair, KeySourceError> {
    let public_hex = extract_string(payload, &["public_hex", "public-key"]).ok_or(
        KeySourceError::InvalidKeyMaterial {
            reason: "remote payload missing public key field",
        },
    )?;
    let private_hex = extract_string(payload, &["private_hex", "private-key"]).ok_or(
        KeySourceError::InvalidKeyMaterial {
            reason: "remote payload missing private key field",
        },
    )?;

    validate_key_pair(&public_hex, &private_hex)?;
    Ok(LoadedKeyPair {
        public_hex,
        private_hex,
    })
}

fn parse_vault_payload(
    payload: &Value,
    public_field: &str,
    private_field: &str,
) -> Result<LoadedKeyPair, KeySourceError> {
    let root_data = payload.get("data").and_then(Value::as_object).ok_or(
        KeySourceError::InvalidKeyMaterial {
            reason: "vault payload missing data object",
        },
    )?;

    let nested = root_data
        .get("data")
        .and_then(Value::as_object)
        .unwrap_or(root_data);

    let public_hex = nested
        .get(public_field)
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .ok_or(KeySourceError::InvalidKeyMaterial {
            reason: "vault payload missing public key field",
        })?;

    let private_hex = nested
        .get(private_field)
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .ok_or(KeySourceError::InvalidKeyMaterial {
            reason: "vault payload missing private key field",
        })?;

    validate_key_pair(&public_hex, &private_hex)?;
    Ok(LoadedKeyPair {
        public_hex,
        private_hex,
    })
}

fn extract_string(payload: &Value, fields: &[&str]) -> Option<String> {
    fields
        .iter()
        .find_map(|name| payload.get(*name).and_then(Value::as_str))
        .map(ToString::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn fixture_pair() -> (String, String) {
        let private = "24e55b25c598d4df78387de983b455144e197e3e63239d0c1fc92f862bbd7c0c";
        let public = derive_public_hex_from_private(private).unwrap();
        (public, private.to_string())
    }

    #[test]
    fn validate_hex_64_accepts_valid_hex() {
        assert!(validate_hex_64(&"a".repeat(64)).is_ok());
        assert!(validate_hex_64(&"A".repeat(64)).is_ok());
    }

    #[test]
    fn validate_hex_64_rejects_bad_length() {
        let err = validate_hex_64("abcd").unwrap_err();
        assert_eq!(
            err,
            KeySourceError::InvalidKeyMaterial {
                reason: "expected 64 hex characters"
            }
        );
    }

    #[test]
    fn validate_hex_64_rejects_non_hex() {
        let invalid = format!("{}z", "a".repeat(63));
        let err = validate_hex_64(&invalid).unwrap_err();
        assert_eq!(
            err,
            KeySourceError::InvalidKeyMaterial {
                reason: "contains non-hex characters"
            }
        );
    }

    #[test]
    fn validate_key_pair_accepts_matching_pair() {
        let (public, private) = fixture_pair();
        assert!(validate_key_pair(&public, &private).is_ok());
    }

    #[test]
    fn validate_key_pair_rejects_mismatch() {
        let (_public, private) = fixture_pair();
        let mismatch_public = "f".repeat(64);
        let err = validate_key_pair(&mismatch_public, &private).unwrap_err();
        assert_eq!(
            err,
            KeySourceError::InvalidKeyMaterial {
                reason: "public key does not match private key"
            }
        );
    }

    #[test]
    fn loaded_key_pair_debug_redacts_private_key() {
        let (public, private) = fixture_pair();
        let kp = LoadedKeyPair {
            public_hex: public,
            private_hex: private,
        };
        let debug = format!("{kp:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("24e55b25c598d4df"));
    }

    #[test]
    fn policy_context_requires_tenant_and_env() {
        let err = PolicyContext::new("", "test").unwrap_err();
        assert_eq!(err, KeySourceError::ContextRequired { field: "tenant" });

        let err = PolicyContext::new("tsm", "").unwrap_err();
        assert_eq!(err, KeySourceError::ContextRequired { field: "env" });

        let ok = PolicyContext::new("tsm", "test").unwrap();
        assert_eq!(ok.tenant, "tsm");
        assert_eq!(ok.env, "test");
    }

    #[test]
    fn require_policy_context_fails_when_missing_values() {
        let err = require_policy_context(None, Some("test")).unwrap_err();
        assert_eq!(err, KeySourceError::ContextRequired { field: "tenant" });

        let err = require_policy_context(Some("tsm"), None).unwrap_err();
        assert_eq!(err, KeySourceError::ContextRequired { field: "env" });
    }

    #[test]
    fn require_policy_context_accepts_both_values() {
        let ctx = require_policy_context(Some("tsm"), Some("test")).unwrap();
        assert_eq!(ctx.tenant, "tsm");
        assert_eq!(ctx.env, "test");
    }

    #[test]
    fn load_from_env_map_prefers_canonical_names() {
        let (public, private) = fixture_pair();
        let mut vars = HashMap::new();
        vars.insert(CANON_PUBLIC.to_string(), public.clone());
        vars.insert(CANON_PRIVATE.to_string(), private.clone());
        vars.insert(LEGACY_PUBLIC.to_string(), "f".repeat(64));
        vars.insert(LEGACY_PRIVATE.to_string(), "e".repeat(64));

        let loaded = load_from_env_map(&vars).unwrap();
        assert_eq!(loaded.public_hex, public);
        assert_eq!(loaded.private_hex, private);
    }

    #[test]
    fn load_from_env_map_uses_legacy_when_canonical_missing() {
        let (public, private) = fixture_pair();
        let mut vars = HashMap::new();
        vars.insert(LEGACY_PUBLIC.to_string(), public.clone());
        vars.insert(LEGACY_PRIVATE.to_string(), private.clone());

        let loaded = load_from_env_map(&vars).unwrap();
        assert_eq!(loaded.public_hex, public);
        assert_eq!(loaded.private_hex, private);
    }

    #[test]
    fn load_from_env_map_fails_when_missing_private_key() {
        let (public, _private) = fixture_pair();
        let mut vars = HashMap::new();
        vars.insert(CANON_PUBLIC.to_string(), public);
        let err = load_from_env_map(&vars).unwrap_err();
        assert_eq!(
            err,
            KeySourceError::MissingConfig {
                name: "ENCJSON_PRIVATE_KEY (or SECRET_PRIVATE_KEY)"
            }
        );
    }

    #[test]
    fn load_from_dir_reads_and_validates_key_pair() {
        let (public, private) = fixture_pair();
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("encjson-core-key-sources-{unique}"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("public.key"), format!("{public}\n")).unwrap();
        std::fs::write(dir.join("private.key"), format!("{private}\n")).unwrap();

        let loaded = load_from_dir(&dir).unwrap();
        assert_eq!(loaded.public_hex, public);
        assert_eq!(loaded.private_hex, private);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_from_source_dir_requires_keydir_without_fallback() {
        let options = KeySourceOptions {
            kind: KeySourceKind::Dir,
            keydir: None,
            remote_mtls: None,
            vault: None,
            conjur: None,
        };
        let err = load_from_source(&options).unwrap_err();
        assert_eq!(
            err,
            KeySourceError::MissingConfig {
                name: "ENCJSON_KEYDIR"
            }
        );
    }

    #[test]
    fn load_from_source_requires_vault_config() {
        let options = KeySourceOptions {
            kind: KeySourceKind::Vault,
            keydir: None,
            remote_mtls: None,
            vault: None,
            conjur: None,
        };
        let err = load_from_source(&options).unwrap_err();
        assert_eq!(
            err,
            KeySourceError::MissingConfig {
                name: "vault config"
            }
        );
    }

    #[test]
    fn load_from_source_requires_remote_mtls_config() {
        let options = KeySourceOptions {
            kind: KeySourceKind::RemoteMtls,
            keydir: None,
            remote_mtls: None,
            vault: None,
            conjur: None,
        };
        let err = load_from_source(&options).unwrap_err();
        assert_eq!(
            err,
            KeySourceError::MissingConfig {
                name: "remote-mtls config"
            }
        );
    }

    #[test]
    fn load_from_source_requires_conjur_config() {
        let options = KeySourceOptions {
            kind: KeySourceKind::Conjur,
            keydir: None,
            remote_mtls: None,
            vault: None,
            conjur: None,
        };
        let err = load_from_source(&options).unwrap_err();
        assert_eq!(
            err,
            KeySourceError::MissingConfig {
                name: "conjur config"
            }
        );
    }

    #[test]
    fn load_from_cli_accepts_private_key_file() {
        let (public, private) = fixture_pair();
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let file = std::env::temp_dir().join(format!("encjson-core-cli-private-{unique}.key"));
        std::fs::write(&file, format!("{private}\n")).unwrap();

        let input = CliKeyInput {
            public_key: Some(public.clone()),
            private_key_file: Some(file.display().to_string()),
            ..Default::default()
        };
        let loaded = load_from_cli(&input).unwrap();
        assert_eq!(loaded.public_hex, public);
        assert_eq!(loaded.private_hex, private);

        std::fs::remove_file(file).unwrap();
    }

    #[test]
    fn load_from_cli_rejects_raw_private_key_without_opt_in() {
        let (public, private) = fixture_pair();
        let input = CliKeyInput {
            public_key: Some(public),
            private_key: Some(private),
            allow_insecure_cli_private_key: false,
            ..Default::default()
        };
        let err = load_from_cli(&input).unwrap_err();
        assert_eq!(
            err,
            KeySourceError::InsecureInputDisallowed {
                reason: "raw --private-key requires --allow-insecure-cli-private-key"
            }
        );
    }

    #[test]
    fn load_from_cli_accepts_raw_private_key_with_opt_in() {
        let (public, private) = fixture_pair();
        let input = CliKeyInput {
            public_key: Some(public.clone()),
            private_key: Some(private.clone()),
            allow_insecure_cli_private_key: true,
            ..Default::default()
        };
        let loaded = load_from_cli(&input).unwrap();
        assert_eq!(loaded.public_hex, public);
        assert_eq!(loaded.private_hex, private);
    }

    #[test]
    fn load_from_cli_rejects_multiple_private_key_sources() {
        let (public, private) = fixture_pair();
        let input = CliKeyInput {
            public_key: Some(public),
            private_key: Some(private),
            private_key_stdin: true,
            allow_insecure_cli_private_key: true,
            ..Default::default()
        };
        let err = load_from_cli(&input).unwrap_err();
        assert_eq!(
            err,
            KeySourceError::InvalidKeyMaterial {
                reason: "multiple private key input sources provided"
            }
        );
    }

    #[test]
    fn parse_remote_payload_accepts_hex_fields() {
        let (public, private) = fixture_pair();
        let payload = serde_json::json!({
            "public_hex": public,
            "private_hex": private
        });
        let loaded = parse_remote_payload(&payload).unwrap();
        assert!(validate_key_pair(&loaded.public_hex, &loaded.private_hex).is_ok());
    }

    #[test]
    fn parse_vault_payload_supports_kv_v2_shape() {
        let (public, private) = fixture_pair();
        let payload = serde_json::json!({
            "data": {
                "data": {
                    "public-key": public,
                    "private-key": private
                }
            }
        });
        let loaded = parse_vault_payload(&payload, "public-key", "private-key").unwrap();
        assert!(validate_key_pair(&loaded.public_hex, &loaded.private_hex).is_ok());
    }

    #[test]
    fn parse_vault_payload_supports_kv_v1_shape() {
        let (public, private) = fixture_pair();
        let payload = serde_json::json!({
            "data": {
                "public-key": public,
                "private-key": private
            }
        });
        let loaded = parse_vault_payload(&payload, "public-key", "private-key").unwrap();
        assert!(validate_key_pair(&loaded.public_hex, &loaded.private_hex).is_ok());
    }

    #[test]
    fn remote_mtls_requires_required_config() {
        let cfg = RemoteMtlsConfig {
            url: "".to_string(),
            client_cert_path: "".to_string(),
            client_key_path: "".to_string(),
            ca_cert_path: None,
        };
        let err = load_from_remote_mtls(&cfg).unwrap_err();
        assert_eq!(
            err,
            KeySourceError::MissingConfig {
                name: "ENCJSON_REMOTE_KEYS_URL"
            }
        );
    }

    #[test]
    fn vault_requires_required_config() {
        let cfg = VaultConfig {
            addr: "".to_string(),
            path: "".to_string(),
            token: "".to_string(),
            public_field: None,
            private_field: None,
        };
        let err = load_from_vault(&cfg).unwrap_err();
        assert_eq!(
            err,
            KeySourceError::MissingConfig {
                name: "ENCJSON_VAULT_ADDR"
            }
        );
    }
}
