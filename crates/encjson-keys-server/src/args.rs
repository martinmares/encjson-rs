use clap::Parser;
use encjson_core::key_sources::KeySourceKind;

#[derive(Debug, Parser)]
#[command(name = "encjson-keys-server", about = "Keys server for encjson")]
pub(crate) struct Args {
    #[arg(long, env = "DATABASE_URL")]
    pub(crate) database_url: Option<String>,
    #[arg(long, env = "ENCRYPTION_SECRET")]
    pub(crate) encryption_secret: Option<String>,
    #[arg(long, env = "ENCJSON_KEYS_ADDR", default_value = "127.0.0.1:8080")]
    pub(crate) keys_addr: String,
    #[arg(long, env = "ENCJSON_KEYS_AUTH")]
    pub(crate) keys_auth: Option<String>,
    #[arg(long, env = "ENCJSON_KEYS_JWT_ISSUER")]
    pub(crate) keys_jwt_issuer: Option<String>,
    #[arg(long, env = "ENCJSON_KEYS_JWKS_URL")]
    pub(crate) keys_jwks_url: Option<String>,
    #[arg(long, env = "ENCJSON_KEYS_JWT_AUDIENCE")]
    pub(crate) keys_jwt_audience: Option<String>,
    #[arg(long, env = "ENCJSON_KEYS_KUBE_SA_ISSUER")]
    pub(crate) keys_kube_sa_issuer: Option<String>,
    #[arg(long, env = "ENCJSON_KEYS_KUBE_SA_JWKS_URL")]
    pub(crate) keys_kube_sa_jwks_url: Option<String>,
    #[arg(long, env = "ENCJSON_KEYS_KUBE_SA_AUDIENCE")]
    pub(crate) keys_kube_sa_audience: Option<String>,
    #[arg(long, env = "ENCJSON_KEYS_MTLS_MODE")]
    pub(crate) keys_mtls_mode: Option<String>,
    #[arg(long, env = "ENCJSON_KEYS_POLICY_FILE")]
    pub(crate) keys_policy_file: Option<String>,
    #[arg(long, env = "ENCJSON_KEYS_RATE_LIMIT_PER_MINUTE")]
    pub(crate) keys_rate_limit_per_minute: Option<u64>,
    #[arg(long, env = "ENCJSON_KEYS_REQUESTS_RATE_LIMIT_PER_MINUTE")]
    pub(crate) keys_requests_rate_limit_per_minute: Option<u64>,
    #[arg(long, env = "ENCJSON_KEYS_UI_ENABLED")]
    pub(crate) keys_ui_enabled: Option<bool>,
    #[arg(long, env = "ENCJSON_KEYS_UI_ISSUER")]
    pub(crate) keys_ui_issuer: Option<String>,
    #[arg(long, env = "ENCJSON_KEYS_UI_CLIENT_ID")]
    pub(crate) keys_ui_client_id: Option<String>,
    #[arg(long, env = "ENCJSON_KEYS_UI_CLIENT_SECRET")]
    pub(crate) keys_ui_client_secret: Option<String>,
    #[arg(long, env = "ENCJSON_KEYS_UI_BASE_URL")]
    pub(crate) keys_ui_base_url: Option<String>,
    #[arg(long, env = "ENCJSON_KEYS_UI_COOKIE_SECURE")]
    pub(crate) keys_ui_cookie_secure: Option<bool>,
    #[arg(long, env = "ENCJSON_KEYS_TLS_CERT_FILE")]
    pub(crate) keys_tls_cert_file: Option<String>,
    #[arg(long, env = "ENCJSON_KEYS_TLS_KEY_FILE")]
    pub(crate) keys_tls_key_file: Option<String>,
    #[arg(long, env = "ENCJSON_KEYS_TLS_CLIENT_CA_FILE")]
    pub(crate) keys_tls_client_ca_file: Option<String>,
    #[arg(
        long,
        env = "ENCJSON_KEYS_SERVER_SCOPE_REQUIRED",
        default_value_t = false
    )]
    pub(crate) keys_server_scope_required: bool,
    #[arg(long, env = "ENCJSON_TENANT")]
    pub(crate) tenant: Option<String>,
    #[arg(long = "env", env = "ENCJSON_ENV")]
    pub(crate) env_name: Option<String>,
    #[arg(long, env = "ENCJSON_KEY_SOURCE", value_enum)]
    pub(crate) key_source: Option<KeySourceCli>,
    #[arg(long, env = "ENCJSON_REMOTE_KEYS_URL")]
    pub(crate) remote_keys_url: Option<String>,
    #[arg(long, env = "ENCJSON_REMOTE_TLS_CERT_FILE")]
    pub(crate) remote_tls_cert_file: Option<String>,
    #[arg(long, env = "ENCJSON_REMOTE_TLS_KEY_FILE")]
    pub(crate) remote_tls_key_file: Option<String>,
    #[arg(long, env = "ENCJSON_REMOTE_TLS_CA_FILE")]
    pub(crate) remote_tls_ca_file: Option<String>,
    #[arg(long, env = "ENCJSON_VAULT_ADDR")]
    pub(crate) vault_addr: Option<String>,
    #[arg(long, env = "ENCJSON_VAULT_PATH")]
    pub(crate) vault_path: Option<String>,
    #[arg(long, env = "ENCJSON_VAULT_TOKEN")]
    pub(crate) vault_token: Option<String>,
    #[arg(long, env = "ENCJSON_VAULT_PUBLIC_FIELD")]
    pub(crate) vault_public_field: Option<String>,
    #[arg(long, env = "ENCJSON_VAULT_PRIVATE_FIELD")]
    pub(crate) vault_private_field: Option<String>,
    #[arg(long, env = "ENCJSON_CONJUR_APPLIANCE_URL")]
    pub(crate) conjur_appliance_url: Option<String>,
    #[arg(long, env = "ENCJSON_CONJUR_ACCOUNT")]
    pub(crate) conjur_account: Option<String>,
    #[arg(long, env = "ENCJSON_CONJUR_AUTHN_LOGIN")]
    pub(crate) conjur_authn_login: Option<String>,
    #[arg(long, env = "ENCJSON_CONJUR_AUTHN_API_KEY")]
    pub(crate) conjur_authn_api_key: Option<String>,
    #[arg(long, env = "ENCJSON_CONJUR_PUBLIC_VARIABLE_ID")]
    pub(crate) conjur_public_variable_id: Option<String>,
    #[arg(long, env = "ENCJSON_CONJUR_PRIVATE_VARIABLE_ID")]
    pub(crate) conjur_private_variable_id: Option<String>,
    #[arg(long, env = "ENCJSON_CONJUR_CA_CERT_FILE")]
    pub(crate) conjur_ca_cert_file: Option<String>,
    #[arg(
        long,
        env = "ENCJSON_KEYS_BOOTSTRAP_FROM_SOURCE",
        default_value_t = false
    )]
    pub(crate) keys_bootstrap_from_source: bool,
    #[arg(long, env = "ENCJSON_KEYS_BOOTSTRAP_STATUS", default_value = "active")]
    pub(crate) keys_bootstrap_status: String,
    #[arg(
        long,
        env = "ENCJSON_KEYS_BOOTSTRAP_NOTE",
        default_value = "bootstrap-from-source"
    )]
    pub(crate) keys_bootstrap_note: String,
}

#[derive(Debug, Clone, clap::ValueEnum)]
pub(crate) enum KeySourceCli {
    Env,
    Dir,
    #[value(name = "remote-mtls")]
    RemoteMtls,
    Vault,
    Conjur,
}

impl KeySourceCli {
    pub(crate) fn to_core_kind(&self) -> KeySourceKind {
        match self {
            KeySourceCli::Env => KeySourceKind::Env,
            KeySourceCli::Dir => KeySourceKind::Dir,
            KeySourceCli::RemoteMtls => KeySourceKind::RemoteMtls,
            KeySourceCli::Vault => KeySourceKind::Vault,
            KeySourceCli::Conjur => KeySourceKind::Conjur,
        }
    }
}
