mod tui_edit;
mod tui_register;

use base64::Engine as _;
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::{Shell, generate};
use serde_json::Value;
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Once;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::tui_edit::run_edit_ui;
use encjson_core::crypto::{
    HybridSecureBox, SecureBox, contains_api_version, generate_pair_consistent_key_pair,
    generate_v3_key_bundle,
};
use encjson_core::error::Error;
use encjson_core::json_utils::{
    TransformMode, dotenv_exports, env_exports, transform_json, transform_json_v3,
};
use encjson_core::key_sources::{
    CliKeyInput, ConjurConfig, KeySourceKind, KeySourceOptions, RemoteMtlsConfig, VaultConfig,
    derive_public_hex_from_private, load_from_cli, load_from_source, require_policy_context,
};
use encjson_core::key_store::{
    StoredKeyMaterial, default_key_dir, list_public_keys, load_private_key,
    load_stored_key_material, load_v3_key_bundle, save_private_key, save_v3_key_bundle,
};
use encjson_core::oidc_session;
use encjson_core::recipient::{LocalKeyFileV3, PrivateBundle, PublicBundle, RecipientMetadata};

type Result<T> = std::result::Result<T, Error>;

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum EncJsonApiVersion {
    #[value(name = "2.0")]
    V2_0,
    #[value(name = "3.0")]
    V3_0,
}

#[derive(Parser, Debug)]
#[command(
    name = "encjson",
    about = "Encrypted JSON helper using X25519 + XChaCha20-Poly1305",
    arg_required_else_help = true
)]
struct Cli {
    /// Print version and exit (like `encjson -v`)
    #[arg(short = 'v', long = "version")]
    version: bool,

    /// Enable debug tracing on stderr.
    #[arg(long, global = true)]
    debug: bool,

    /// Suppress all encjson warning messages on stderr.
    #[arg(long = "quiet", global = true, env = "ENCJSON_QUIET")]
    quiet: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Args, Debug, Clone, Default)]
struct ResolveArgs {
    /// Raw private key override
    #[arg(long, env = "ENCJSON_PRIVATE_KEY", help_heading = "Key Resolution")]
    private_key: Option<String>,

    /// Policy tenant
    #[arg(long, env = "ENCJSON_TENANT", help_heading = "Key Resolution")]
    tenant: Option<String>,

    /// Policy environment
    #[arg(
        long = "env",
        env = "ENCJSON_ENV",
        value_name = "ENV",
        help_heading = "Key Resolution"
    )]
    env_name: Option<String>,

    /// Require tenant+env when policy-backed source is used
    #[arg(
        long,
        env = "ENCJSON_SCOPE_REQUIRED",
        default_value_t = false,
        help_heading = "Key Resolution"
    )]
    scope_required: bool,

    /// Allow legacy inconsistent key pairs
    #[arg(
        long,
        env = "ENCJSON_LEGACY_MODE",
        default_value_t = true,
        help_heading = "Key Resolution"
    )]
    legacy_mode: bool,

    /// Resolve key material from provider instead of local store
    #[arg(
        long,
        env = "ENCJSON_KEY_SOURCE",
        value_enum,
        help_heading = "Key Resolution"
    )]
    key_source: Option<KeySourceCli>,
    /// Remote mTLS keys server URL
    #[arg(long, env = "ENCJSON_REMOTE_KEYS_URL", help_heading = "Key Resolution")]
    remote_keys_url: Option<String>,
    /// Client certificate for remote mTLS source
    #[arg(
        long,
        env = "ENCJSON_REMOTE_TLS_CERT_FILE",
        help_heading = "Key Resolution"
    )]
    remote_tls_cert_file: Option<PathBuf>,
    /// Client private key for remote mTLS source
    #[arg(
        long,
        env = "ENCJSON_REMOTE_TLS_KEY_FILE",
        help_heading = "Key Resolution"
    )]
    remote_tls_key_file: Option<PathBuf>,
    /// CA bundle for remote mTLS source
    #[arg(
        long,
        env = "ENCJSON_REMOTE_TLS_CA_FILE",
        help_heading = "Key Resolution"
    )]
    remote_tls_ca_file: Option<PathBuf>,
    /// HashiCorp Vault base URL
    #[arg(long, env = "ENCJSON_VAULT_ADDR", help_heading = "Key Resolution")]
    vault_addr: Option<String>,
    /// Vault secret path
    #[arg(long, env = "ENCJSON_VAULT_PATH", help_heading = "Key Resolution")]
    vault_path: Option<String>,
    /// Vault token
    #[arg(long, env = "ENCJSON_VAULT_TOKEN", help_heading = "Key Resolution")]
    vault_token: Option<String>,
    /// Vault field containing public key
    #[arg(
        long,
        env = "ENCJSON_VAULT_PUBLIC_FIELD",
        help_heading = "Key Resolution"
    )]
    vault_public_field: Option<String>,
    /// Vault field containing private key
    #[arg(
        long,
        env = "ENCJSON_VAULT_PRIVATE_FIELD",
        help_heading = "Key Resolution"
    )]
    vault_private_field: Option<String>,
    /// CyberArk Conjur appliance URL
    #[arg(
        long,
        env = "ENCJSON_CONJUR_APPLIANCE_URL",
        help_heading = "Key Resolution"
    )]
    conjur_appliance_url: Option<String>,
    /// Conjur account
    #[arg(long, env = "ENCJSON_CONJUR_ACCOUNT", help_heading = "Key Resolution")]
    conjur_account: Option<String>,
    /// Conjur authn login
    #[arg(
        long,
        env = "ENCJSON_CONJUR_AUTHN_LOGIN",
        help_heading = "Key Resolution"
    )]
    conjur_authn_login: Option<String>,
    /// Conjur authn API key
    #[arg(
        long,
        env = "ENCJSON_CONJUR_AUTHN_API_KEY",
        help_heading = "Key Resolution"
    )]
    conjur_authn_api_key: Option<String>,
    /// Conjur variable id containing public key
    #[arg(
        long,
        env = "ENCJSON_CONJUR_PUBLIC_VARIABLE_ID",
        help_heading = "Key Resolution"
    )]
    conjur_public_variable_id: Option<String>,
    /// Conjur variable id containing private key
    #[arg(
        long,
        env = "ENCJSON_CONJUR_PRIVATE_VARIABLE_ID",
        help_heading = "Key Resolution"
    )]
    conjur_private_variable_id: Option<String>,
    /// CA bundle for Conjur TLS
    #[arg(
        long,
        env = "ENCJSON_CONJUR_CA_CERT_FILE",
        help_heading = "Key Resolution"
    )]
    conjur_ca_cert_file: Option<PathBuf>,
}

#[derive(Clone, Debug, ValueEnum)]
enum OutputFormat {
    /// JSON (default) - decrypted JSON to stdout or back to file with -w
    Json,
    /// Shell `export` lines - suitable for `eval "$(encjson decrypt -o shell ...)"`,
    Shell,
    /// .env format - lines like `VAR="value"`
    DotEnv,
}

#[derive(Clone, Debug, ValueEnum)]
enum KeySourceCli {
    Env,
    Dir,
    #[value(name = "remote-mtls")]
    RemoteMtls,
    Vault,
    Conjur,
}

impl KeySourceCli {
    fn to_core_kind(&self) -> KeySourceKind {
        match self {
            KeySourceCli::Env => KeySourceKind::Env,
            KeySourceCli::Dir => KeySourceKind::Dir,
            KeySourceCli::RemoteMtls => KeySourceKind::RemoteMtls,
            KeySourceCli::Vault => KeySourceKind::Vault,
            KeySourceCli::Conjur => KeySourceKind::Conjur,
        }
    }
}

#[derive(Clone, Debug, Default)]
struct KeySourceRuntimeConfig {
    key_source: Option<KeySourceCli>,
    remote_keys_url: Option<String>,
    remote_tls_cert_file: Option<PathBuf>,
    remote_tls_key_file: Option<PathBuf>,
    remote_tls_ca_file: Option<PathBuf>,
    vault_addr: Option<String>,
    vault_path: Option<String>,
    vault_token: Option<String>,
    vault_public_field: Option<String>,
    vault_private_field: Option<String>,
    conjur_appliance_url: Option<String>,
    conjur_account: Option<String>,
    conjur_authn_login: Option<String>,
    conjur_authn_api_key: Option<String>,
    conjur_public_variable_id: Option<String>,
    conjur_private_variable_id: Option<String>,
    conjur_ca_cert_file: Option<PathBuf>,
}

fn source_cfg_from_resolve_args(args: &ResolveArgs) -> KeySourceRuntimeConfig {
    KeySourceRuntimeConfig {
        key_source: args.key_source.clone(),
        remote_keys_url: args.remote_keys_url.clone(),
        remote_tls_cert_file: args.remote_tls_cert_file.clone(),
        remote_tls_key_file: args.remote_tls_key_file.clone(),
        remote_tls_ca_file: args.remote_tls_ca_file.clone(),
        vault_addr: args.vault_addr.clone(),
        vault_path: args.vault_path.clone(),
        vault_token: args.vault_token.clone(),
        vault_public_field: args.vault_public_field.clone(),
        vault_private_field: args.vault_private_field.clone(),
        conjur_appliance_url: args.conjur_appliance_url.clone(),
        conjur_account: args.conjur_account.clone(),
        conjur_authn_login: args.conjur_authn_login.clone(),
        conjur_authn_api_key: args.conjur_authn_api_key.clone(),
        conjur_public_variable_id: args.conjur_public_variable_id.clone(),
        conjur_private_variable_id: args.conjur_private_variable_id.clone(),
        conjur_ca_cert_file: args.conjur_ca_cert_file.clone(),
    }
}

fn validate_scope_args(args: &ResolveArgs) -> Result<()> {
    if args.scope_required {
        require_policy_context(args.tenant.as_deref(), args.env_name.as_deref())
            .map_err(|e| Error::Http(e.to_string()))?;
    }
    Ok(())
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate shell completion script
    Completion {
        #[arg(value_enum)]
        shell: Shell,
    },

    /// Generate a new public/private key pair
    Init {
        /// Optional key directory (overrides ENCJSON_KEYDIR, default is OS-specific via dirs)
        #[arg(short, long, env = "ENCJSON_KEYDIR")]
        keydir: Option<PathBuf>,

        /// Key/API version to initialize
        #[arg(long, value_enum, default_value_t = EncJsonApiVersion::V3_0)]
        api: EncJsonApiVersion,

        /// Also create `env.secured.json` in current directory with generated recipient metadata
        #[arg(long)]
        create_file: bool,
    },

    /// List local public keys
    #[command(alias = "ls")]
    List {
        /// Optional key directory (overrides ENCJSON_KEYDIR, default is OS-specific via dirs)
        #[arg(short = 'k', long, env = "ENCJSON_KEYDIR")]
        keydir: Option<PathBuf>,
    },

    /// Show key info for a secured JSON file (_public_key/_recipient_key + resolved key material)
    Info {
        #[command(flatten)]
        resolve: ResolveArgs,

        /// Input file
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Optional positional input path
        #[arg(value_name = "INPUT", conflicts_with = "file")]
        input: Option<PathBuf>,

        /// Optional key directory (overrides ENCJSON_KEYDIR, default is OS-specific via dirs)
        #[arg(
            short = 'k',
            long,
            env = "ENCJSON_KEYDIR",
            help_heading = "Key Resolution"
        )]
        keydir: Option<PathBuf>,
    },

    /// Encrypt all string values in a JSON file
    Encrypt {
        #[command(flatten)]
        resolve: ResolveArgs,

        /// Input file (otherwise reads from stdin)
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Optional positional input (use "-" for stdin)
        #[arg(value_name = "INPUT", conflicts_with = "file")]
        input: Option<PathBuf>,

        /// Overwrite the input file in place
        #[arg(short = 'w', long)]
        write: bool,

        /// Optional key directory (overrides ENCJSON_KEYDIR, default is OS-specific via dirs)
        #[arg(
            short = 'k',
            long,
            env = "ENCJSON_KEYDIR",
            help_heading = "Key Resolution"
        )]
        keydir: Option<PathBuf>,
    },

    /// Decrypt EncJson strings in a JSON file
    ///
    /// By default, prints decrypted JSON to stdout. The -o/--output flag can change the format:
    ///
    ///   -o json     (default)  -> decrypted JSON
    ///   -o shell               -> shell export lines
    ///   -o dot-env             -> .env file format
    Decrypt {
        #[command(flatten)]
        resolve: ResolveArgs,

        /// Input file (otherwise reads from stdin).
        ///
        /// You can also pass "-" as a positional argument to read from stdin:
        ///   encjson decrypt -o shell -
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Optional positional input (use "-" for stdin)
        #[arg(value_name = "INPUT", conflicts_with = "file")]
        input: Option<PathBuf>,

        /// Overwrite the input file in place (only valid with -o json)
        #[arg(short = 'w', long)]
        write: bool,

        /// Optional key directory (overrides ENCJSON_KEYDIR, default is OS-specific via dirs)
        #[arg(
            short = 'k',
            long,
            env = "ENCJSON_KEYDIR",
            help_heading = "Key Resolution"
        )]
        keydir: Option<PathBuf>,

        /// Output format (json / shell / dot-env)
        #[arg(short = 'o', long = "output", value_enum, default_value_t = OutputFormat::Json)]
        output: OutputFormat,

        /// Return only one concrete value from `environment` / `env` object (raw value to stdout)
        #[arg(long = "env-name", value_name = "NAME", conflicts_with = "write")]
        env_value_name: Option<String>,
    },

    /// Manage virtual filesystem assets stored in JSON bundles
    Assets {
        #[command(subcommand)]
        command: AssetsCommand,
    },

    /// (Deprecated) shortcut for `decrypt -o shell`
    Env {
        #[command(flatten)]
        resolve: ResolveArgs,

        /// Input file (otherwise reads from stdin)
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Optional key directory (overrides ENCJSON_KEYDIR, default is OS-specific via dirs)
        #[arg(
            short = 'k',
            long,
            env = "ENCJSON_KEYDIR",
            help_heading = "Key Resolution"
        )]
        keydir: Option<PathBuf>,
    },

    /// Decrypt file and render Kubernetes Secret YAML (with optional sidecar schema transforms)
    #[command(name = "render-k8s-secret")]
    RenderK8sSecret {
        #[command(flatten)]
        resolve: ResolveArgs,

        /// Input file
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Optional positional input path
        #[arg(value_name = "INPUT", conflicts_with = "file")]
        input: Option<PathBuf>,

        /// Secret name (required for single-secret mode)
        #[arg(long)]
        name: Option<String>,

        /// Optional namespace
        #[arg(long)]
        namespace: Option<String>,

        /// Kubernetes Secret type (default: kubernetes.io/tls)
        #[arg(long, value_enum, default_value_t = K8sSecretType::KubernetesIoTls)]
        secret_type: K8sSecretType,

        /// Optional mapping ENV_KEY=secretKey (can be repeated)
        #[arg(long = "from-env", action = clap::ArgAction::Append)]
        from_env: Vec<String>,

        /// Optional mapping ENV_KEY=secretName/secretKey (can be repeated, multi-secret mode)
        #[arg(long = "from-env-secret", action = clap::ArgAction::Append)]
        from_env_secret: Vec<String>,

        /// Optional output file (default stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Optional key directory (overrides ENCJSON_KEYDIR, default is OS-specific via dirs)
        #[arg(
            short = 'k',
            long,
            env = "ENCJSON_KEYDIR",
            help_heading = "Key Resolution"
        )]
        keydir: Option<PathBuf>,
    },

    /// Render Secret with runtime key material:
    /// - api=2.0 => public/private pair from `_public_key`
    /// - api=3.0 => expanded `ENCJSON_*` env-style fields from `_recipient_key`
    #[command(name = "render-k8s-pair-secret")]
    RenderK8sPairSecret {
        #[command(flatten)]
        resolve: ResolveArgs,

        /// Input file
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Optional positional input path
        #[arg(value_name = "INPUT", conflicts_with = "file")]
        input: Option<PathBuf>,

        /// Secret name
        #[arg(long)]
        name: String,

        /// Optional namespace
        #[arg(long)]
        namespace: Option<String>,

        /// Public key field name in data (api=2.0 only)
        #[arg(long, default_value = "public-key")]
        public_key_name: String,

        /// Private key field name in data (api=2.0 only)
        #[arg(long, default_value = "private-key")]
        private_key_name: String,

        /// Optional output file (default stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Optional key directory (overrides ENCJSON_KEYDIR, default is OS-specific via dirs)
        #[arg(
            short = 'k',
            long,
            env = "ENCJSON_KEYDIR",
            help_heading = "Key Resolution"
        )]
        keydir: Option<PathBuf>,
    },

    /// Edit key/value pairs in `environment` or `env` using a terminal UI
    Edit {
        /// Input file (required for UI editing)
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Optional positional input path
        #[arg(value_name = "INPUT", conflicts_with = "file")]
        input: Option<PathBuf>,

        /// Optional key directory (overrides ENCJSON_KEYDIR, default is OS-specific via dirs)
        #[arg(short = 'k', long, env = "ENCJSON_KEYDIR")]
        keydir: Option<PathBuf>,

        /// Launch terminal UI (default)
        #[arg(long)]
        ui: bool,

        /// (Reserved) launch web UI
        #[arg(long, conflicts_with = "ui")]
        web: bool,
    },

    /// Set (upsert) a key in `environment`/`env` for CI/CD automation
    Set {
        #[command(flatten)]
        resolve: ResolveArgs,

        /// Input file (required for reliable automation)
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Environment key to upsert
        #[arg(value_name = "KEY")]
        key: String,

        /// Value to store (string by default)
        #[arg(value_name = "VALUE")]
        value: String,

        /// Parse VALUE as JSON (number/bool/null/object/array)
        #[arg(long)]
        json_value: bool,

        /// Overwrite the input file in place
        #[arg(short = 'w', long)]
        write: bool,

        /// Optional key directory (overrides ENCJSON_KEYDIR, default is OS-specific via dirs)
        #[arg(
            short = 'k',
            long,
            env = "ENCJSON_KEYDIR",
            help_heading = "Key Resolution"
        )]
        keydir: Option<PathBuf>,
    },

    /// Remove a key from `environment`/`env` for CI/CD automation
    Unset {
        #[command(flatten)]
        resolve: ResolveArgs,

        /// Input file (required for reliable automation)
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Environment key to remove
        #[arg(value_name = "KEY")]
        key: String,

        /// Overwrite the input file in place
        #[arg(short = 'w', long)]
        write: bool,

        /// Optional key directory (overrides ENCJSON_KEYDIR, default is OS-specific via dirs)
        #[arg(
            short = 'k',
            long,
            env = "ENCJSON_KEYDIR",
            help_heading = "Key Resolution"
        )]
        keydir: Option<PathBuf>,
    },

    /// Rotate file encryption key (decrypt -> replace _public_key -> encrypt)
    #[command(name = "rotate-key", alias = "rekey", alias = "migrate-key")]
    RotateKey {
        #[command(flatten)]
        resolve: ResolveArgs,

        /// Input file
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Optional positional input path
        #[arg(value_name = "INPUT", conflicts_with = "file")]
        input: Option<PathBuf>,

        /// Overwrite the input file in place
        #[arg(short = 'w', long)]
        write: bool,

        /// Existing v3 recipient key id to use (api=3.0 only)
        #[arg(long)]
        recipient: Option<String>,

        /// Optional key directory (overrides ENCJSON_KEYDIR, default is OS-specific via dirs)
        #[arg(
            short = 'k',
            long,
            env = "ENCJSON_KEYDIR",
            help_heading = "Key Resolution"
        )]
        keydir: Option<PathBuf>,
    },

    /// Explicitly migrate secured file format (e.g. api=2.0 -> api=3.0)
    #[command(name = "migrate-format")]
    MigrateFormat {
        #[command(flatten)]
        resolve: ResolveArgs,

        /// Input file
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Optional positional input path
        #[arg(value_name = "INPUT", conflicts_with = "file")]
        input: Option<PathBuf>,

        /// Target API version
        #[arg(long, value_enum)]
        to: EncJsonApiVersion,

        /// Target recipient key id for api=3.0 (if omitted, a new v3 key bundle is generated)
        #[arg(long)]
        recipient: Option<String>,

        /// Overwrite the input file in place
        #[arg(short = 'w', long)]
        write: bool,

        /// Optional key directory (overrides ENCJSON_KEYDIR, default is OS-specific via dirs)
        #[arg(
            short = 'k',
            long,
            env = "ENCJSON_KEYDIR",
            help_heading = "Key Resolution"
        )]
        keydir: Option<PathBuf>,
    },

    /// Register local keys to keys server (pending approval)
    Register {
        /// Optional key reference to register explicitly (legacy public_hex or v3 key_id)
        #[arg(value_name = "KEY_REF")]
        public_hex: Option<String>,

        /// Keys server URL (overrides ENCJSON_KEYS_URL)
        #[arg(long, env = "ENCJSON_KEYS_URL")]
        keys_url: Option<String>,

        /// Access token (overrides ENCJSON_ACCESS_TOKEN)
        #[arg(long, env = "ENCJSON_ACCESS_TOKEN")]
        token: Option<String>,

        /// Tenant name (required for explicit key reference)
        #[arg(long)]
        tenant: Option<String>,

        /// Note (required for explicit key reference)
        #[arg(long)]
        note: Option<String>,

        /// Tags (optional, can be repeated)
        #[arg(long, action = clap::ArgAction::Append)]
        tag: Vec<String>,

        /// Optional key directory (overrides ENCJSON_KEYDIR, default is OS-specific via dirs)
        #[arg(short = 'k', long, env = "ENCJSON_KEYDIR")]
        keydir: Option<PathBuf>,

        /// Private key loaded from file (preferred over raw --private-key)
        #[arg(long)]
        private_key_file: Option<PathBuf>,

        /// Private key loaded from file descriptor (reads /dev/fd/<N> on Unix)
        #[arg(long)]
        private_key_fd: Option<i32>,

        /// Read private key from stdin
        #[arg(long)]
        private_key_stdin: bool,

        /// Allow insecure raw private key input via --private-key
        #[arg(long, default_value_t = false)]
        allow_insecure_cli_private_key: bool,
    },

    /// Sync private keys from the keys server into the local key directory
    Sync {
        /// Input file (reads _public_key or _recipient_key)
        #[arg(short, long, conflicts_with = "key")]
        file: Option<PathBuf>,

        /// Key reference to sync explicitly (legacy public_hex or v3 key_id)
        #[arg(long, conflicts_with = "file")]
        key: Option<String>,

        /// Keys server URL (overrides ENCJSON_KEYS_URL)
        #[arg(long, env = "ENCJSON_KEYS_URL")]
        keys_url: Option<String>,

        /// Access token (overrides ENCJSON_ACCESS_TOKEN)
        #[arg(long, env = "ENCJSON_ACCESS_TOKEN")]
        token: Option<String>,

        /// Optional key directory (overrides ENCJSON_KEYDIR, default is OS-specific via dirs)
        #[arg(short = 'k', long, env = "ENCJSON_KEYDIR")]
        keydir: Option<PathBuf>,
    },

    /// Sync key files from one local directory to another (copy only missing filenames)
    #[command(name = "sync-dir")]
    SyncDir {
        /// Source directory with key files
        #[arg(long, required = true)]
        src_dir: PathBuf,

        /// Destination directory with key files
        #[arg(long, required = true)]
        dst_dir: PathBuf,

        /// Show what would be copied without writing files
        #[arg(long, default_value_t = false)]
        dry_run: bool,
    },

    Login {
        #[arg(long, default_value_t = false)]
        insecure: bool,

        #[arg(long, required = true)]
        url: String,
        #[arg(long, default_value = "cli-tools")]
        client: String,
        #[arg(long, default_value = "8181")]
        port: u16,
        #[arg(long, default_value = "default")]
        server: String,
    },
    Logout {
        #[arg(long)]
        server: Option<String>,
        #[arg(long)]
        all: bool,
    },
    Sessions {
        #[command(subcommand)]
        command: SessionsCommand,
    },
    Status,
}

#[derive(Subcommand, Debug)]
enum AssetsCommand {
    /// List files stored in assets bundle
    List {
        #[command(flatten)]
        resolve: ResolveArgs,

        /// Input file
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Optional positional input path
        #[arg(value_name = "INPUT", conflicts_with = "file")]
        input: Option<PathBuf>,

        /// Optional key directory (overrides ENCJSON_KEYDIR, default is OS-specific via dirs)
        #[arg(
            short = 'k',
            long,
            env = "ENCJSON_KEYDIR",
            help_heading = "Key Resolution"
        )]
        keydir: Option<PathBuf>,
    },

    /// Get one file from assets bundle
    Get {
        #[command(flatten)]
        resolve: ResolveArgs,

        /// Input file
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Optional positional input path
        #[arg(value_name = "INPUT", conflicts_with = "file")]
        input: Option<PathBuf>,

        /// Asset path inside virtual filesystem
        #[arg(long)]
        path: String,

        /// Print base64 value instead of raw bytes
        #[arg(long, default_value_t = false)]
        base64: bool,

        /// Optional output file (default stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Optional key directory (overrides ENCJSON_KEYDIR, default is OS-specific via dirs)
        #[arg(
            short = 'k',
            long,
            env = "ENCJSON_KEYDIR",
            help_heading = "Key Resolution"
        )]
        keydir: Option<PathBuf>,
    },

    /// Export all files from assets bundle into directory
    Export {
        #[command(flatten)]
        resolve: ResolveArgs,

        /// Input file
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Optional positional input path
        #[arg(value_name = "INPUT", conflicts_with = "file")]
        input: Option<PathBuf>,

        /// Output directory
        #[arg(long)]
        out_dir: PathBuf,

        /// Overwrite existing files
        #[arg(long, default_value_t = false)]
        overwrite: bool,

        /// Optional key directory (overrides ENCJSON_KEYDIR, default is OS-specific via dirs)
        #[arg(
            short = 'k',
            long,
            env = "ENCJSON_KEYDIR",
            help_heading = "Key Resolution"
        )]
        keydir: Option<PathBuf>,
    },

    /// Import files from directory into assets bundle
    Import {
        #[command(flatten)]
        resolve: ResolveArgs,

        /// Source directory to pack
        #[arg(long)]
        from_dir: PathBuf,

        /// Output JSON file
        #[arg(short, long)]
        output: PathBuf,

        /// Create or update secured assets bundle
        #[arg(long, conflicts_with = "unsecured")]
        secured: bool,

        /// Create or update unsecured assets bundle
        #[arg(long, conflicts_with = "secured")]
        unsecured: bool,

        /// Public key for new secured bundle
        #[arg(long)]
        public_key: Option<String>,

        /// Optional key directory (overrides ENCJSON_KEYDIR, default is OS-specific via dirs)
        #[arg(
            short = 'k',
            long,
            env = "ENCJSON_KEYDIR",
            help_heading = "Key Resolution"
        )]
        keydir: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
enum SessionsCommand {
    #[command(alias = "ls")]
    List,
    Use {
        #[arg(value_name = "SERVER")]
        server: String,
    },
}

static QUIET_WARNINGS: AtomicBool = AtomicBool::new(false);

fn emit_warning(message: impl std::fmt::Display) {
    if !QUIET_WARNINGS.load(Ordering::Relaxed) {
        eprintln!("Warning: {message}");
    }
}

fn warn_legacy_mlkem_private_key(bundle: &LocalKeyFileV3) {
    let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(&bundle.mlkem768.private_b64)
    else {
        return;
    };

    if bytes.len() == 2400 {
        emit_warning(
            "legacy ML-KEM expanded private key detected; run `encjson rotate-key -f <file> -w` to migrate to the seed format.",
        );
    }
}

fn load_v3_key_bundle_cli(key_id: &str, keydir: Option<&Path>) -> Result<LocalKeyFileV3> {
    let bundle = load_v3_key_bundle(key_id, keydir)?;
    warn_legacy_mlkem_private_key(&bundle);
    Ok(bundle)
}

fn main() {
    let cli = Cli::parse();
    QUIET_WARNINGS.store(cli.quiet, Ordering::Relaxed);
    if cli.debug {
        init_tracing(true);
    }

    // Support `encjson -v`
    if cli.version {
        println!("encjson {} (rust)", env!("CARGO_PKG_VERSION"));
        return;
    }

    if let Some(cmd) = cli.command
        && let Err(e) = run(cmd, cli.debug)
    {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

fn current_bin_name(default_name: &str) -> String {
    std::env::args_os()
        .next()
        .as_deref()
        .and_then(|arg0| Path::new(arg0).file_name())
        .and_then(OsStr::to_str)
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| default_name.to_string())
}

fn run(command: Commands, debug: bool) -> Result<()> {
    match command {
        Commands::Completion { shell } => {
            let mut cmd = Cli::command();
            let bin_name = current_bin_name("encjson");
            generate(shell, &mut cmd, bin_name, &mut io::stdout());
            Ok(())
        }
        Commands::Init {
            keydir,
            api,
            create_file,
        } => cmd_init(keydir, api, create_file),
        Commands::List { keydir } => cmd_list(keydir),
        Commands::Info {
            resolve,
            file,
            input,
            keydir,
        } => {
            validate_scope_args(&resolve)?;
            let source_cfg = source_cfg_from_resolve_args(&resolve);
            let ctx = ResolveCtx {
                keydir,
                private_key: resolve.private_key.as_deref(),
                source_cfg: &source_cfg,
                legacy_mode: resolve.legacy_mode,
            };
            cmd_info(FileInput { file, input }, &ctx)
        }
        Commands::Encrypt {
            resolve,
            file,
            input,
            write,
            keydir,
        } => {
            validate_scope_args(&resolve)?;
            let source_cfg = source_cfg_from_resolve_args(&resolve);
            let ctx = ResolveCtx {
                keydir,
                private_key: resolve.private_key.as_deref(),
                source_cfg: &source_cfg,
                legacy_mode: resolve.legacy_mode,
            };
            cmd_encrypt(FileInput { file, input }, write, &ctx, true)
        }
        Commands::Decrypt {
            resolve,
            file,
            input,
            write,
            keydir,
            output,
            env_value_name,
        } => {
            validate_scope_args(&resolve)?;
            let source_cfg = source_cfg_from_resolve_args(&resolve);
            let ctx = ResolveCtx {
                keydir,
                private_key: resolve.private_key.as_deref(),
                source_cfg: &source_cfg,
                legacy_mode: resolve.legacy_mode,
            };
            cmd_decrypt(
                FileInput { file, input },
                write,
                output,
                debug,
                env_value_name,
                &ctx,
                true,
            )
        }
        Commands::Env {
            resolve,
            file,
            keydir,
        } => {
            validate_scope_args(&resolve)?;
            let source_cfg = source_cfg_from_resolve_args(&resolve);
            let ctx = ResolveCtx {
                keydir,
                private_key: resolve.private_key.as_deref(),
                source_cfg: &source_cfg,
                legacy_mode: resolve.legacy_mode,
            };
            cmd_decrypt(
                FileInput { file, input: None },
                false,
                OutputFormat::Shell,
                debug,
                None,
                &ctx,
                false,
            )
        }
        Commands::Assets { command } => cmd_assets(command),
        Commands::RenderK8sSecret {
            resolve,
            file,
            input,
            name,
            namespace,
            secret_type,
            from_env,
            from_env_secret,
            output,
            keydir,
        } => {
            validate_scope_args(&resolve)?;
            let source_cfg = source_cfg_from_resolve_args(&resolve);
            let ctx = ResolveCtx {
                keydir,
                private_key: resolve.private_key.as_deref(),
                source_cfg: &source_cfg,
                legacy_mode: resolve.legacy_mode,
            };
            cmd_render_k8s_secret(
                FileInput { file, input },
                RenderK8sSecretOptions {
                    name,
                    namespace,
                    secret_type,
                    from_env,
                    from_env_secret,
                    output,
                },
                &ctx,
            )
        }
        Commands::RenderK8sPairSecret {
            resolve,
            file,
            input,
            name,
            namespace,
            public_key_name,
            private_key_name,
            output,
            keydir,
        } => {
            validate_scope_args(&resolve)?;
            let source_cfg = source_cfg_from_resolve_args(&resolve);
            let ctx = ResolveCtx {
                keydir,
                private_key: resolve.private_key.as_deref(),
                source_cfg: &source_cfg,
                legacy_mode: resolve.legacy_mode,
            };
            cmd_render_k8s_pair_secret(
                FileInput { file, input },
                name,
                namespace,
                public_key_name,
                private_key_name,
                output,
                &ctx,
            )
        }
        Commands::Edit {
            file,
            input,
            keydir,
            ui,
            web,
        } => cmd_edit(file, input, keydir, ui, web),
        Commands::Set {
            resolve,
            file,
            key,
            value,
            json_value,
            write,
            keydir,
        } => {
            validate_scope_args(&resolve)?;
            let source_cfg = source_cfg_from_resolve_args(&resolve);
            let ctx = ResolveCtx {
                keydir,
                private_key: resolve.private_key.as_deref(),
                source_cfg: &source_cfg,
                legacy_mode: resolve.legacy_mode,
            };
            cmd_set(
                FileInput { file, input: None },
                key,
                value,
                json_value,
                write,
                &ctx,
            )
        }
        Commands::Unset {
            resolve,
            file,
            key,
            write,
            keydir,
        } => {
            validate_scope_args(&resolve)?;
            let source_cfg = source_cfg_from_resolve_args(&resolve);
            let ctx = ResolveCtx {
                keydir,
                private_key: resolve.private_key.as_deref(),
                source_cfg: &source_cfg,
                legacy_mode: resolve.legacy_mode,
            };
            cmd_unset(FileInput { file, input: None }, key, write, &ctx)
        }
        Commands::RotateKey {
            resolve,
            file,
            input,
            write,
            recipient,
            keydir,
        } => {
            validate_scope_args(&resolve)?;
            let source_cfg = source_cfg_from_resolve_args(&resolve);
            let ctx = ResolveCtx {
                keydir,
                private_key: resolve.private_key.as_deref(),
                source_cfg: &source_cfg,
                legacy_mode: resolve.legacy_mode,
            };
            cmd_rekey(FileInput { file, input }, recipient.as_deref(), write, &ctx)
        }
        Commands::MigrateFormat {
            resolve,
            file,
            input,
            to,
            recipient,
            write,
            keydir,
        } => {
            validate_scope_args(&resolve)?;
            let source_cfg = source_cfg_from_resolve_args(&resolve);
            let ctx = ResolveCtx {
                keydir,
                private_key: resolve.private_key.as_deref(),
                source_cfg: &source_cfg,
                legacy_mode: resolve.legacy_mode,
            };
            cmd_migrate_format(
                FileInput { file, input },
                to,
                recipient.as_deref(),
                write,
                &ctx,
            )
        }
        Commands::Register {
            public_hex,
            keys_url,
            token,
            tenant,
            note,
            tag,
            keydir,
            private_key_file,
            private_key_fd,
            private_key_stdin,
            allow_insecure_cli_private_key,
        } => {
            let source_cfg = KeySourceRuntimeConfig::default();
            let ctx = ResolveCtx {
                keydir,
                private_key: None,
                source_cfg: &source_cfg,
                legacy_mode: true,
            };
            cmd_register(
                RegisterCommand {
                    public_hex,
                    keys_url,
                    token,
                    tenant,
                    note,
                    tags: tag,
                    private_key_file,
                    private_key_fd,
                    private_key_stdin,
                    allow_insecure_cli_private_key,
                },
                &ctx,
            )
        }
        Commands::Sync {
            file,
            key,
            keys_url,
            token,
            keydir,
        } => cmd_sync(file, key, keys_url, token, keydir),
        Commands::SyncDir {
            src_dir,
            dst_dir,
            dry_run,
        } => cmd_sync_dir(src_dir, dst_dir, dry_run),
        Commands::Login {
            insecure,
            url,
            client,
            port,
            server,
        } => run_async(oidc_session::handle_login(
            "encjson", &url, &client, port, &server, insecure,
        )),
        Commands::Logout { server, all } => {
            if all {
                oidc_session::delete_session("encjson", None)
                    .map_err(|e| Error::Http(e.to_string()))?;
                println!("All sessions removed.");
            } else {
                let target = server.as_deref();
                oidc_session::delete_session("encjson", target)
                    .map_err(|e| Error::Http(e.to_string()))?;
                println!("Session removed.");
            }
            Ok(())
        }
        Commands::Sessions { command } => handle_sessions(&command),
        Commands::Status => handle_status(),
    }
}

fn run_async<F>(future: F) -> Result<()>
where
    F: std::future::Future<Output = anyhow::Result<()>>,
{
    let runtime = tokio::runtime::Runtime::new().map_err(|e| Error::Http(e.to_string()))?;
    runtime
        .block_on(future)
        .map_err(|e| Error::Http(e.to_string()))
}

fn handle_sessions(command: &SessionsCommand) -> Result<()> {
    match command {
        SessionsCommand::List => {
            let config =
                oidc_session::load_sessions("encjson").map_err(|e| Error::Http(e.to_string()))?;
            if config.servers.is_empty() {
                println!("No sessions found. Run 'encjson login' first.");
                return Ok(());
            }
            println!("Active: {}", config.active);
            for (name, session) in &config.servers {
                let status = if name == &config.active { "*" } else { " " };
                println!(
                    "{status} {name} -> {} (expires {})",
                    session.base_url,
                    session.expires_at.format("%Y-%m-%d %H:%M:%S")
                );
            }
        }
        SessionsCommand::Use { server } => {
            let mut config =
                oidc_session::load_sessions("encjson").map_err(|e| Error::Http(e.to_string()))?;
            if !config.servers.contains_key(server) {
                return Err(Error::Http(format!("Session '{}' not found", server)));
            }
            config.active = server.to_string();
            oidc_session::save_sessions("encjson", &config)
                .map_err(|e| Error::Http(e.to_string()))?;
            println!("Active session set to '{}'", server);
        }
    }
    Ok(())
}

fn handle_status() -> Result<()> {
    let config = oidc_session::load_sessions("encjson").map_err(|e| Error::Http(e.to_string()))?;
    let Some(session) = config.servers.get(&config.active) else {
        println!("Not logged in. Run 'encjson login --url <SERVER_URL>' first.");
        return Ok(());
    };
    let valid = oidc_session::is_session_valid(session);
    let expires_in = (session.expires_at - chrono::Utc::now()).num_seconds();
    println!(
        "Status: {}",
        if valid {
            "✓ Logged in"
        } else {
            "✗ Token expired"
        }
    );
    println!("Active server: {}", config.active);
    println!("Server URL: {}", session.base_url);
    println!(
        "Token expires in: {} seconds ({} minutes)",
        expires_in,
        expires_in / 60
    );
    println!(
        "Session created: {}",
        session.created_at.format("%Y-%m-%d %H:%M:%S")
    );
    if let Some(email) = &session.user_email {
        println!("User: {}", email);
    }
    if !session.user_groups.is_empty() {
        println!("Groups: {}", session.user_groups.join(", "));
    }
    if !valid {
        println!("\nToken expired. Run 'encjson login' to re-authenticate.");
    }
    Ok(())
}

#[derive(serde::Deserialize)]
struct KeysKey {
    public_hex: String,
    key_id: Option<String>,
    bundle_version: Option<i32>,
}

#[derive(serde::Deserialize)]
struct KeysRequest {
    public_hex: String,
    key_id: Option<String>,
}

#[derive(serde::Serialize)]
struct RegisterPayloadLegacy {
    public_hex: String,
    private_hex: String,
    tenant: String,
    note: String,
    tags: Vec<String>,
}

#[derive(serde::Serialize)]
struct RegisterPayloadV3 {
    key_id: String,
    version: u32,
    algorithm: String,
    public_bundle: PublicBundle,
    private_bundle: PrivateBundle,
    tenant: String,
    note: String,
    tags: Vec<String>,
}

#[derive(serde::Serialize)]
#[serde(untagged)]
enum RegisterPayload {
    Legacy(RegisterPayloadLegacy),
    V3(RegisterPayloadV3),
}

#[derive(serde::Deserialize)]
struct KeysPrivateKey {
    public_hex: String,
    private_hex: String,
}

#[derive(serde::Deserialize)]
struct KeysBundle {
    key_id: String,
    version: u32,
    algorithm: String,
    public_bundle: PublicBundle,
    private_bundle: PrivateBundle,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct K8sSecretManifest {
    #[serde(rename = "apiVersion")]
    api_version: String,
    kind: String,
    metadata: K8sMetadata,
    #[serde(rename = "type")]
    secret_type: String,
    data: BTreeMap<String, String>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct K8sMetadata {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    namespace: Option<String>,
}

fn build_key_source_options(
    source_cfg: &KeySourceRuntimeConfig,
    keydir: Option<&std::path::Path>,
) -> Result<Option<KeySourceOptions>> {
    let Some(kind) = source_cfg.key_source.as_ref() else {
        return Ok(None);
    };

    let remote_mtls = match kind {
        KeySourceCli::RemoteMtls => Some(RemoteMtlsConfig {
            url: source_cfg
                .remote_keys_url
                .clone()
                .ok_or_else(|| Error::Http("missing --remote-keys-url".to_string()))?,
            client_cert_path: source_cfg
                .remote_tls_cert_file
                .as_ref()
                .ok_or_else(|| Error::Http("missing --remote-tls-cert-file".to_string()))?
                .display()
                .to_string(),
            client_key_path: source_cfg
                .remote_tls_key_file
                .as_ref()
                .ok_or_else(|| Error::Http("missing --remote-tls-key-file".to_string()))?
                .display()
                .to_string(),
            ca_cert_path: source_cfg
                .remote_tls_ca_file
                .as_ref()
                .map(|p| p.display().to_string()),
        }),
        _ => None,
    };

    let vault = match kind {
        KeySourceCli::Vault => Some(VaultConfig {
            addr: source_cfg
                .vault_addr
                .clone()
                .ok_or_else(|| Error::Http("missing --vault-addr".to_string()))?,
            path: source_cfg
                .vault_path
                .clone()
                .ok_or_else(|| Error::Http("missing --vault-path".to_string()))?,
            token: source_cfg
                .vault_token
                .clone()
                .ok_or_else(|| Error::Http("missing --vault-token".to_string()))?,
            public_field: source_cfg.vault_public_field.clone(),
            private_field: source_cfg.vault_private_field.clone(),
        }),
        _ => None,
    };

    let conjur =
        match kind {
            KeySourceCli::Conjur => Some(ConjurConfig {
                appliance_url: source_cfg
                    .conjur_appliance_url
                    .clone()
                    .ok_or_else(|| Error::Http("missing --conjur-appliance-url".to_string()))?,
                account: source_cfg
                    .conjur_account
                    .clone()
                    .ok_or_else(|| Error::Http("missing --conjur-account".to_string()))?,
                authn_login: source_cfg
                    .conjur_authn_login
                    .clone()
                    .ok_or_else(|| Error::Http("missing --conjur-authn-login".to_string()))?,
                authn_api_key: source_cfg
                    .conjur_authn_api_key
                    .clone()
                    .ok_or_else(|| Error::Http("missing --conjur-authn-api-key".to_string()))?,
                public_variable_id: source_cfg.conjur_public_variable_id.clone().ok_or_else(
                    || Error::Http("missing --conjur-public-variable-id".to_string()),
                )?,
                private_variable_id: source_cfg.conjur_private_variable_id.clone().ok_or_else(
                    || Error::Http("missing --conjur-private-variable-id".to_string()),
                )?,
                ca_cert_path: source_cfg
                    .conjur_ca_cert_file
                    .as_ref()
                    .map(|p| p.display().to_string()),
            }),
            _ => None,
        };

    Ok(Some(KeySourceOptions {
        kind: kind.to_core_kind(),
        keydir: keydir.map(|p| p.display().to_string()),
        remote_mtls,
        vault,
        conjur,
    }))
}

struct KeyResolution {
    private_hex: String,
    pair_consistent: bool,
}

struct ResolveCtx<'a> {
    keydir: Option<PathBuf>,
    private_key: Option<&'a str>,
    source_cfg: &'a KeySourceRuntimeConfig,
    legacy_mode: bool,
}

struct FileInput {
    file: Option<PathBuf>,
    input: Option<PathBuf>,
}

struct RegisterCommand {
    public_hex: Option<String>,
    keys_url: Option<String>,
    token: Option<String>,
    tenant: Option<String>,
    note: Option<String>,
    tags: Vec<String>,
    private_key_file: Option<PathBuf>,
    private_key_fd: Option<i32>,
    private_key_stdin: bool,
    allow_insecure_cli_private_key: bool,
}

struct RenderK8sSecretOptions {
    name: Option<String>,
    namespace: Option<String>,
    secret_type: K8sSecretType,
    from_env: Vec<String>,
    from_env_secret: Vec<String>,
    output: Option<PathBuf>,
}

#[derive(Debug, Clone)]
struct AssetsBundle {
    assets: BTreeMap<String, AssetEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
enum AssetKind {
    Text,
    Binary,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct AssetEntry {
    content: String,
    #[serde(default)]
    kind: Option<AssetKind>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AssetImportMode {
    Secured,
    Unsecured,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
enum SidecarEncoding {
    Plain,
    Base64,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct SidecarRule {
    #[serde(default)]
    encoding: Option<SidecarEncoding>,
    #[serde(default)]
    normalize_line_endings: bool,
}

type SidecarSchema = BTreeMap<String, SidecarRule>;

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
enum K8sSecretType {
    #[value(name = "kubernetes.io/tls")]
    KubernetesIoTls,
    #[value(name = "Opaque")]
    Opaque,
}

impl K8sSecretType {
    fn as_str(self) -> &'static str {
        match self {
            K8sSecretType::KubernetesIoTls => "kubernetes.io/tls",
            K8sSecretType::Opaque => "Opaque",
        }
    }
}

fn resolve_private_key_for_public(
    public_key_hex: &str,
    ctx: &ResolveCtx<'_>,
) -> Result<KeyResolution> {
    if let Some(options) = build_key_source_options(ctx.source_cfg, ctx.keydir.as_deref())? {
        let loaded = load_from_source(&options).map_err(|e| Error::Http(e.to_string()))?;
        if !loaded.public_hex.eq_ignore_ascii_case(public_key_hex) {
            return Err(Error::Http(format!(
                "key source public key mismatch: requested={public_key_hex}, loaded={}",
                loaded.public_hex
            )));
        }
        return Ok(KeyResolution {
            private_hex: loaded.private_hex,
            pair_consistent: true,
        });
    }
    let private_hex = load_private_key(public_key_hex, ctx.keydir.as_deref(), ctx.private_key)?;
    let derived = derive_public_hex_from_private(&private_hex)
        .map_err(|e| Error::Http(format!("invalid private key material: {e}")))?;
    let pair_consistent = derived.eq_ignore_ascii_case(public_key_hex);
    if !pair_consistent && !ctx.legacy_mode {
        return Err(Error::Http(format!(
            "inconsistent key pair for public key {public_key_hex} (set ENCJSON_LEGACY_MODE=true to allow legacy behavior)"
        )));
    }
    Ok(KeyResolution {
        private_hex,
        pair_consistent,
    })
}

fn cmd_register(cmd: RegisterCommand, ctx: &ResolveCtx<'_>) -> Result<()> {
    let RegisterCommand {
        public_hex,
        keys_url,
        token,
        tenant,
        note,
        tags,
        private_key_file,
        private_key_fd,
        private_key_stdin,
        allow_insecure_cli_private_key,
    } = cmd;
    let keys_url = keys_url.ok_or(Error::MissingKeysUrl)?;
    let token = token
        .or_else(load_token_from_session)
        .ok_or(Error::MissingAccessToken)?;

    if let Some(public_hex) = public_hex {
        let tenant = tenant.ok_or(Error::RegisterMissingFields)?;
        let note = note.ok_or(Error::RegisterMissingFields)?;
        let payload = if ctx.private_key.is_some()
            || private_key_file.is_some()
            || private_key_fd.is_some()
            || private_key_stdin
        {
            let loaded = load_from_cli(&CliKeyInput {
                public_key: Some(public_hex.clone()),
                private_key: ctx.private_key.map(ToString::to_string),
                private_key_file: private_key_file.as_ref().map(|p| p.display().to_string()),
                private_key_fd,
                private_key_stdin,
                allow_insecure_cli_private_key,
            })
            .map_err(|e| Error::Http(e.to_string()))?;
            RegisterPayload::Legacy(RegisterPayloadLegacy {
                public_hex,
                private_hex: loaded.private_hex,
                tenant,
                note,
                tags,
            })
        } else {
            build_register_payload_from_local_key(&public_hex, tenant, note, tags, ctx)?
        };
        send_register_request(&keys_url, &token, payload)?;
        println!("Register request submitted.");
        return Ok(());
    }

    let local_keys = list_public_keys(ctx.keydir.as_deref())?;
    if local_keys.is_empty() {
        println!("No local keys found.");
        return Ok(());
    }

    let remote_keys = fetch_remote_keys(&keys_url, &token)?;
    let pending = fetch_pending_requests(&keys_url, &token)?;
    let existing: std::collections::HashSet<String> = remote_keys
        .into_iter()
        .map(|k| k.key_id.unwrap_or(k.public_hex))
        .chain(
            pending
                .into_iter()
                .map(|r| r.key_id.unwrap_or(r.public_hex)),
        )
        .collect();

    let mut new_keys: Vec<String> = local_keys
        .into_iter()
        .filter(|k| !existing.contains(k))
        .collect();
    new_keys.sort();

    if new_keys.is_empty() {
        println!("No new keys to register.");
        return Ok(());
    }

    let tenants = fetch_remote_tenants(&keys_url, &token)?;
    tui_register::run_register_tui(new_keys, tenants, keys_url, token, ctx.keydir.clone())
        .map_err(|e| Error::Http(e.to_string()))?;

    Ok(())
}

fn build_register_payload_from_local_key(
    key_ref: &str,
    tenant: String,
    note: String,
    tags: Vec<String>,
    ctx: &ResolveCtx<'_>,
) -> Result<RegisterPayload> {
    match load_stored_key_material(key_ref, ctx.keydir.as_deref())? {
        StoredKeyMaterial::LegacyPrivateHex(private_hex) => {
            Ok(RegisterPayload::Legacy(RegisterPayloadLegacy {
                public_hex: key_ref.to_string(),
                private_hex,
                tenant,
                note,
                tags,
            }))
        }
        StoredKeyMaterial::V3Bundle(bundle) => {
            warn_legacy_mlkem_private_key(&bundle);
            Ok(RegisterPayload::V3(RegisterPayloadV3 {
                key_id: bundle.key_id.clone(),
                version: bundle.version,
                algorithm: bundle.algorithm.clone(),
                public_bundle: bundle.to_recipient_key().to_public_bundle(),
                private_bundle: PrivateBundle {
                    version: bundle.version,
                    key_id: bundle.key_id.clone(),
                    algorithm: bundle.algorithm.clone(),
                    components: vec![
                        encjson_core::recipient::KeyComponentPrivate {
                            role: "kex".to_string(),
                            algorithm: "x25519".to_string(),
                            encoding: "hex".to_string(),
                            private: bundle.x25519.private_hex.clone(),
                        },
                        encjson_core::recipient::KeyComponentPrivate {
                            role: "kex".to_string(),
                            algorithm: "ml-kem-768".to_string(),
                            encoding: "base64".to_string(),
                            private: bundle.mlkem768.private_b64.clone(),
                        },
                    ],
                },
                tenant,
                note,
                tags,
            }))
        }
    }
}

fn cmd_list(keydir: Option<PathBuf>) -> Result<()> {
    let keys = list_public_keys(keydir.as_deref())?;
    if keys.is_empty() {
        println!("No keys found.");
        return Ok(());
    }
    for key in keys {
        println!("{key}");
    }
    Ok(())
}

fn cmd_info(input: FileInput, ctx: &ResolveCtx<'_>) -> Result<()> {
    let effective_path = input.file.or(input.input);
    let root = read_json(effective_path.as_ref())?;
    match RecipientMetadata::parse(&root)? {
        RecipientMetadata::LegacyPublicKey(public_key_hex) => {
            if contains_api_version(&root, "1.0") {
                print_legacy_api1_warning();
            } else {
                print_legacy_api2_warning();
            }
            let resolved = resolve_private_key_for_public(&public_key_hex, ctx)?;
            println!("metadata: legacy");
            println!("public_key: {public_key_hex}");
            println!("private_key: {}", resolved.private_hex);
            println!("pair_consistent: {}", resolved.pair_consistent);
        }
        RecipientMetadata::RecipientKeyV3(recipient) => {
            println!("metadata: recipient_key");
            println!("version: {}", recipient.version);
            println!("key_id: {}", recipient.key_id);
            println!("algorithm: {}", recipient.algorithm);
            println!("x25519_public_hex: {}", recipient.x25519_public_hex);
            println!("mlkem768_public_b64: {}", recipient.mlkem768_public_b64);
        }
    }
    Ok(())
}

fn load_token_from_session() -> Option<String> {
    let config = oidc_session::load_sessions("encjson").ok()?;
    let session = config.servers.get(&config.active)?;
    Some(session.access_token.clone())
}

fn fetch_remote_keys(keys_url: &str, token: &str) -> Result<Vec<KeysKey>> {
    let url = format!("{}/api/v1/keys", keys_url.trim_end_matches('/'));
    let response = reqwest::blocking::Client::new()
        .get(url)
        .bearer_auth(token)
        .send()
        .map_err(|e| Error::Http(e.to_string()))?;
    let status = response.status();
    let body = response.text().map_err(|e| Error::Http(e.to_string()))?;
    if !status.is_success() {
        return Err(Error::Http(body.trim().to_string()));
    }
    serde_json::from_str(&body).map_err(Error::Json)
}

#[derive(serde::Deserialize)]
struct KeysTenant {
    name: String,
}

fn fetch_remote_tenants(keys_url: &str, token: &str) -> Result<Vec<String>> {
    let url = format!("{}/api/v1/tenants", keys_url.trim_end_matches('/'));
    let response = reqwest::blocking::Client::new()
        .get(url)
        .bearer_auth(token)
        .send()
        .map_err(|e| Error::Http(e.to_string()))?;
    let status = response.status();
    let body = response.text().map_err(|e| Error::Http(e.to_string()))?;
    if !status.is_success() {
        return Err(Error::Http(body.trim().to_string()));
    }
    let items: Vec<KeysTenant> =
        serde_json::from_str(&body).map_err(|e| Error::Http(e.to_string()))?;
    Ok(items.into_iter().map(|t| t.name).collect())
}

fn fetch_pending_requests(keys_url: &str, token: &str) -> Result<Vec<KeysRequest>> {
    let url = format!(
        "{}/api/v1/requests?status=pending",
        keys_url.trim_end_matches('/')
    );
    let response = reqwest::blocking::Client::new()
        .get(url)
        .bearer_auth(token)
        .send()
        .map_err(|e| Error::Http(e.to_string()))?;
    let status = response.status();
    let body = response.text().map_err(|e| Error::Http(e.to_string()))?;
    if !status.is_success() {
        return Err(Error::Http(body.trim().to_string()));
    }
    serde_json::from_str(&body).map_err(Error::Json)
}

fn send_register_request(keys_url: &str, token: &str, payload: RegisterPayload) -> Result<()> {
    let url = format!("{}/api/v1/requests", keys_url.trim_end_matches('/'));
    let response = reqwest::blocking::Client::new()
        .post(url)
        .bearer_auth(token)
        .json(&payload)
        .send()
        .map_err(|e| Error::Http(e.to_string()))?;
    let status = response.status();
    let body = response.text().map_err(|e| Error::Http(e.to_string()))?;
    if !status.is_success() {
        return Err(Error::Http(body.trim().to_string()));
    }
    Ok(())
}

fn fetch_private_key(keys_url: &str, token: &str, public_hex: &str) -> Result<KeysPrivateKey> {
    let url = format!(
        "{}/api/v1/keys/{}/private",
        keys_url.trim_end_matches('/'),
        public_hex
    );
    let response = reqwest::blocking::Client::new()
        .get(url)
        .bearer_auth(token)
        .send()
        .map_err(|e| Error::Http(e.to_string()))?;
    let status = response.status();
    let body = response.text().map_err(|e| Error::Http(e.to_string()))?;
    if !status.is_success() {
        return Err(Error::Http(body.trim().to_string()));
    }
    serde_json::from_str(&body).map_err(Error::Json)
}

fn fetch_key_bundle(keys_url: &str, token: &str, key_id: &str) -> Result<KeysBundle> {
    let url = format!(
        "{}/api/v1/keys/{}/bundle",
        keys_url.trim_end_matches('/'),
        key_id
    );
    let response = reqwest::blocking::Client::new()
        .get(url)
        .bearer_auth(token)
        .send()
        .map_err(|e| Error::Http(e.to_string()))?;
    let status = response.status();
    let body = response.text().map_err(|e| Error::Http(e.to_string()))?;
    if !status.is_success() {
        return Err(Error::Http(body.trim().to_string()));
    }
    serde_json::from_str(&body).map_err(Error::Json)
}

fn cmd_sync(
    file: Option<PathBuf>,
    key: Option<String>,
    keys_url: Option<String>,
    token: Option<String>,
    keydir: Option<PathBuf>,
) -> Result<()> {
    let keys_url = keys_url.ok_or(Error::MissingKeysUrl)?;
    let token = token
        .or_else(load_token_from_session)
        .ok_or(Error::MissingAccessToken)?;

    let mut remote_keys = fetch_remote_keys(&keys_url, &token)?;
    if let Some(ref key_ref) = key {
        remote_keys.retain(|item| {
            item.public_hex == *key_ref || item.key_id.as_deref() == Some(key_ref.as_str())
        });
    } else if let Some(path) = file.as_ref() {
        let json = read_json(Some(path))?;
        match RecipientMetadata::parse(&json)? {
            RecipientMetadata::LegacyPublicKey(public_hex) => {
                remote_keys.retain(|item| item.public_hex == public_hex);
            }
            RecipientMetadata::RecipientKeyV3(recipient) => {
                remote_keys
                    .retain(|item| item.key_id.as_deref() == Some(recipient.key_id.as_str()));
            }
        }
    }

    if remote_keys.is_empty() {
        println!("No keys to sync.");
        return Ok(());
    }

    let mut downloaded = 0;
    let mut skipped = 0;
    let dir = keydir.clone().unwrap_or_else(default_key_dir);
    std::fs::create_dir_all(&dir)?;
    remote_keys.sort_by(|a, b| {
        a.key_id
            .as_deref()
            .unwrap_or(a.public_hex.as_str())
            .cmp(b.key_id.as_deref().unwrap_or(b.public_hex.as_str()))
    });
    remote_keys.dedup_by(|a, b| {
        a.key_id.as_deref().unwrap_or(a.public_hex.as_str())
            == b.key_id.as_deref().unwrap_or(b.public_hex.as_str())
    });

    for item in remote_keys {
        if item.bundle_version == Some(3) {
            let Some(key_id) = item.key_id.as_deref() else {
                return Err(Error::Http(
                    "keys server returned v3 key without key_id".to_string(),
                ));
            };
            let path = dir.join(key_id);
            if path.exists() {
                skipped += 1;
                continue;
            }
            let bundle = fetch_key_bundle(&keys_url, &token, key_id)?;
            save_v3_key_bundle(
                &encjson_core::recipient::LocalKeyFileV3 {
                    version: bundle.version,
                    key_id: bundle.key_id,
                    algorithm: bundle.algorithm,
                    created_at: chrono::Utc::now().to_rfc3339(),
                    x25519: encjson_core::recipient::LocalX25519Keypair {
                        public_hex: bundle
                            .public_bundle
                            .components
                            .iter()
                            .find(|c| c.algorithm == "x25519")
                            .map(|c| c.public.clone())
                            .ok_or_else(|| {
                                Error::Http("v3 bundle missing x25519 public component".to_string())
                            })?,
                        private_hex: bundle
                            .private_bundle
                            .components
                            .iter()
                            .find(|c| c.algorithm == "x25519")
                            .map(|c| c.private.clone())
                            .ok_or_else(|| {
                                Error::Http(
                                    "v3 bundle missing x25519 private component".to_string(),
                                )
                            })?,
                    },
                    mlkem768: encjson_core::recipient::LocalMlKem768Keypair {
                        public_b64: bundle
                            .public_bundle
                            .components
                            .iter()
                            .find(|c| c.algorithm == "ml-kem-768")
                            .map(|c| c.public.clone())
                            .ok_or_else(|| {
                                Error::Http(
                                    "v3 bundle missing ml-kem-768 public component".to_string(),
                                )
                            })?,
                        private_b64: bundle
                            .private_bundle
                            .components
                            .iter()
                            .find(|c| c.algorithm == "ml-kem-768")
                            .map(|c| c.private.clone())
                            .ok_or_else(|| {
                                Error::Http(
                                    "v3 bundle missing ml-kem-768 private component".to_string(),
                                )
                            })?,
                    },
                },
                Some(&dir),
            )?;
            downloaded += 1;
        } else {
            let public_hex = item.public_hex;
            let private_key = fetch_private_key(&keys_url, &token, &public_hex)?;
            if private_key.public_hex != public_hex {
                return Err(Error::Http(format!(
                    "keys server returned mismatched key {}",
                    private_key.public_hex
                )));
            }
            let path = dir.join(&public_hex);
            if path.exists() {
                skipped += 1;
                continue;
            }
            save_private_key(&public_hex, &private_key.private_hex, Some(&dir))?;
            downloaded += 1;
        }
    }

    println!("Sync OK. Downloaded: {downloaded}, Skipped: {skipped}");
    Ok(())
}

fn cmd_sync_dir(src_dir: PathBuf, dst_dir: PathBuf, dry_run: bool) -> Result<()> {
    if !src_dir.exists() {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("source directory does not exist: {}", src_dir.display()),
        )));
    }
    if !src_dir.is_dir() {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("source path is not a directory: {}", src_dir.display()),
        )));
    }

    std::fs::create_dir_all(&dst_dir)?;

    let mut copied = 0usize;
    let mut skipped_existing = 0usize;
    let mut skipped_non_key = 0usize;

    for entry in std::fs::read_dir(&src_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            skipped_non_key += 1;
            continue;
        };
        if !is_hex_key_name(name) {
            skipped_non_key += 1;
            continue;
        }

        let target = dst_dir.join(name);
        if target.exists() {
            skipped_existing += 1;
            continue;
        }

        if dry_run {
            println!("would copy: {}", name);
            copied += 1;
            continue;
        }

        std::fs::copy(&path, &target)?;
        copied += 1;
    }

    if dry_run {
        println!(
            "Sync-dir dry-run OK. Would copy: {copied}, Skipped existing: {skipped_existing}, Ignored non-key files: {skipped_non_key}"
        );
    } else {
        println!(
            "Sync-dir OK. Copied: {copied}, Skipped existing: {skipped_existing}, Ignored non-key files: {skipped_non_key}"
        );
    }
    Ok(())
}

fn is_hex_key_name(name: &str) -> bool {
    if name.len() != 64 {
        return false;
    }
    name.chars().all(|c| c.is_ascii_hexdigit())
}

fn cmd_init(keydir: Option<PathBuf>, api: EncJsonApiVersion, create_file: bool) -> Result<()> {
    if api == EncJsonApiVersion::V3_0 {
        let bundle = generate_v3_key_bundle()?;
        let recipient = bundle.to_recipient_key();
        let path = save_v3_key_bundle(&bundle, keydir.as_deref())?;
        let template = minimal_secured_template_v3(&recipient)?;

        println!("OK init");
        println!("  api       : 3.0");
        println!("  key_id    : {}", bundle.key_id);
        println!("  algorithm : {}", bundle.algorithm);
        println!("  key file  : {}", path.display());

        if create_file {
            let out = PathBuf::from("env.secured.json");
            if out.exists() {
                return Err(Error::FileAlreadyExists(out.display().to_string()));
            }
            fs::write(&out, serde_json::to_string_pretty(&template)?)?;
            println!("  created   : {}", out.display());
        }
        print_minimal_secured_template(&template)?;
        return Ok(());
    }

    let (priv_hex, pub_hex) = generate_pair_consistent_key_pair();
    let path = save_private_key(&pub_hex, &priv_hex, keydir.as_deref())?;
    let template = minimal_secured_template_v2(&pub_hex);

    println!("OK init");
    println!("  public key : {pub_hex}");
    println!("  private key: {priv_hex}");
    println!("  key file   : {}", path.display());

    if create_file {
        let out = PathBuf::from("env.secured.json");
        if out.exists() {
            return Err(Error::FileAlreadyExists(out.display().to_string()));
        }
        fs::write(&out, serde_json::to_string_pretty(&template)?)?;
        println!("  created    : {}", out.display());
    }
    print_minimal_secured_template(&template)?;

    Ok(())
}

fn minimal_secured_template_v2(public_hex: &str) -> Value {
    serde_json::json!({
        "_public_key": public_hex,
        "environment": {}
    })
}

fn minimal_secured_template_v3(
    recipient: &encjson_core::recipient::RecipientKeyV3,
) -> Result<Value> {
    Ok(serde_json::json!({
        "_recipient_key": recipient,
        "environment": {}
    }))
}

fn print_minimal_secured_template(template: &Value) -> Result<()> {
    println!();
    println!("Minimal env.secured.json (copy/paste):");
    println!("{}", serde_json::to_string_pretty(template)?);
    Ok(())
}

fn cmd_encrypt(
    input: FileInput,
    write: bool,
    ctx: &ResolveCtx<'_>,
    warn_pair_mismatch: bool,
) -> Result<()> {
    // sjednotíme -f a pozicní argument (např. "-")
    let effective_path = input.file.or(input.input);

    let mut value = read_json(effective_path.as_ref())?;
    let upgraded_legacy_metadata_to_v3 =
        upgrade_legacy_public_key_metadata_to_v3_if_possible(&mut value, ctx, true)?;
    let legacy_api2 = !upgraded_legacy_metadata_to_v3 && contains_api_version(&value, "2.0");

    let mut pair_mismatch = false;
    match resolve_json_crypto(&value, ctx)? {
        ResolvedJsonCrypto::None => {
            emit_warning("no recipient metadata found in JSON, nothing encrypted");
        }
        ResolvedJsonCrypto::Legacy {
            sb,
            pair_mismatch: legacy_pair_mismatch,
        } => {
            pair_mismatch = legacy_pair_mismatch;
            transform_json(&mut value, &sb, TransformMode::Encrypt)?;
        }
        ResolvedJsonCrypto::V3 { sb } => {
            transform_json_v3(&mut value, &sb, TransformMode::Encrypt)?;
        }
    }

    write_json_to(effective_path.as_ref(), write, &value)?;
    if legacy_api2 {
        print_legacy_api2_warning();
    }
    if pair_mismatch && warn_pair_mismatch {
        emit_warning(
            "legacy inconsistent key pair detected for _public_key; encryption proceeded because ENCJSON_LEGACY_MODE=true. Run `encjson rotate-key -f <file> -w`.",
        );
    }
    Ok(())
}

fn upgrade_legacy_public_key_metadata_to_v3_if_possible(
    root: &mut Value,
    ctx: &ResolveCtx<'_>,
    warn: bool,
) -> Result<bool> {
    let Ok(RecipientMetadata::LegacyPublicKey(key_id)) = RecipientMetadata::parse(root) else {
        return Ok(false);
    };

    // API 1.0 and API 2.0 use different key derivation and wire formats. Do
    // not replace API 1.0 metadata merely because a same-named local key file
    // happens to contain a v3 bundle.
    if contains_api_version(root, "1.0") {
        return Ok(false);
    }

    match load_stored_key_material(&key_id, ctx.keydir.as_deref()) {
        Ok(StoredKeyMaterial::V3Bundle(bundle)) => {
            warn_legacy_mlkem_private_key(&bundle);
            replace_root_metadata_with_recipient(root, &bundle.to_recipient_key())?;
            if warn {
                emit_warning(
                    "`_public_key` referenced a local api=3.0 key bundle; upgraded JSON metadata to `_recipient_key`.",
                );
            }
            Ok(true)
        }
        Ok(StoredKeyMaterial::LegacyPrivateHex(_)) => Ok(false),
        Err(Error::PrivateKeyNotFound(_)) => Ok(false),
        Err(err) => Err(err),
    }
}

fn replace_root_metadata_with_recipient(
    root: &mut Value,
    recipient: &encjson_core::recipient::RecipientKeyV3,
) -> Result<()> {
    let obj = root.as_object_mut().ok_or(Error::MissingEnvObject)?;
    obj.remove("_public_key");
    obj.remove("_recipient_key");

    let mut reordered = serde_json::Map::new();
    reordered.insert(
        "_recipient_key".to_string(),
        serde_json::to_value(recipient)?,
    );
    for (key, value) in std::mem::take(obj) {
        reordered.insert(key, value);
    }
    *obj = reordered;
    Ok(())
}

fn cmd_decrypt(
    input: FileInput,
    write: bool,
    output: OutputFormat,
    debug: bool,
    env_name: Option<String>,
    ctx: &ResolveCtx<'_>,
    warn_pair_mismatch: bool,
) -> Result<()> {
    if debug {
        init_tracing(true);
    }

    // `-w` dává smysl jen pro JSON výstup
    if write && !matches!(output, OutputFormat::Json) {
        return Err(Error::InvalidWriteForOutput);
    }
    if env_name.is_some() && write {
        return Err(Error::Http(
            "--env-name cannot be used together with --write".to_string(),
        ));
    }
    if env_name.is_some() && !matches!(output, OutputFormat::Json) {
        return Err(Error::Http(
            "--env-name supports only default -o json mode".to_string(),
        ));
    }

    // sjednotíme -f a pozicní argument (např. "-")
    let effective_path = input.file.or(input.input);
    if debug {
        tracing::debug!(
            path = ?effective_path,
            output = ?output,
            write,
            env_name = env_name.as_deref(),
            "encjson: decrypt"
        );
    }
    let legacy_api2 = input_path_uses_api_version(effective_path.as_ref(), "2.0")?;
    let (value, pair_mismatch, upgraded_legacy_metadata_to_v3) =
        decrypt_json_with_sidecar(effective_path.as_ref(), ctx)?;

    if let Some(name) = env_name {
        let raw = get_env_value_raw(&value, &name)?;
        print!("{raw}");
        if pair_mismatch && warn_pair_mismatch {
            emit_warning(
                "legacy inconsistent key pair detected for _public_key; decryption proceeded because ENCJSON_LEGACY_MODE=true. Run `encjson rotate-key -f <file> -w`.",
            );
        }
        return Ok(());
    }

    match output {
        OutputFormat::Json => {
            write_json_to(effective_path.as_ref(), write, &value)?;
            if legacy_api2 && !upgraded_legacy_metadata_to_v3 && warn_pair_mismatch {
                print_legacy_api2_warning();
            }
            if pair_mismatch && warn_pair_mismatch {
                emit_warning(
                    "legacy inconsistent key pair detected for _public_key; decryption proceeded because ENCJSON_LEGACY_MODE=true. Run `encjson rotate-key -f <file> -w`.",
                );
            }
            Ok(())
        }
        OutputFormat::Shell => {
            let exports = env_exports(&value)?;
            print!("{exports}");
            Ok(())
        }
        OutputFormat::DotEnv => {
            let dotenv = dotenv_exports(&value)?;
            print!("{dotenv}");
            Ok(())
        }
    }
}

fn cmd_assets(command: AssetsCommand) -> Result<()> {
    match command {
        AssetsCommand::List {
            resolve,
            file,
            input,
            keydir,
        } => {
            validate_scope_args(&resolve)?;
            let source_cfg = source_cfg_from_resolve_args(&resolve);
            let ctx = ResolveCtx {
                keydir,
                private_key: resolve.private_key.as_deref(),
                source_cfg: &source_cfg,
                legacy_mode: resolve.legacy_mode,
            };
            let bundle = load_assets_bundle(FileInput { file, input }, &ctx)?;
            for path in bundle.assets.keys() {
                println!("{path}");
            }
            Ok(())
        }
        AssetsCommand::Get {
            resolve,
            file,
            input,
            path,
            base64,
            output,
            keydir,
        } => {
            validate_scope_args(&resolve)?;
            let source_cfg = source_cfg_from_resolve_args(&resolve);
            let ctx = ResolveCtx {
                keydir,
                private_key: resolve.private_key.as_deref(),
                source_cfg: &source_cfg,
                legacy_mode: resolve.legacy_mode,
            };
            let bundle = load_assets_bundle(FileInput { file, input }, &ctx)?;
            let value = bundle.assets.get(&path).ok_or_else(|| {
                Error::Http(format!("asset path '{}' not found in assets bundle", path))
            })?;
            if base64 {
                if let Some(output) = output {
                    fs::write(output, value.content.as_bytes())?;
                } else {
                    print!("{}", value.content);
                }
                return Ok(());
            }
            let bytes = decode_asset_base64(&path, &value.content)?;
            write_asset_output(output.as_ref(), &bytes)
        }
        AssetsCommand::Export {
            resolve,
            file,
            input,
            out_dir,
            overwrite,
            keydir,
        } => {
            validate_scope_args(&resolve)?;
            let source_cfg = source_cfg_from_resolve_args(&resolve);
            let ctx = ResolveCtx {
                keydir,
                private_key: resolve.private_key.as_deref(),
                source_cfg: &source_cfg,
                legacy_mode: resolve.legacy_mode,
            };
            let bundle = load_assets_bundle(FileInput { file, input }, &ctx)?;
            export_assets_bundle(&bundle, &out_dir, overwrite)
        }
        AssetsCommand::Import {
            resolve,
            from_dir,
            output,
            secured,
            unsecured,
            public_key,
            keydir,
        } => {
            validate_scope_args(&resolve)?;
            let source_cfg = source_cfg_from_resolve_args(&resolve);
            let ctx = ResolveCtx {
                keydir,
                private_key: resolve.private_key.as_deref(),
                source_cfg: &source_cfg,
                legacy_mode: resolve.legacy_mode,
            };
            let mode = match (secured, unsecured) {
                (true, false) => AssetImportMode::Secured,
                (false, true) => AssetImportMode::Unsecured,
                (false, false) => infer_asset_import_mode(&output)?,
                (true, true) => unreachable!(),
            };
            import_assets_bundle(&from_dir, &output, mode, public_key, &ctx)
        }
    }
}

fn infer_asset_import_mode(output: &Path) -> Result<AssetImportMode> {
    let name = output
        .file_name()
        .and_then(|v| v.to_str())
        .ok_or_else(|| Error::Http(format!("invalid output path '{}'", output.display())))?;
    if name.ends_with(".secured.json") {
        return Ok(AssetImportMode::Secured);
    }
    if name.ends_with(".unsecured.json") {
        return Ok(AssetImportMode::Unsecured);
    }
    Err(Error::Http(
        "cannot infer asset bundle mode; use --secured or --unsecured, or output *.secured.json / *.unsecured.json"
            .to_string(),
    ))
}

fn load_assets_bundle(input: FileInput, ctx: &ResolveCtx<'_>) -> Result<AssetsBundle> {
    let effective_path = input.file.or(input.input);
    let mut root = read_json(effective_path.as_ref())?;

    match resolve_json_crypto(&root, ctx)? {
        ResolvedJsonCrypto::None => None,
        ResolvedJsonCrypto::Legacy { sb, .. } => {
            transform_json(&mut root, &sb, TransformMode::Decrypt)?;
            Some(())
        }
        ResolvedJsonCrypto::V3 { sb } => {
            transform_json_v3(&mut root, &sb, TransformMode::Decrypt)?;
            None
        }
    };

    parse_assets_bundle(&root).map(|assets| AssetsBundle { assets })
}

fn parse_assets_bundle(root: &Value) -> Result<BTreeMap<String, AssetEntry>> {
    let obj = root
        .get("assets")
        .and_then(Value::as_object)
        .ok_or_else(|| Error::Http("missing assets object".to_string()))?;
    let mut out = BTreeMap::new();
    for (path, value) in obj {
        validate_asset_path(path)?;
        let entry = if let Some(content) = value.as_str() {
            AssetEntry {
                content: content.to_string(),
                kind: None,
            }
        } else {
            serde_json::from_value::<AssetEntry>(value.clone()).map_err(|e| {
                Error::Http(format!(
                    "asset '{}' must be stored as object {{content, kind}}: {e}",
                    path
                ))
            })?
        };
        out.insert(path.clone(), entry);
    }
    Ok(out)
}

fn validate_asset_path(path: &str) -> Result<()> {
    if path.is_empty() {
        return Err(Error::Http("asset path must not be empty".to_string()));
    }
    let p = Path::new(path);
    if p.is_absolute() {
        return Err(Error::Http(format!(
            "asset path '{}' must be relative",
            path
        )));
    }
    if p.components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(Error::Http(format!(
            "asset path '{}' must not contain '..'",
            path
        )));
    }
    Ok(())
}

fn decode_asset_base64(path: &str, value: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(value.trim())
        .map_err(|e| Error::Http(format!("base64 decode failed for asset '{}': {e}", path)))
}

fn asset_kind_from_bytes(bytes: &[u8]) -> AssetKind {
    match std::str::from_utf8(bytes) {
        Ok(text) => {
            let printable = text
                .chars()
                .all(|ch| ch == '\n' || ch == '\r' || ch == '\t' || (!ch.is_control()));
            if printable {
                AssetKind::Text
            } else {
                AssetKind::Binary
            }
        }
        Err(_) => AssetKind::Binary,
    }
}

#[cfg(test)]
fn effective_asset_kind(entry: &AssetEntry) -> AssetKind {
    entry.kind.unwrap_or_else(|| {
        decode_asset_base64("<detect>", &entry.content)
            .map(|bytes| asset_kind_from_bytes(&bytes))
            .unwrap_or(AssetKind::Binary)
    })
}

fn write_asset_output(output: Option<&PathBuf>, bytes: &[u8]) -> Result<()> {
    if let Some(output) = output {
        fs::write(output, bytes)?;
    } else {
        io::stdout().write_all(bytes)?;
    }
    Ok(())
}

fn export_assets_bundle(bundle: &AssetsBundle, out_dir: &Path, overwrite: bool) -> Result<()> {
    fs::create_dir_all(out_dir)?;
    for (path, entry) in &bundle.assets {
        let bytes = decode_asset_base64(path, &entry.content)?;
        let target = out_dir.join(path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        if target.exists() && !overwrite {
            return Err(Error::Http(format!(
                "target '{}' already exists; use --overwrite",
                target.display()
            )));
        }
        fs::write(target, bytes)?;
    }
    Ok(())
}

fn import_assets_bundle(
    from_dir: &Path,
    output: &Path,
    mode: AssetImportMode,
    public_key: Option<String>,
    ctx: &ResolveCtx<'_>,
) -> Result<()> {
    if !from_dir.is_dir() {
        return Err(Error::Http(format!(
            "source directory '{}' does not exist or is not a directory",
            from_dir.display()
        )));
    }

    let mut assets = BTreeMap::new();
    collect_assets_from_dir(from_dir, from_dir, &mut assets)?;

    let mut root = if output.exists() {
        read_json(Some(&output.to_path_buf()))?
    } else {
        Value::Object(serde_json::Map::new())
    };

    let effective_public = match mode {
        AssetImportMode::Secured => {
            let existing_public = match extract_public_key(&root) {
                Ok(v) => Some(v.to_string()),
                Err(Error::MissingPublicKey) => None,
                Err(e) => return Err(e),
            };
            match (existing_public, public_key) {
                (Some(existing), Some(provided)) => {
                    if existing != provided {
                        return Err(Error::Http(format!(
                            "provided --public-key does not match existing _public_key in '{}'",
                            output.display()
                        )));
                    }
                    Some(existing)
                }
                (Some(existing), None) => Some(existing),
                (None, Some(provided)) => Some(provided),
                (None, None) => {
                    return Err(Error::Http(
                        "--public-key is required when creating a new secured assets bundle"
                            .to_string(),
                    ));
                }
            }
        }
        AssetImportMode::Unsecured => None,
    };

    let mut map = serde_json::Map::new();
    if let Some(public) = effective_public.as_ref() {
        map.insert("_public_key".to_string(), Value::String(public.clone()));
    }
    map.insert(
        "assets".to_string(),
        Value::Object(
            assets
                .into_iter()
                .map(|(k, v)| (k, serde_json::to_value(v).unwrap_or(Value::Null)))
                .collect(),
        ),
    );
    root = Value::Object(map);

    if let Some(public_key_hex) = effective_public.as_ref() {
        let resolved = resolve_private_key_for_public(public_key_hex, ctx)?;
        let sb = SecureBox::new_from_hex(&resolved.private_hex, public_key_hex)?;
        encrypt_assets_bundle_contents(&mut root, &sb)?;
    }

    fs::write(output, serde_json::to_string_pretty(&root)?)?;
    Ok(())
}

fn encrypt_assets_bundle_contents(root: &mut Value, sb: &SecureBox) -> Result<()> {
    let Some(assets) = root.get_mut("assets").and_then(Value::as_object_mut) else {
        return Err(Error::Http("missing assets object".to_string()));
    };
    for value in assets.values_mut() {
        let Some(obj) = value.as_object_mut() else {
            continue;
        };
        let Some(content) = obj.get_mut("content") else {
            continue;
        };
        match content {
            Value::String(s) => {
                *s = sb.encrypt_value(s).map_err(Error::Crypto)?;
            }
            other => {
                transform_json(other, sb, TransformMode::Encrypt)?;
            }
        }
    }
    Ok(())
}

fn collect_assets_from_dir(
    root: &Path,
    current: &Path,
    assets: &mut BTreeMap<String, AssetEntry>,
) -> Result<()> {
    for entry in fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_assets_from_dir(root, &path, assets)?;
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        let rel = path
            .strip_prefix(root)
            .map_err(|e| Error::Http(format!("failed to compute relative path: {e}")))?;
        let rel_string = rel
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/");
        validate_asset_path(&rel_string)?;
        let bytes = fs::read(&path)?;
        assets.insert(
            rel_string,
            AssetEntry {
                content: base64::engine::general_purpose::STANDARD.encode(&bytes),
                kind: Some(asset_kind_from_bytes(&bytes)),
            },
        );
    }
    Ok(())
}

fn get_env_value_raw(root: &Value, env_name: &str) -> Result<String> {
    let obj = root
        .get("environment")
        .or_else(|| root.get("env"))
        .and_then(Value::as_object)
        .ok_or(Error::MissingEnvObject)?;

    let value = obj.get(env_name).ok_or_else(|| {
        Error::Http(format!(
            "environment value '{env_name}' not found in environment/env object"
        ))
    })?;

    if let Some(s) = value.as_str() {
        return Ok(s.to_string());
    }

    serde_json::to_string(value)
        .map_err(|e| Error::Http(format!("failed to serialize '{env_name}' value: {e}")))
}

fn decrypt_json_with_sidecar(
    effective_path: Option<&PathBuf>,
    ctx: &ResolveCtx<'_>,
) -> Result<(Value, bool, bool)> {
    let mut value = read_json(effective_path)?;
    let upgraded_legacy_metadata_to_v3 =
        upgrade_legacy_public_key_metadata_to_v3_if_possible(&mut value, ctx, false)?;
    let sidecar_schema = load_sidecar_schema(effective_path)?;

    let mut pair_mismatch = false;
    match resolve_json_crypto(&value, ctx)? {
        ResolvedJsonCrypto::None => {}
        ResolvedJsonCrypto::Legacy {
            sb,
            pair_mismatch: legacy_pair_mismatch,
        } => {
            pair_mismatch = legacy_pair_mismatch;
            transform_json(&mut value, &sb, TransformMode::Decrypt)?;
        }
        ResolvedJsonCrypto::V3 { sb } => {
            transform_json_v3(&mut value, &sb, TransformMode::Decrypt)?;
        }
    }

    if let Some(schema) = sidecar_schema.as_ref() {
        apply_sidecar_schema(&mut value, schema)?;
    }

    Ok((value, pair_mismatch, upgraded_legacy_metadata_to_v3))
}

fn cmd_render_k8s_secret(
    input: FileInput,
    opts: RenderK8sSecretOptions,
    ctx: &ResolveCtx<'_>,
) -> Result<()> {
    let RenderK8sSecretOptions {
        name,
        namespace,
        secret_type,
        from_env,
        from_env_secret,
        output,
    } = opts;
    let effective_path = input.file.or(input.input);
    let legacy_api2 = input_path_uses_api_version(effective_path.as_ref(), "2.0")?;
    let (value, pair_mismatch, upgraded_legacy_metadata_to_v3) =
        decrypt_json_with_sidecar(effective_path.as_ref(), ctx)?;

    let env_obj = value
        .get("environment")
        .or_else(|| value.get("env"))
        .and_then(Value::as_object)
        .ok_or(Error::MissingEnvObject)?;

    let mappings = parse_from_env_mappings(&from_env)?;
    let mappings_multi = parse_from_env_secret_mappings(&from_env_secret)?;
    let manifests = build_secret_manifests(
        env_obj,
        namespace.as_deref(),
        name.as_deref(),
        secret_type,
        &mappings,
        &mappings_multi,
    )?;
    let mut yaml = String::new();
    for (idx, manifest) in manifests.iter().enumerate() {
        if idx > 0 {
            yaml.push_str("---\n");
        }
        yaml.push_str(
            &serde_yaml_ng::to_string(manifest)
                .map_err(|e| Error::Http(format!("failed to serialize secret YAML: {e}")))?,
        );
    }
    if let Some(path) = output {
        fs::write(&path, yaml)
            .map_err(|e| Error::Http(format!("failed to write {}: {e}", path.display())))?;
    } else {
        print!("{yaml}");
    }
    if legacy_api2 && !upgraded_legacy_metadata_to_v3 {
        print_legacy_api2_warning();
    }
    if pair_mismatch {
        emit_warning(
            "legacy inconsistent key pair detected for _public_key; decryption proceeded because ENCJSON_LEGACY_MODE=true. Run `encjson rotate-key -f <file> -w`.",
        );
    }
    Ok(())
}

fn cmd_render_k8s_pair_secret(
    input: FileInput,
    name: String,
    namespace: Option<String>,
    public_key_name: String,
    private_key_name: String,
    output: Option<PathBuf>,
    ctx: &ResolveCtx<'_>,
) -> Result<()> {
    let effective_path = input.file.or(input.input);
    let value = read_json(effective_path.as_ref())?;
    let manifest = match RecipientMetadata::parse(&value)? {
        RecipientMetadata::LegacyPublicKey(public_key) => {
            if contains_api_version(&value, "1.0") {
                print_legacy_api1_warning();
            } else {
                print_legacy_api2_warning();
            }
            let resolved = resolve_private_key_for_public(&public_key, ctx)?;
            let mut data = BTreeMap::new();
            data.insert(public_key_name, encode_k8s_data(&public_key));
            data.insert(private_key_name, encode_k8s_data(&resolved.private_hex));

            K8sSecretManifest {
                api_version: "v1".to_string(),
                kind: "Secret".to_string(),
                metadata: K8sMetadata { name, namespace },
                secret_type: "Opaque".to_string(),
                data,
            }
        }
        RecipientMetadata::RecipientKeyV3(recipient) => {
            let bundle = load_v3_key_bundle_cli(&recipient.key_id, ctx.keydir.as_deref())?;
            let mut data = BTreeMap::new();
            data.insert("ENCJSON_KEY_VERSION".to_string(), encode_k8s_data("3"));
            data.insert(
                "ENCJSON_X25519_PUBLIC".to_string(),
                encode_k8s_data(&bundle.x25519.public_hex),
            );
            data.insert(
                "ENCJSON_X25519_PRIVATE".to_string(),
                encode_k8s_data(&bundle.x25519.private_hex),
            );
            data.insert(
                "ENCJSON_MLKEM768_PUBLIC".to_string(),
                encode_k8s_data(&bundle.mlkem768.public_b64),
            );
            data.insert(
                "ENCJSON_MLKEM768_PRIVATE".to_string(),
                encode_k8s_data(&bundle.mlkem768.private_b64),
            );

            K8sSecretManifest {
                api_version: "v1".to_string(),
                kind: "Secret".to_string(),
                metadata: K8sMetadata { name, namespace },
                secret_type: "Opaque".to_string(),
                data,
            }
        }
    };
    let yaml = serde_yaml_ng::to_string(&manifest)
        .map_err(|e| Error::Http(format!("failed to serialize secret YAML: {e}")))?;
    if let Some(path) = output {
        fs::write(&path, yaml)
            .map_err(|e| Error::Http(format!("failed to write {}: {e}", path.display())))?;
    } else {
        print!("{yaml}");
    }
    Ok(())
}

fn build_secret_manifests(
    env_obj: &serde_json::Map<String, Value>,
    namespace: Option<&str>,
    secret_name: Option<&str>,
    secret_type: K8sSecretType,
    mappings: &[(String, String)],
    mappings_multi: &[(String, String, String)],
) -> Result<Vec<K8sSecretManifest>> {
    if !mappings.is_empty() && !mappings_multi.is_empty() {
        return Err(Error::Http(
            "use either --from-env or --from-env-secret, not both".to_string(),
        ));
    }

    if !mappings_multi.is_empty() {
        let mut grouped: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
        for (env_key, secret_name, secret_key) in mappings_multi {
            let value = env_obj.get(env_key).ok_or_else(|| {
                Error::Http(format!(
                    "missing env key '{}' for --from-env-secret mapping",
                    env_key
                ))
            })?;
            let value = value.as_str().ok_or_else(|| {
                Error::Http(format!(
                    "env key '{}' is not a string and cannot be written to secret",
                    env_key
                ))
            })?;
            grouped
                .entry(secret_name.clone())
                .or_default()
                .insert(secret_key.clone(), value.to_string());
        }
        let mut manifests = Vec::new();
        for (name, plain_map) in grouped {
            if secret_type == K8sSecretType::KubernetesIoTls {
                validate_tls_required_keys(&plain_map)?;
            }
            manifests.push(K8sSecretManifest {
                api_version: "v1".to_string(),
                kind: "Secret".to_string(),
                metadata: K8sMetadata {
                    name,
                    namespace: namespace.map(|v| v.to_string()),
                },
                secret_type: secret_type.as_str().to_string(),
                data: encode_k8s_data_map(&plain_map),
            });
        }
        return Ok(manifests);
    }

    let Some(secret_name) = secret_name else {
        return Err(Error::Http(
            "--name is required unless --from-env-secret is used".to_string(),
        ));
    };

    let mut plain_data = BTreeMap::new();
    if mappings.is_empty() {
        for (k, v) in env_obj {
            if let Some(s) = v.as_str() {
                plain_data.insert(k.clone(), s.to_string());
            }
        }
    } else {
        for (env_key, secret_key) in mappings {
            let value = env_obj.get(env_key).ok_or_else(|| {
                Error::Http(format!(
                    "missing env key '{}' for --from-env mapping",
                    env_key
                ))
            })?;
            let value = value.as_str().ok_or_else(|| {
                Error::Http(format!(
                    "env key '{}' is not a string and cannot be written to secret",
                    env_key
                ))
            })?;
            plain_data.insert(secret_key.clone(), value.to_string());
        }
    }

    if secret_type == K8sSecretType::KubernetesIoTls {
        validate_tls_required_keys(&plain_data)?;
    }

    Ok(vec![K8sSecretManifest {
        api_version: "v1".to_string(),
        kind: "Secret".to_string(),
        metadata: K8sMetadata {
            name: secret_name.to_string(),
            namespace: namespace.map(|v| v.to_string()),
        },
        secret_type: secret_type.as_str().to_string(),
        data: encode_k8s_data_map(&plain_data),
    }])
}

fn validate_tls_required_keys(plain_data: &BTreeMap<String, String>) -> Result<()> {
    for required in ["ca.crt", "tls.crt", "tls.key"] {
        if !plain_data.contains_key(required) {
            return Err(Error::Http(format!(
                "secret type kubernetes.io/tls requires key '{}'",
                required
            )));
        }
    }
    Ok(())
}

fn encode_k8s_data_map(plain_data: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    plain_data
        .iter()
        .map(|(k, v)| (k.clone(), encode_k8s_data(v)))
        .collect()
}

fn encode_k8s_data(value: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(value.as_bytes())
}

fn parse_from_env_mappings(items: &[String]) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for item in items {
        let Some((left, right)) = item.split_once('=') else {
            return Err(Error::Http(format!(
                "invalid --from-env '{}', expected ENV_KEY=secretKey",
                item
            )));
        };
        let env_key = left.trim();
        let secret_key = right.trim();
        if env_key.is_empty() || secret_key.is_empty() {
            return Err(Error::Http(format!(
                "invalid --from-env '{}', expected ENV_KEY=secretKey",
                item
            )));
        }
        out.push((env_key.to_string(), secret_key.to_string()));
    }
    Ok(out)
}

fn parse_from_env_secret_mappings(items: &[String]) -> Result<Vec<(String, String, String)>> {
    let mut out = Vec::new();
    for item in items {
        let Some((left, right)) = item.split_once('=') else {
            return Err(Error::Http(format!(
                "invalid --from-env-secret '{}', expected ENV_KEY=secretName/secretKey",
                item
            )));
        };
        let env_key = left.trim();
        let Some((secret_name, secret_key)) = right.split_once('/') else {
            return Err(Error::Http(format!(
                "invalid --from-env-secret '{}', expected ENV_KEY=secretName/secretKey",
                item
            )));
        };
        let secret_name = secret_name.trim();
        let secret_key = secret_key.trim();
        if env_key.is_empty() || secret_name.is_empty() || secret_key.is_empty() {
            return Err(Error::Http(format!(
                "invalid --from-env-secret '{}', expected ENV_KEY=secretName/secretKey",
                item
            )));
        }
        out.push((
            env_key.to_string(),
            secret_name.to_string(),
            secret_key.to_string(),
        ));
    }
    Ok(out)
}

fn init_tracing(force_debug: bool) {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let filter = if force_debug {
            tracing_subscriber::EnvFilter::new("debug")
        } else {
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("debug"))
        };
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .with_target(false)
            .with_level(true)
            .init();
    });
}

fn cmd_edit(
    file: Option<PathBuf>,
    input: Option<PathBuf>,
    keydir: Option<PathBuf>,
    _ui: bool,
    web: bool,
) -> Result<()> {
    let effective_path = file.or(input);
    let Some(path) = effective_path else {
        return Err(Error::EditRequiresFile);
    };
    if path.as_os_str() == OsStr::new("-") {
        return Err(Error::EditRequiresFile);
    }
    if web {
        return Err(Error::UnsupportedEditMode);
    }
    run_edit_ui(&path, keydir)
}

fn cmd_set(
    input: FileInput,
    key: String,
    value: String,
    json_value: bool,
    write: bool,
    ctx: &ResolveCtx<'_>,
) -> Result<()> {
    let effective_path = input.file.or(input.input);
    let mut root = read_json(effective_path.as_ref())?;
    let legacy_api2 = contains_api_version(&root, "2.0");

    // Resolve env root key once (`environment` preferred, then `env`).
    let env_key = {
        let obj = root.as_object().ok_or(Error::MissingEnvObject)?;
        if obj.contains_key("environment") {
            "environment"
        } else if obj.contains_key("env") {
            "env"
        } else {
            return Err(Error::MissingEnvObject);
        }
    };

    let crypto = resolve_json_crypto(&root, ctx)?;

    // For secured files, decrypt only env subtree, update, then re-encrypt only that subtree.
    match &crypto {
        ResolvedJsonCrypto::None => {}
        ResolvedJsonCrypto::Legacy { sb, .. } => {
            let env_value = root.get_mut(env_key).ok_or(Error::MissingEnvObject)?;
            transform_json(env_value, sb, TransformMode::Decrypt)?;
        }
        ResolvedJsonCrypto::V3 { sb } => {
            let env_value = root.get_mut(env_key).ok_or(Error::MissingEnvObject)?;
            transform_json_v3(env_value, sb, TransformMode::Decrypt)?;
        }
    }

    let env_obj = root
        .get_mut(env_key)
        .and_then(Value::as_object_mut)
        .ok_or(Error::MissingEnvObject)?;
    let parsed_value = if json_value {
        serde_json::from_str::<Value>(&value)?
    } else {
        Value::String(value)
    };
    env_obj.insert(key, parsed_value);

    match &crypto {
        ResolvedJsonCrypto::None => {}
        ResolvedJsonCrypto::Legacy { sb, .. } => {
            let env_value = root.get_mut(env_key).ok_or(Error::MissingEnvObject)?;
            transform_json(env_value, sb, TransformMode::Encrypt)?;
        }
        ResolvedJsonCrypto::V3 { sb } => {
            let env_value = root.get_mut(env_key).ok_or(Error::MissingEnvObject)?;
            transform_json_v3(env_value, sb, TransformMode::Encrypt)?;
        }
    }

    write_json_to(effective_path.as_ref(), write, &root)?;
    if legacy_api2 {
        print_legacy_api2_warning();
    }
    Ok(())
}

fn cmd_unset(input: FileInput, key: String, write: bool, ctx: &ResolveCtx<'_>) -> Result<()> {
    let effective_path = input.file.or(input.input);
    let mut root = read_json(effective_path.as_ref())?;
    let legacy_api2 = contains_api_version(&root, "2.0");

    let env_key = {
        let obj = root.as_object().ok_or(Error::MissingEnvObject)?;
        if obj.contains_key("environment") {
            "environment"
        } else if obj.contains_key("env") {
            "env"
        } else {
            return Err(Error::MissingEnvObject);
        }
    };

    let crypto = resolve_json_crypto(&root, ctx)?;

    match &crypto {
        ResolvedJsonCrypto::None => {}
        ResolvedJsonCrypto::Legacy { sb, .. } => {
            let env_value = root.get_mut(env_key).ok_or(Error::MissingEnvObject)?;
            transform_json(env_value, sb, TransformMode::Decrypt)?;
        }
        ResolvedJsonCrypto::V3 { sb } => {
            let env_value = root.get_mut(env_key).ok_or(Error::MissingEnvObject)?;
            transform_json_v3(env_value, sb, TransformMode::Decrypt)?;
        }
    }

    let env_obj = root
        .get_mut(env_key)
        .and_then(Value::as_object_mut)
        .ok_or(Error::MissingEnvObject)?;
    env_obj.remove(&key);

    match &crypto {
        ResolvedJsonCrypto::None => {}
        ResolvedJsonCrypto::Legacy { sb, .. } => {
            let env_value = root.get_mut(env_key).ok_or(Error::MissingEnvObject)?;
            transform_json(env_value, sb, TransformMode::Encrypt)?;
        }
        ResolvedJsonCrypto::V3 { sb } => {
            let env_value = root.get_mut(env_key).ok_or(Error::MissingEnvObject)?;
            transform_json_v3(env_value, sb, TransformMode::Encrypt)?;
        }
    }

    write_json_to(effective_path.as_ref(), write, &root)?;
    if legacy_api2 {
        print_legacy_api2_warning();
    }
    Ok(())
}

fn cmd_rekey(
    input: FileInput,
    recipient_key_id: Option<&str>,
    write: bool,
    ctx: &ResolveCtx<'_>,
) -> Result<()> {
    let effective_path = input.file.or(input.input);
    let mut root = read_json(effective_path.as_ref())?;
    let target = effective_path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "stdin/stdout".to_string());
    match RecipientMetadata::parse(&root)? {
        RecipientMetadata::LegacyPublicKey(old_public) => {
            if recipient_key_id.is_some() {
                return Err(Error::Http(
                    "--recipient is supported only for api=3.0 rotate-key".to_string(),
                ));
            }
            let old_private = resolve_private_key_for_public(&old_public, ctx)?.private_hex;
            let old_sb = SecureBox::new_from_hex(&old_private, &old_public)?;
            transform_json(&mut root, &old_sb, TransformMode::Decrypt)?;

            // rotate-key always generates pair-consistent keys.
            let (new_private, new_public) = generate_pair_consistent_key_pair();
            let new_sb = SecureBox::new_from_hex(&new_private, &new_public)?;
            if let Some(obj) = root.as_object_mut() {
                obj.insert("_public_key".to_string(), Value::String(new_public.clone()));
            } else {
                return Err(Error::MissingEnvObject);
            }
            transform_json(&mut root, &new_sb, TransformMode::Encrypt)?;
            let key_path = save_private_key(&new_public, &new_private, ctx.keydir.as_deref())?;

            write_json_to(effective_path.as_ref(), write, &root)?;
            println!("OK rotate-key");
            println!("  target file: {target}");
            println!("  format     : 2.0 (legacy)");
            println!("  old public : {old_public}");
            println!("  new public : {new_public}");
            println!("  new key    : {}", key_path.display());
            if !write {
                println!("  output     : stdout (use -w to write file)");
            }
            Ok(())
        }
        RecipientMetadata::RecipientKeyV3(old_recipient) => {
            let old_bundle = load_v3_key_bundle_cli(&old_recipient.key_id, ctx.keydir.as_deref())?;
            let old_sb = HybridSecureBox::from_bundle(old_bundle);
            transform_json_v3(&mut root, &old_sb, TransformMode::Decrypt)?;

            let new_bundle = if let Some(key_id) = recipient_key_id {
                load_v3_key_bundle_cli(key_id, ctx.keydir.as_deref())?
            } else {
                generate_v3_key_bundle()?
            };
            let new_recipient = new_bundle.to_recipient_key();
            let new_sb = HybridSecureBox::from_bundle(new_bundle.clone());

            let old_obj = root.as_object_mut().ok_or(Error::MissingEnvObject)?;
            old_obj.remove("_recipient_key");
            let mut reordered = serde_json::Map::new();
            reordered.insert(
                "_recipient_key".to_string(),
                serde_json::to_value(&new_recipient)?,
            );
            for (key, value) in std::mem::take(old_obj) {
                reordered.insert(key, value);
            }
            *old_obj = reordered;

            transform_json_v3(&mut root, &new_sb, TransformMode::Encrypt)?;
            let key_path = save_v3_key_bundle(&new_bundle, ctx.keydir.as_deref())?;

            write_json_to(effective_path.as_ref(), write, &root)?;
            println!("OK rotate-key");
            println!("  target file: {target}");
            println!("  format     : 3.0");
            println!("  old key_id : {}", old_recipient.key_id);
            println!("  new key_id : {}", new_recipient.key_id);
            println!("  new key    : {}", key_path.display());
            if recipient_key_id.is_some() {
                println!("  recipient  : existing bundle");
            }
            if !write {
                println!("  output     : stdout (use -w to write file)");
            }
            Ok(())
        }
    }
}

fn cmd_migrate_format(
    input: FileInput,
    to: EncJsonApiVersion,
    recipient_key_id: Option<&str>,
    write: bool,
    ctx: &ResolveCtx<'_>,
) -> Result<()> {
    let effective_path = input.file.or(input.input);
    let mut root = read_json(effective_path.as_ref())?;

    if to != EncJsonApiVersion::V3_0 {
        return Err(Error::Http(
            "migrate-format currently supports only --to 3.0".to_string(),
        ));
    }

    let old_public = extract_public_key(&root)?.to_string();
    let old_private = resolve_private_key_for_public(&old_public, ctx)?.private_hex;
    let from_api = if contains_api_version(&root, "1.0") {
        if contains_api_version(&root, "2.0") {
            return Err(Error::Http(
                "mixed EncJson api=1.0 and api=2.0 values are not supported in one file"
                    .to_string(),
            ));
        }
        let old_sb = SecureBox::new_api1_from_hex(&old_private, &old_public)?;
        transform_json(&mut root, &old_sb, TransformMode::Decrypt)?;
        "1.0"
    } else {
        let old_sb = SecureBox::new_from_hex(&old_private, &old_public)?;
        transform_json(&mut root, &old_sb, TransformMode::Decrypt)?;
        "2.0"
    };

    let generated_bundle;
    let new_bundle = if let Some(key_id) = recipient_key_id {
        load_v3_key_bundle_cli(key_id, ctx.keydir.as_deref())?
    } else {
        generated_bundle = generate_v3_key_bundle()?;
        save_v3_key_bundle(&generated_bundle, ctx.keydir.as_deref())?;
        generated_bundle
    };
    let new_recipient = new_bundle.to_recipient_key();
    let new_sb = HybridSecureBox::from_bundle(new_bundle);

    let old_obj = root.as_object_mut().ok_or(Error::MissingEnvObject)?;
    old_obj.remove("_public_key");
    let mut reordered = serde_json::Map::new();
    reordered.insert(
        "_recipient_key".to_string(),
        serde_json::to_value(&new_recipient)?,
    );
    for (key, value) in std::mem::take(old_obj) {
        reordered.insert(key, value);
    }
    *old_obj = reordered;

    transform_json_v3(&mut root, &new_sb, TransformMode::Encrypt)?;
    write_json_to(effective_path.as_ref(), write, &root)?;

    let target = effective_path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "stdin/stdout".to_string());
    println!("OK migrate-format");
    println!("  target file: {target}");
    println!("  from api   : {from_api}");
    println!("  to api     : 3.0");
    println!("  old public : {old_public}");
    println!("  recipient  : {}", new_recipient.key_id);
    if recipient_key_id.is_none() {
        println!("  key bundle : generated automatically");
    }
    if !write {
        println!("  output     : stdout (use -w to write file)");
    }
    Ok(())
}

fn read_json(file: Option<&PathBuf>) -> Result<Value> {
    let text = match file {
        // explicitní stdin: -f - nebo pozicní "-"
        Some(path) if path.as_os_str() == OsStr::new("-") => {
            let mut buf = String::new();
            io::stdin().read_to_string(&mut buf)?;
            buf
        }
        // běžný soubor
        Some(path) => fs::read_to_string(path)?,
        // bez -f a bez pozicního argumentu => stdin
        None => {
            let mut buf = String::new();
            io::stdin().read_to_string(&mut buf)?;
            buf
        }
    };
    Ok(serde_json::from_str(&text)?)
}

fn write_json_to(path: Option<&PathBuf>, write_in_place: bool, value: &Value) -> Result<()> {
    let out = serde_json::to_string_pretty(value)?;
    if write_in_place {
        if let Some(p) = path {
            fs::write(p, out)?;
        } else {
            // `encjson decrypt -w` bez -f
            return Err(Error::WriteWithoutFile);
        }
    } else {
        println!("{out}");
    }
    Ok(())
}

fn load_sidecar_schema(file: Option<&PathBuf>) -> Result<Option<SidecarSchema>> {
    let Some(path) = file else {
        return Ok(None);
    };
    if path.as_os_str() == OsStr::new("-") {
        return Ok(None);
    }
    let sidecar_path = sidecar_schema_path(path);
    if !sidecar_path.exists() {
        return Ok(None);
    }
    let text = fs::read_to_string(&sidecar_path).map_err(|e| {
        Error::Http(format!(
            "failed to read sidecar schema {}: {e}",
            sidecar_path.display()
        ))
    })?;
    let parsed: SidecarSchema = serde_json::from_str(&text).map_err(|e| {
        Error::Http(format!(
            "invalid sidecar schema {}: {e}",
            sidecar_path.display()
        ))
    })?;
    Ok(Some(parsed))
}

fn sidecar_schema_path(path: &std::path::Path) -> PathBuf {
    let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let file_name = path
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string_lossy().into_owned());
    let schema_name = if let Some(stem) = file_name.strip_suffix(".json") {
        format!("{stem}.schema.json")
    } else {
        format!("{file_name}.schema.json")
    };
    parent.join(schema_name)
}

fn apply_sidecar_schema(root: &mut Value, schema: &SidecarSchema) -> Result<()> {
    for env_key in ["environment", "env"] {
        let Some(obj) = root.get_mut(env_key).and_then(Value::as_object_mut) else {
            continue;
        };
        let keys: Vec<String> = obj.keys().cloned().collect();
        for key in keys {
            let Some(rule) = select_sidecar_rule(schema, &key) else {
                continue;
            };
            let Some(raw) = obj.get(&key).and_then(Value::as_str) else {
                continue;
            };
            let mut transformed = raw.to_string();
            match rule.encoding.as_ref().unwrap_or(&SidecarEncoding::Plain) {
                SidecarEncoding::Plain => {}
                SidecarEncoding::Base64 => {
                    let bytes = base64::engine::general_purpose::STANDARD
                        .decode(transformed.trim())
                        .map_err(|e| {
                            Error::Http(format!("base64 decode failed for key {key}: {e}"))
                        })?;
                    transformed = String::from_utf8(bytes).map_err(|e| {
                        Error::Http(format!(
                            "decoded value for key {key} is not valid UTF-8: {e}"
                        ))
                    })?;
                }
            }
            if rule.normalize_line_endings {
                transformed = normalize_line_endings(&transformed);
            }
            obj.insert(key, Value::String(transformed));
        }
    }
    Ok(())
}

fn select_sidecar_rule<'a>(schema: &'a SidecarSchema, key: &str) -> Option<&'a SidecarRule> {
    let mut best: Option<(&SidecarRule, i32, usize)> = None;
    for (pattern, rule) in schema {
        let score = if pattern == "*" {
            Some((1, 0usize))
        } else if pattern.ends_with('*') {
            let prefix = &pattern[..pattern.len().saturating_sub(1)];
            if key.starts_with(prefix) {
                Some((2, prefix.len()))
            } else {
                None
            }
        } else if pattern == key {
            Some((3, pattern.len()))
        } else {
            None
        };
        let Some((kind, len)) = score else {
            continue;
        };
        match best {
            Some((_, best_kind, best_len))
                if kind < best_kind || (kind == best_kind && len <= best_len) => {}
            _ => best = Some((rule, kind, len)),
        }
    }
    best.map(|(rule, _, _)| rule)
}

fn normalize_line_endings(value: &str) -> String {
    value.replace("\r\n", "\n").replace('\r', "\n")
}

enum ResolvedJsonCrypto {
    None,
    Legacy { sb: SecureBox, pair_mismatch: bool },
    V3 { sb: HybridSecureBox },
}

fn resolve_json_crypto(root: &Value, ctx: &ResolveCtx<'_>) -> Result<ResolvedJsonCrypto> {
    match RecipientMetadata::parse(root) {
        Ok(RecipientMetadata::LegacyPublicKey(public_key_hex)) => {
            let api1 = contains_api_version(root, "1.0");
            let api2 = contains_api_version(root, "2.0");
            if api1 && api2 {
                return Err(Error::Http(
                    "mixed EncJson api=1.0 and api=2.0 values are not supported in one file"
                        .to_string(),
                ));
            }
            let resolved = resolve_private_key_for_public(&public_key_hex, ctx)?;
            let sb = if api1 {
                SecureBox::new_api1_from_hex(&resolved.private_hex, &public_key_hex)?
            } else {
                SecureBox::new_from_hex(&resolved.private_hex, &public_key_hex)?
            };
            Ok(ResolvedJsonCrypto::Legacy {
                sb,
                pair_mismatch: !resolved.pair_consistent,
            })
        }
        Ok(RecipientMetadata::RecipientKeyV3(recipient)) => {
            let bundle = load_v3_key_bundle_cli(&recipient.key_id, ctx.keydir.as_deref())?;
            Ok(ResolvedJsonCrypto::V3 {
                sb: HybridSecureBox::from_bundle(bundle),
            })
        }
        Err(Error::MissingRecipientMetadata) => Ok(ResolvedJsonCrypto::None),
        Err(err) => Err(err),
    }
}

fn input_path_uses_api_version(path: Option<&PathBuf>, version: &str) -> Result<bool> {
    let Some(path) = path else {
        return Ok(false);
    };
    if path.as_os_str() == OsStr::new("-") {
        return Ok(false);
    }
    let root = read_json(Some(path))?;
    Ok(contains_api_version(&root, version))
}

fn print_legacy_api1_warning() {
    emit_warning(
        "legacy EncJson api=1.0 detected; migrate to api=3.0 with `encjson migrate-format -f <file> --to 3.0 -w`.",
    );
}

fn print_legacy_api2_warning() {
    emit_warning(
        "legacy EncJson api=2.0 detected; migrate to api=3.0 with `encjson migrate-format -f <file> --to 3.0 -w`.",
    );
}

/// Extract `_public_key` from JSON and validate length (64 hex chars).
pub(crate) fn extract_public_key(root: &Value) -> Result<&str> {
    match RecipientMetadata::parse(root) {
        Err(Error::MissingRecipientMetadata) => Err(Error::MissingPublicKey),
        Err(err) => Err(err),
        Ok(RecipientMetadata::RecipientKeyV3(_)) => Err(Error::UnsupportedRecipientKey(
            "this command path still expects legacy `_public_key`; api=3.0 support is not wired here yet"
                .to_string(),
        )),
        Ok(RecipientMetadata::LegacyPublicKey(_)) => root
            .get("_public_key")
            .and_then(Value::as_str)
            .ok_or(Error::MissingPublicKey),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::{Mutex, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn empty_source_cfg() -> KeySourceRuntimeConfig {
        KeySourceRuntimeConfig::default()
    }

    fn cwd_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn unique_path(prefix: &str, suffix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "encjson-{prefix}-{}-{nanos}{suffix}",
            std::process::id()
        ))
    }

    #[test]
    fn parse_encrypt_accepts_short_keydir() {
        let cli = Cli::parse_from(["encjson", "encrypt", "-k", "keys-dir"]);
        match cli.command {
            Some(Commands::Encrypt { keydir, .. }) => {
                assert_eq!(keydir, Some(PathBuf::from("keys-dir")));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_decrypt_accepts_short_keydir() {
        let cli = Cli::parse_from(["encjson", "decrypt", "-k", "keys-dir"]);
        match cli.command {
            Some(Commands::Decrypt { keydir, .. }) => {
                assert_eq!(keydir, Some(PathBuf::from("keys-dir")));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_assets_list_accepts_short_keydir() {
        let cli = Cli::parse_from([
            "encjson",
            "assets",
            "list",
            "-k",
            "keys-dir",
            "-f",
            "assets.secured.json",
        ]);
        match cli.command {
            Some(Commands::Assets {
                command: AssetsCommand::List { keydir, .. },
            }) => {
                assert_eq!(keydir, Some(PathBuf::from("keys-dir")));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_assets_get_accepts_options() {
        let cli = Cli::parse_from([
            "encjson",
            "assets",
            "get",
            "-f",
            "assets.secured.json",
            "--path",
            "ssl/private-key.pem",
            "--base64",
            "-o",
            "out.pem.b64",
        ]);
        match cli.command {
            Some(Commands::Assets {
                command:
                    AssetsCommand::Get {
                        path,
                        base64,
                        output,
                        ..
                    },
            }) => {
                assert_eq!(path, "ssl/private-key.pem");
                assert!(base64);
                assert_eq!(output, Some(PathBuf::from("out.pem.b64")));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_assets_import_accepts_secured_mode() {
        let cli = Cli::parse_from([
            "encjson",
            "assets",
            "import",
            "--from-dir",
            "assets",
            "-o",
            "assets.secured.json",
            "--secured",
            "--public-key",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ]);
        match cli.command {
            Some(Commands::Assets {
                command:
                    AssetsCommand::Import {
                        secured,
                        unsecured,
                        public_key,
                        ..
                    },
            }) => {
                assert!(secured);
                assert!(!unsecured);
                assert_eq!(
                    public_key.as_deref(),
                    Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                );
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_env_accepts_short_keydir() {
        let cli = Cli::parse_from(["encjson", "env", "-k", "keys-dir"]);
        match cli.command {
            Some(Commands::Env { keydir, .. }) => {
                assert_eq!(keydir, Some(PathBuf::from("keys-dir")));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_info_accepts_short_keydir() {
        let cli = Cli::parse_from([
            "encjson",
            "info",
            "-k",
            "keys-dir",
            "-f",
            "env.secured.json",
        ]);
        match cli.command {
            Some(Commands::Info { keydir, .. }) => {
                assert_eq!(keydir, Some(PathBuf::from("keys-dir")));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_render_k8s_secret_accepts_options() {
        let cli = Cli::parse_from([
            "encjson",
            "render-k8s-secret",
            "-f",
            "mtls.secured.json",
            "--name",
            "mtls-test-api-api",
            "--namespace",
            "nac-test",
            "--from-env",
            "MTLS_TEST_API_TLS_CRT=tls.crt",
            "--from-env",
            "MTLS_TEST_API_TLS_KEY=tls.key",
            "--from-env",
            "MTLS_TEST_API_CA_CRT=ca.crt",
            "-k",
            "keys-dir",
        ]);
        match cli.command {
            Some(Commands::RenderK8sSecret {
                keydir,
                name,
                namespace,
                secret_type,
                from_env,
                from_env_secret,
                ..
            }) => {
                assert_eq!(keydir, Some(PathBuf::from("keys-dir")));
                assert_eq!(name.as_deref(), Some("mtls-test-api-api"));
                assert_eq!(namespace.as_deref(), Some("nac-test"));
                assert_eq!(secret_type, K8sSecretType::KubernetesIoTls);
                assert_eq!(from_env.len(), 3);
                assert!(from_env_secret.is_empty());
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_render_k8s_secret_accepts_multi_secret_mapping() {
        let cli = Cli::parse_from([
            "encjson",
            "render-k8s-secret",
            "-f",
            "mtls.secured.json",
            "--from-env-secret",
            "A=sec-a/tls.crt",
            "--from-env-secret",
            "B=sec-b/tls.key",
        ]);
        match cli.command {
            Some(Commands::RenderK8sSecret {
                name,
                from_env_secret,
                ..
            }) => {
                assert!(name.is_none());
                assert_eq!(from_env_secret.len(), 2);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_render_k8s_pair_secret_defaults() {
        let cli = Cli::parse_from([
            "encjson",
            "render-k8s-pair-secret",
            "-f",
            "env.secured.json",
            "--name",
            "app-secrets",
            "--namespace",
            "nac-test",
        ]);
        match cli.command {
            Some(Commands::RenderK8sPairSecret {
                name,
                namespace,
                public_key_name,
                private_key_name,
                ..
            }) => {
                assert_eq!(name, "app-secrets");
                assert_eq!(namespace.as_deref(), Some("nac-test"));
                assert_eq!(public_key_name, "public-key");
                assert_eq!(private_key_name, "private-key");
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_edit_accepts_short_keydir() {
        let cli = Cli::parse_from([
            "encjson", "edit", "-k", "keys-dir", "--ui", "-f", "env.json",
        ]);
        match cli.command {
            Some(Commands::Edit { keydir, .. }) => {
                assert_eq!(keydir, Some(PathBuf::from("keys-dir")));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_set_accepts_short_keydir() {
        let cli = Cli::parse_from([
            "encjson",
            "set",
            "-k",
            "keys-dir",
            "-f",
            "env.json",
            "APP_DB_PASSWORD",
            "secret",
            "-w",
        ]);
        match cli.command {
            Some(Commands::Set { keydir, .. }) => {
                assert_eq!(keydir, Some(PathBuf::from("keys-dir")));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_unset_accepts_short_keydir() {
        let cli = Cli::parse_from([
            "encjson",
            "unset",
            "-k",
            "keys-dir",
            "-f",
            "env.json",
            "APP_DB_PASSWORD",
            "-w",
        ]);
        match cli.command {
            Some(Commands::Unset { keydir, .. }) => {
                assert_eq!(keydir, Some(PathBuf::from("keys-dir")));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_init_accepts_create_file() {
        let cli = Cli::parse_from(["encjson", "init", "--create-file"]);
        match cli.command {
            Some(Commands::Init { create_file, .. }) => {
                assert!(create_file);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_init_accepts_api_version() {
        let cli = Cli::parse_from(["encjson", "init", "--api", "3.0"]);
        match cli.command {
            Some(Commands::Init { api, .. }) => {
                assert_eq!(api, EncJsonApiVersion::V3_0);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_init_defaults_to_api_v3() {
        let cli = Cli::parse_from(["encjson", "init"]);
        match cli.command {
            Some(Commands::Init { api, .. }) => {
                assert_eq!(api, EncJsonApiVersion::V3_0);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_migrate_format_accepts_optional_recipient() {
        let cli = Cli::parse_from([
            "encjson",
            "migrate-format",
            "-f",
            "env.secured.json",
            "--to",
            "3.0",
            "-w",
        ]);
        match cli.command {
            Some(Commands::MigrateFormat {
                recipient,
                to,
                write,
                ..
            }) => {
                assert_eq!(to, EncJsonApiVersion::V3_0);
                assert!(write);
                assert!(recipient.is_none());
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_rotate_key_accepts_short_keydir() {
        let cli = Cli::parse_from([
            "encjson",
            "rotate-key",
            "-k",
            "keys-dir",
            "-f",
            "env.json",
            "-w",
        ]);
        match cli.command {
            Some(Commands::RotateKey { keydir, .. }) => {
                assert_eq!(keydir, Some(PathBuf::from("keys-dir")));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_rotate_key_accepts_optional_recipient() {
        let cli = Cli::parse_from([
            "encjson",
            "rotate-key",
            "-f",
            "env.json",
            "--recipient",
            "abc123",
            "-w",
        ]);
        match cli.command {
            Some(Commands::RotateKey {
                recipient, write, ..
            }) => {
                assert_eq!(recipient.as_deref(), Some("abc123"));
                assert!(write);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_register_accepts_secure_private_key_inputs() {
        let cli = Cli::parse_from([
            "encjson",
            "register",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--tenant",
            "demo",
            "--note",
            "bootstrap",
            "--private-key-file",
            "/tmp/private.key",
            "--allow-insecure-cli-private-key",
        ]);
        match cli.command {
            Some(Commands::Register {
                private_key_file,
                allow_insecure_cli_private_key,
                ..
            }) => {
                assert_eq!(private_key_file, Some(PathBuf::from("/tmp/private.key")));
                assert!(allow_insecure_cli_private_key);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_global_scope_options() {
        let cli = Cli::parse_from([
            "encjson",
            "decrypt",
            "--scope-required",
            "--tenant",
            "demo",
            "--env",
            "test",
        ]);
        match cli.command {
            Some(Commands::Decrypt { resolve, .. }) => {
                assert!(resolve.scope_required);
                assert_eq!(resolve.tenant.as_deref(), Some("demo"));
                assert_eq!(resolve.env_name.as_deref(), Some("test"));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_global_conjur_key_source_options() {
        let cli = Cli::parse_from([
            "encjson",
            "decrypt",
            "--key-source",
            "conjur",
            "--conjur-appliance-url",
            "https://conjur.example.com",
            "--conjur-account",
            "default",
            "--conjur-authn-login",
            "host%2Fapps%2Fencjson",
            "--conjur-authn-api-key",
            "api-key",
            "--conjur-public-variable-id",
            "data/encjson/public",
            "--conjur-private-variable-id",
            "data/encjson/private",
        ]);
        match cli.command {
            Some(Commands::Decrypt { resolve, .. }) => {
                assert!(matches!(resolve.key_source, Some(KeySourceCli::Conjur)));
                assert_eq!(
                    resolve.conjur_appliance_url.as_deref(),
                    Some("https://conjur.example.com")
                );
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn cmd_set_updates_unsecured_environment() {
        let path = unique_path("set", ".json");
        let source_cfg = empty_source_cfg();
        fs::write(&path, r#"{"environment":{"APP_A":"a","APP_B":"b"}}"#).unwrap();

        cmd_set(
            FileInput {
                file: Some(path.clone()),
                input: None,
            },
            "APP_B".to_string(),
            "new-b".to_string(),
            false,
            true,
            &ResolveCtx {
                keydir: None,
                private_key: None,
                source_cfg: &source_cfg,
                legacy_mode: true,
            },
        )
        .unwrap();

        let root: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let env = root.get("environment").unwrap().as_object().unwrap();
        assert_eq!(env.get("APP_A").unwrap().as_str(), Some("a"));
        assert_eq!(env.get("APP_B").unwrap().as_str(), Some("new-b"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn cmd_set_json_value_stores_number() {
        let path = unique_path("set-json", ".json");
        let source_cfg = empty_source_cfg();
        fs::write(&path, r#"{"environment":{"APP_PUBLIC_PORT":443}}"#).unwrap();

        cmd_set(
            FileInput {
                file: Some(path.clone()),
                input: None,
            },
            "APP_PUBLIC_PORT".to_string(),
            "8443".to_string(),
            true,
            true,
            &ResolveCtx {
                keydir: None,
                private_key: None,
                source_cfg: &source_cfg,
                legacy_mode: true,
            },
        )
        .unwrap();

        let root: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let env = root.get("environment").unwrap().as_object().unwrap();
        assert_eq!(env.get("APP_PUBLIC_PORT").unwrap().as_i64(), Some(8443));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn cmd_unset_removes_key_from_env_alias() {
        let path = unique_path("unset", ".json");
        let source_cfg = empty_source_cfg();
        fs::write(&path, r#"{"env":{"APP_A":"a","APP_B":"b"}}"#).unwrap();

        cmd_unset(
            FileInput {
                file: Some(path.clone()),
                input: None,
            },
            "APP_A".to_string(),
            true,
            &ResolveCtx {
                keydir: None,
                private_key: None,
                source_cfg: &source_cfg,
                legacy_mode: true,
            },
        )
        .unwrap();

        let root: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let env = root.get("env").unwrap().as_object().unwrap();
        assert!(env.get("APP_A").is_none());
        assert_eq!(env.get("APP_B").unwrap().as_str(), Some("b"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn cmd_set_errors_when_env_object_missing() {
        let path = unique_path("set-missing-env", ".json");
        let source_cfg = empty_source_cfg();
        fs::write(&path, r#"{"foo":"bar"}"#).unwrap();

        let err = cmd_set(
            FileInput {
                file: Some(path.clone()),
                input: None,
            },
            "APP_A".to_string(),
            "x".to_string(),
            false,
            true,
            &ResolveCtx {
                keydir: None,
                private_key: None,
                source_cfg: &source_cfg,
                legacy_mode: true,
            },
        )
        .unwrap_err();
        assert!(matches!(err, Error::MissingEnvObject));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn cmd_set_and_decrypt_json_with_sidecar_roundtrip_for_v3() {
        let key_dir = unique_path("v3-keys", "");
        fs::create_dir_all(&key_dir).unwrap();
        let path = unique_path("v3-set", ".secured.json");
        let source_cfg = empty_source_cfg();

        let bundle = encjson_core::crypto::generate_v3_key_bundle().unwrap();
        let recipient = bundle.to_recipient_key();
        save_v3_key_bundle(&bundle, Some(&key_dir)).unwrap();

        fs::write(
            &path,
            serde_json::to_string_pretty(&serde_json::json!({
                    "_recipient_key": recipient,
                    "environment": {
                    "APP_DB_PASSWORD": "secret"
                }
            }))
            .unwrap(),
        )
        .unwrap();

        cmd_set(
            FileInput {
                file: Some(path.clone()),
                input: None,
            },
            "APP_DB_PASSWORD".to_string(),
            "new-secret".to_string(),
            false,
            true,
            &ResolveCtx {
                keydir: Some(key_dir.clone()),
                private_key: None,
                source_cfg: &source_cfg,
                legacy_mode: true,
            },
        )
        .unwrap();

        let stored: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert!(
            stored
                .get("environment")
                .and_then(|v| v.get("APP_DB_PASSWORD"))
                .and_then(Value::as_str)
                .unwrap()
                .starts_with("EncJson[@api=3.0:@box=")
        );

        let (decrypted, pair_mismatch, _) = decrypt_json_with_sidecar(
            Some(&path),
            &ResolveCtx {
                keydir: Some(key_dir.clone()),
                private_key: None,
                source_cfg: &source_cfg,
                legacy_mode: true,
            },
        )
        .unwrap();

        assert!(!pair_mismatch);
        assert_eq!(
            decrypted
                .get("environment")
                .and_then(|v| v.get("APP_DB_PASSWORD"))
                .and_then(Value::as_str),
            Some("new-secret")
        );

        let _ = fs::remove_file(path);
        let _ = fs::remove_dir_all(key_dir);
    }

    #[test]
    fn cmd_encrypt_upgrades_legacy_public_key_metadata_when_it_points_to_v3_bundle() {
        let key_dir = unique_path("encrypt-v3-legacy-metadata-keys", "");
        fs::create_dir_all(&key_dir).unwrap();
        let path = unique_path("encrypt-v3-legacy-metadata", ".secured.json");
        let source_cfg = empty_source_cfg();

        let bundle = encjson_core::crypto::generate_v3_key_bundle().unwrap();
        let key_id = bundle.key_id.clone();
        save_v3_key_bundle(&bundle, Some(&key_dir)).unwrap();

        fs::write(
            &path,
            serde_json::to_string_pretty(&serde_json::json!({
                "_public_key": key_id,
                "environment": {
                    "APP_DB_USER": "hello"
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let ctx = ResolveCtx {
            keydir: Some(key_dir.clone()),
            private_key: None,
            source_cfg: &source_cfg,
            legacy_mode: true,
        };

        cmd_encrypt(
            FileInput {
                file: Some(path.clone()),
                input: None,
            },
            true,
            &ctx,
            false,
        )
        .unwrap();

        let encrypted: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert!(encrypted.get("_public_key").is_none());
        assert_eq!(
            encrypted
                .get("_recipient_key")
                .and_then(|v| v.get("key_id"))
                .and_then(Value::as_str),
            Some(key_id.as_str())
        );
        assert!(
            encrypted
                .get("environment")
                .and_then(|v| v.get("APP_DB_USER"))
                .and_then(Value::as_str)
                .unwrap()
                .starts_with("EncJson[@api=3.0:@box=")
        );

        let (decrypted, pair_mismatch, _) = decrypt_json_with_sidecar(Some(&path), &ctx).unwrap();
        assert!(!pair_mismatch);
        assert_eq!(
            decrypted
                .get("environment")
                .and_then(|v| v.get("APP_DB_USER"))
                .and_then(Value::as_str),
            Some("hello")
        );

        let _ = fs::remove_file(path);
        let _ = fs::remove_dir_all(key_dir);
    }

    #[test]
    fn cmd_rotate_key_rewrites_public_key() {
        let dir = unique_path("rotate-key-dir", "");
        let source_cfg = empty_source_cfg();
        fs::create_dir_all(&dir).unwrap();

        let (old_private, old_public) = encjson_core::crypto::generate_key_pair();
        save_private_key(&old_public, &old_private, Some(&dir)).unwrap();

        let path = unique_path("rotate-key-file", ".json");
        fs::write(
            &path,
            format!(
                r#"{{"_public_key":"{old_public}","environment":{{"APP_DB_PASSWORD":"secret"}}}}"#
            ),
        )
        .unwrap();

        cmd_rekey(
            FileInput {
                file: Some(path.clone()),
                input: None,
            },
            None,
            true,
            &ResolveCtx {
                keydir: Some(dir.clone()),
                private_key: None,
                source_cfg: &source_cfg,
                legacy_mode: true,
            },
        )
        .unwrap();

        let root: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let new_public = root.get("_public_key").and_then(Value::as_str).unwrap();
        assert_ne!(new_public, old_public);
        assert!(dir.join(new_public).exists());

        let _ = fs::remove_file(path);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn cmd_rotate_key_generates_pair_consistent_key() {
        let dir = unique_path("rotate-key-consistent-dir", "");
        let source_cfg = empty_source_cfg();
        fs::create_dir_all(&dir).unwrap();

        let (old_private, old_public) = encjson_core::crypto::generate_key_pair();
        save_private_key(&old_public, &old_private, Some(&dir)).unwrap();

        let path = unique_path("rotate-key-consistent-file", ".json");
        fs::write(
            &path,
            format!(
                r#"{{"_public_key":"{old_public}","environment":{{"APP_DB_PASSWORD":"secret"}}}}"#
            ),
        )
        .unwrap();

        cmd_rekey(
            FileInput {
                file: Some(path.clone()),
                input: None,
            },
            None,
            true,
            &ResolveCtx {
                keydir: Some(dir.clone()),
                private_key: None,
                source_cfg: &source_cfg,
                legacy_mode: true,
            },
        )
        .unwrap();

        let root: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let new_public = root
            .get("_public_key")
            .and_then(Value::as_str)
            .unwrap()
            .to_string();
        let new_private = fs::read_to_string(dir.join(&new_public)).unwrap();
        let derived = derive_public_hex_from_private(new_private.trim()).unwrap();
        assert_eq!(derived, new_public);

        let _ = fs::remove_file(path);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn cmd_rotate_key_rewrites_recipient_key_for_v3() {
        let dir = unique_path("rotate-key-v3-dir", "");
        let source_cfg = empty_source_cfg();
        fs::create_dir_all(&dir).unwrap();

        let bundle = encjson_core::crypto::generate_v3_key_bundle().unwrap();
        let old_key_id = bundle.key_id.clone();
        let recipient = bundle.to_recipient_key();
        save_v3_key_bundle(&bundle, Some(&dir)).unwrap();

        let path = unique_path("rotate-key-v3-file", ".json");
        fs::write(
            &path,
            serde_json::to_string_pretty(&serde_json::json!({
                    "_recipient_key": recipient,
                    "environment": {
                    "APP_DB_PASSWORD": "secret"
                }
            }))
            .unwrap(),
        )
        .unwrap();

        cmd_set(
            FileInput {
                file: Some(path.clone()),
                input: None,
            },
            "APP_DB_PASSWORD".to_string(),
            "old-secret".to_string(),
            false,
            true,
            &ResolveCtx {
                keydir: Some(dir.clone()),
                private_key: None,
                source_cfg: &source_cfg,
                legacy_mode: true,
            },
        )
        .unwrap();

        cmd_rekey(
            FileInput {
                file: Some(path.clone()),
                input: None,
            },
            None,
            true,
            &ResolveCtx {
                keydir: Some(dir.clone()),
                private_key: None,
                source_cfg: &source_cfg,
                legacy_mode: true,
            },
        )
        .unwrap();

        let root: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let new_recipient = root.get("_recipient_key").unwrap();
        let new_key_id = new_recipient.get("key_id").and_then(Value::as_str).unwrap();
        assert_ne!(new_key_id, old_key_id);
        assert!(dir.join(new_key_id).exists());
        assert_eq!(
            root.as_object().unwrap().keys().next().map(String::as_str),
            Some("_recipient_key")
        );

        let (decrypted, pair_mismatch, _) = decrypt_json_with_sidecar(
            Some(&path),
            &ResolveCtx {
                keydir: Some(dir.clone()),
                private_key: None,
                source_cfg: &source_cfg,
                legacy_mode: true,
            },
        )
        .unwrap();

        assert!(!pair_mismatch);
        assert_eq!(
            decrypted
                .get("environment")
                .and_then(|v| v.get("APP_DB_PASSWORD"))
                .and_then(Value::as_str),
            Some("old-secret")
        );

        let _ = fs::remove_file(path);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn cmd_rotate_key_uses_explicit_recipient_for_v3() {
        let dir = unique_path("rotate-key-v3-explicit-dir", "");
        let source_cfg = empty_source_cfg();
        fs::create_dir_all(&dir).unwrap();

        let source_bundle = encjson_core::crypto::generate_v3_key_bundle().unwrap();
        let source_recipient = source_bundle.to_recipient_key();
        save_v3_key_bundle(&source_bundle, Some(&dir)).unwrap();

        let target_bundle = encjson_core::crypto::generate_v3_key_bundle().unwrap();
        let target_key_id = target_bundle.key_id.clone();
        save_v3_key_bundle(&target_bundle, Some(&dir)).unwrap();

        let path = unique_path("rotate-key-v3-explicit-file", ".json");
        fs::write(
            &path,
            serde_json::to_string_pretty(&serde_json::json!({
                    "_recipient_key": source_recipient,
                    "environment": {
                    "APP_DB_PASSWORD": "secret"
                }
            }))
            .unwrap(),
        )
        .unwrap();

        cmd_set(
            FileInput {
                file: Some(path.clone()),
                input: None,
            },
            "APP_DB_PASSWORD".to_string(),
            "explicit-secret".to_string(),
            false,
            true,
            &ResolveCtx {
                keydir: Some(dir.clone()),
                private_key: None,
                source_cfg: &source_cfg,
                legacy_mode: true,
            },
        )
        .unwrap();

        cmd_rekey(
            FileInput {
                file: Some(path.clone()),
                input: None,
            },
            Some(&target_key_id),
            true,
            &ResolveCtx {
                keydir: Some(dir.clone()),
                private_key: None,
                source_cfg: &source_cfg,
                legacy_mode: true,
            },
        )
        .unwrap();

        let root: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let new_key_id = root
            .get("_recipient_key")
            .and_then(|v| v.get("key_id"))
            .and_then(Value::as_str)
            .unwrap();
        assert_eq!(new_key_id, target_key_id);

        let (decrypted, pair_mismatch, _) = decrypt_json_with_sidecar(
            Some(&path),
            &ResolveCtx {
                keydir: Some(dir.clone()),
                private_key: None,
                source_cfg: &source_cfg,
                legacy_mode: true,
            },
        )
        .unwrap();
        assert!(!pair_mismatch);
        assert_eq!(
            decrypted
                .get("environment")
                .and_then(|v| v.get("APP_DB_PASSWORD"))
                .and_then(Value::as_str),
            Some("explicit-secret")
        );

        let _ = fs::remove_file(path);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn cmd_init_v3_creates_recipient_key_file_and_template() {
        let _guard = cwd_lock().lock().unwrap();
        let prev_dir = std::env::current_dir().unwrap();
        let work_dir = unique_path("init-v3-work", "");
        let key_dir = unique_path("init-v3-keys", "");
        fs::create_dir_all(&work_dir).unwrap();
        fs::create_dir_all(&key_dir).unwrap();
        std::env::set_current_dir(&work_dir).unwrap();

        cmd_init(Some(key_dir.clone()), EncJsonApiVersion::V3_0, true).unwrap();

        let root: Value =
            serde_json::from_str(&fs::read_to_string(work_dir.join("env.secured.json")).unwrap())
                .unwrap();
        let recipient = root.get("_recipient_key").unwrap();
        let key_id = recipient.get("key_id").and_then(Value::as_str).unwrap();
        assert!(key_dir.join(key_id).exists());
        assert_eq!(recipient.get("version").and_then(Value::as_u64), Some(3));
        assert_eq!(root.get("environment"), Some(&serde_json::json!({})));

        std::env::set_current_dir(prev_dir).unwrap();
        let _ = fs::remove_dir_all(work_dir);
        let _ = fs::remove_dir_all(key_dir);
    }

    #[test]
    fn minimal_secured_templates_use_the_correct_api_metadata() {
        let legacy = minimal_secured_template_v2(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        assert_eq!(
            legacy.get("_public_key").and_then(Value::as_str),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
        assert!(legacy.get("_recipient_key").is_none());
        assert_eq!(legacy.get("environment"), Some(&serde_json::json!({})));

        let bundle = encjson_core::crypto::generate_v3_key_bundle().unwrap();
        let v3 = minimal_secured_template_v3(&bundle.to_recipient_key()).unwrap();
        assert!(v3.get("_public_key").is_none());
        assert_eq!(
            v3.get("_recipient_key")
                .and_then(|recipient| recipient.get("version"))
                .and_then(Value::as_u64),
            Some(3)
        );
        assert_eq!(v3.get("environment"), Some(&serde_json::json!({})));
    }

    #[test]
    fn cmd_render_k8s_pair_secret_outputs_v3_runtime_env_secret() {
        let path = unique_path("render-k8s-v3", ".json");
        let key_dir = unique_path("render-k8s-v3-keys", "");
        let output = unique_path("render-k8s-v3", ".yaml");
        fs::create_dir_all(&key_dir).unwrap();
        let source_cfg = empty_source_cfg();

        let bundle = encjson_core::crypto::generate_v3_key_bundle().unwrap();
        let recipient = bundle.to_recipient_key();
        save_v3_key_bundle(&bundle, Some(&key_dir)).unwrap();

        fs::write(
            &path,
            serde_json::to_string_pretty(&serde_json::json!({
                    "_recipient_key": recipient,
                    "environment": {
                    "APP_DB_PASSWORD": "secret"
                }
            }))
            .unwrap(),
        )
        .unwrap();

        cmd_render_k8s_pair_secret(
            FileInput {
                file: Some(path.clone()),
                input: None,
            },
            "my-secret".to_string(),
            Some("demo".to_string()),
            "PUBLIC_KEY".to_string(),
            "PRIVATE_KEY".to_string(),
            Some(output.clone()),
            &ResolveCtx {
                keydir: Some(key_dir.clone()),
                private_key: None,
                source_cfg: &source_cfg,
                legacy_mode: true,
            },
        )
        .unwrap();

        let manifest: K8sSecretManifest =
            serde_yaml_ng::from_str(&fs::read_to_string(&output).unwrap()).unwrap();
        assert_eq!(manifest.secret_type, "Opaque");
        assert_eq!(manifest.metadata.name, "my-secret");
        assert_eq!(manifest.metadata.namespace.as_deref(), Some("demo"));
        assert_eq!(
            manifest.data.get("ENCJSON_KEY_VERSION").unwrap(),
            &encode_k8s_data("3")
        );
        assert_eq!(
            manifest.data.get("ENCJSON_X25519_PUBLIC").unwrap(),
            &encode_k8s_data(&bundle.x25519.public_hex)
        );
        assert_eq!(
            manifest.data.get("ENCJSON_X25519_PRIVATE").unwrap(),
            &encode_k8s_data(&bundle.x25519.private_hex)
        );
        assert_eq!(
            manifest.data.get("ENCJSON_MLKEM768_PUBLIC").unwrap(),
            &encode_k8s_data(&bundle.mlkem768.public_b64)
        );
        assert_eq!(
            manifest.data.get("ENCJSON_MLKEM768_PRIVATE").unwrap(),
            &encode_k8s_data(&bundle.mlkem768.private_b64)
        );
        assert!(!manifest.data.contains_key("PUBLIC_KEY"));
        assert!(!manifest.data.contains_key("PRIVATE_KEY"));

        let _ = fs::remove_file(path);
        let _ = fs::remove_file(output);
        let _ = fs::remove_dir_all(key_dir);
    }

    #[test]
    fn cmd_render_k8s_pair_secret_keeps_legacy_shape_for_api_v2() {
        let path = unique_path("render-k8s-v2", ".json");
        let key_dir = unique_path("render-k8s-v2-keys", "");
        let output = unique_path("render-k8s-v2", ".yaml");
        fs::create_dir_all(&key_dir).unwrap();
        let source_cfg = empty_source_cfg();

        let (private_hex, public_hex) = encjson_core::crypto::generate_pair_consistent_key_pair();
        save_private_key(&public_hex, &private_hex, Some(&key_dir)).unwrap();
        fs::write(
            &path,
            serde_json::to_string_pretty(&serde_json::json!({
                    "_public_key": public_hex,
                    "environment": {
                    "APP_DB_PASSWORD": "secret"
                }
            }))
            .unwrap(),
        )
        .unwrap();

        cmd_render_k8s_pair_secret(
            FileInput {
                file: Some(path.clone()),
                input: None,
            },
            "legacy-secret".to_string(),
            None,
            "PUBLIC_KEY".to_string(),
            "PRIVATE_KEY".to_string(),
            Some(output.clone()),
            &ResolveCtx {
                keydir: Some(key_dir.clone()),
                private_key: None,
                source_cfg: &source_cfg,
                legacy_mode: true,
            },
        )
        .unwrap();

        let manifest: K8sSecretManifest =
            serde_yaml_ng::from_str(&fs::read_to_string(&output).unwrap()).unwrap();
        assert_eq!(
            manifest.data.get("PUBLIC_KEY").unwrap(),
            &encode_k8s_data(&public_hex)
        );
        assert_eq!(
            manifest.data.get("PRIVATE_KEY").unwrap(),
            &encode_k8s_data(&private_hex)
        );
        assert!(!manifest.data.contains_key("ENCJSON_KEY_VERSION"));

        let _ = fs::remove_file(path);
        let _ = fs::remove_file(output);
        let _ = fs::remove_dir_all(key_dir);
    }

    #[test]
    fn cmd_migrate_format_migrates_legacy_file_to_v3() {
        let key_dir = unique_path("migrate-v3-keys", "");
        fs::create_dir_all(&key_dir).unwrap();
        let path = unique_path("migrate-v3-file", ".secured.json");
        let source_cfg = empty_source_cfg();

        let (legacy_private, legacy_public) =
            encjson_core::crypto::generate_pair_consistent_key_pair();
        save_private_key(&legacy_public, &legacy_private, Some(&key_dir)).unwrap();

        fs::write(
            &path,
            format!(
                r#"{{"_public_key":"{legacy_public}","environment":{{"APP_DB_PASSWORD":"secret"}}}}"#
            ),
        )
        .unwrap();

        cmd_encrypt(
            FileInput {
                file: Some(path.clone()),
                input: None,
            },
            true,
            &ResolveCtx {
                keydir: Some(key_dir.clone()),
                private_key: None,
                source_cfg: &source_cfg,
                legacy_mode: true,
            },
            false,
        )
        .unwrap();

        let new_bundle = encjson_core::crypto::generate_v3_key_bundle().unwrap();
        let new_key_id = new_bundle.key_id.clone();
        save_v3_key_bundle(&new_bundle, Some(&key_dir)).unwrap();

        cmd_migrate_format(
            FileInput {
                file: Some(path.clone()),
                input: None,
            },
            EncJsonApiVersion::V3_0,
            Some(&new_key_id),
            true,
            &ResolveCtx {
                keydir: Some(key_dir.clone()),
                private_key: None,
                source_cfg: &source_cfg,
                legacy_mode: true,
            },
        )
        .unwrap();

        let migrated: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert!(migrated.get("_public_key").is_none());
        assert_eq!(
            migrated
                .get("_recipient_key")
                .and_then(|v| v.get("key_id"))
                .and_then(Value::as_str),
            Some(new_key_id.as_str())
        );
        assert!(
            migrated
                .get("environment")
                .and_then(|v| v.get("APP_DB_PASSWORD"))
                .and_then(Value::as_str)
                .unwrap()
                .starts_with("EncJson[@api=3.0:@box=")
        );

        let (decrypted, pair_mismatch, _) = decrypt_json_with_sidecar(
            Some(&path),
            &ResolveCtx {
                keydir: Some(key_dir.clone()),
                private_key: None,
                source_cfg: &source_cfg,
                legacy_mode: true,
            },
        )
        .unwrap();
        assert!(!pair_mismatch);
        assert_eq!(
            decrypted
                .get("environment")
                .and_then(|v| v.get("APP_DB_PASSWORD"))
                .and_then(Value::as_str),
            Some("secret")
        );

        let _ = fs::remove_file(path);
        let _ = fs::remove_dir_all(key_dir);
    }

    #[test]
    fn cmd_migrate_format_rejects_v3_source_file() {
        let key_dir = unique_path("migrate-v3-reject-keys", "");
        fs::create_dir_all(&key_dir).unwrap();
        let path = unique_path("migrate-v3-reject-file", ".secured.json");
        let source_cfg = empty_source_cfg();

        let bundle = encjson_core::crypto::generate_v3_key_bundle().unwrap();
        let recipient = bundle.to_recipient_key();
        save_v3_key_bundle(&bundle, Some(&key_dir)).unwrap();
        fs::write(
            &path,
            serde_json::to_string_pretty(&serde_json::json!({
                    "_recipient_key": recipient,
                    "environment": {
                    "APP_DB_PASSWORD": "secret"
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let err = cmd_migrate_format(
            FileInput {
                file: Some(path.clone()),
                input: None,
            },
            EncJsonApiVersion::V3_0,
            Some(&bundle.key_id),
            true,
            &ResolveCtx {
                keydir: Some(key_dir.clone()),
                private_key: None,
                source_cfg: &source_cfg,
                legacy_mode: true,
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("Unsupported `_recipient_key`"));

        let _ = fs::remove_file(path);
        let _ = fs::remove_dir_all(key_dir);
    }

    #[test]
    fn cmd_migrate_format_generates_v3_bundle_when_recipient_missing() {
        let key_dir = unique_path("migrate-v3-auto-keys", "");
        fs::create_dir_all(&key_dir).unwrap();
        let path = unique_path("migrate-v3-auto-file", ".secured.json");
        let source_cfg = empty_source_cfg();

        let (legacy_private, legacy_public) =
            encjson_core::crypto::generate_pair_consistent_key_pair();
        save_private_key(&legacy_public, &legacy_private, Some(&key_dir)).unwrap();

        fs::write(
            &path,
            format!(
                r#"{{"_public_key":"{legacy_public}","environment":{{"APP_DB_PASSWORD":"secret"}}}}"#
            ),
        )
        .unwrap();

        cmd_encrypt(
            FileInput {
                file: Some(path.clone()),
                input: None,
            },
            true,
            &ResolveCtx {
                keydir: Some(key_dir.clone()),
                private_key: None,
                source_cfg: &source_cfg,
                legacy_mode: true,
            },
            false,
        )
        .unwrap();

        let before = list_public_keys(Some(&key_dir)).unwrap();

        cmd_migrate_format(
            FileInput {
                file: Some(path.clone()),
                input: None,
            },
            EncJsonApiVersion::V3_0,
            None,
            true,
            &ResolveCtx {
                keydir: Some(key_dir.clone()),
                private_key: None,
                source_cfg: &source_cfg,
                legacy_mode: true,
            },
        )
        .unwrap();

        let after = list_public_keys(Some(&key_dir)).unwrap();
        assert_eq!(after.len(), before.len() + 1);

        let migrated: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let new_key_id = migrated
            .get("_recipient_key")
            .and_then(|v| v.get("key_id"))
            .and_then(Value::as_str)
            .unwrap();
        assert!(key_dir.join(new_key_id).exists());

        let _ = fs::remove_file(path);
        let _ = fs::remove_dir_all(key_dir);
    }

    #[test]
    fn assets_unsecured_import_and_load_roundtrip() {
        let src_dir = unique_path("assets-import-unsecured-src", "");
        let out_file = unique_path("assets-import-unsecured-out", ".unsecured.json");
        fs::create_dir_all(src_dir.join("ssl")).unwrap();
        fs::write(src_dir.join("ssl").join("cert.pem"), b"plain-cert").unwrap();

        let source_cfg = empty_source_cfg();
        import_assets_bundle(
            &src_dir,
            &out_file,
            AssetImportMode::Unsecured,
            None,
            &ResolveCtx {
                keydir: None,
                private_key: None,
                source_cfg: &source_cfg,
                legacy_mode: true,
            },
        )
        .unwrap();

        let bundle = load_assets_bundle(
            FileInput {
                file: Some(out_file.clone()),
                input: None,
            },
            &ResolveCtx {
                keydir: None,
                private_key: None,
                source_cfg: &source_cfg,
                legacy_mode: true,
            },
        )
        .unwrap();
        let bytes = decode_asset_base64(
            "ssl/cert.pem",
            &bundle.assets.get("ssl/cert.pem").unwrap().content,
        )
        .unwrap();
        assert_eq!(bytes, b"plain-cert");
        assert_eq!(
            effective_asset_kind(bundle.assets.get("ssl/cert.pem").unwrap()),
            AssetKind::Text
        );

        let _ = fs::remove_file(out_file);
        let _ = fs::remove_dir_all(src_dir);
    }

    #[test]
    fn assets_secured_import_uses_existing_public_key() {
        let src_dir = unique_path("assets-import-secured-src", "");
        let out_file = unique_path("assets-import-secured-out", ".secured.json");
        let key_dir = unique_path("assets-import-secured-keys", "");
        fs::create_dir_all(src_dir.join("ssl")).unwrap();
        fs::create_dir_all(&key_dir).unwrap();
        fs::write(src_dir.join("ssl").join("private-key.pem"), b"super-secret").unwrap();

        let (private_hex, public_hex) = generate_pair_consistent_key_pair();
        save_private_key(&public_hex, &private_hex, Some(&key_dir)).unwrap();

        let source_cfg = empty_source_cfg();
        import_assets_bundle(
            &src_dir,
            &out_file,
            AssetImportMode::Secured,
            Some(public_hex.clone()),
            &ResolveCtx {
                keydir: Some(key_dir.clone()),
                private_key: None,
                source_cfg: &source_cfg,
                legacy_mode: true,
            },
        )
        .unwrap();

        let root: Value = serde_json::from_str(&fs::read_to_string(&out_file).unwrap()).unwrap();
        assert_eq!(
            root.get("_public_key").and_then(Value::as_str),
            Some(public_hex.as_str())
        );
        let stored = root
            .get("assets")
            .and_then(Value::as_object)
            .unwrap()
            .get("ssl/private-key.pem")
            .and_then(Value::as_object)
            .and_then(|v| v.get("content"))
            .and_then(Value::as_str)
            .unwrap();
        assert!(stored.starts_with("EncJson[@api=2.0:@box="));
        assert_eq!(
            root.get("assets")
                .and_then(Value::as_object)
                .unwrap()
                .get("ssl/private-key.pem")
                .and_then(Value::as_object)
                .and_then(|v| v.get("kind"))
                .and_then(Value::as_str),
            Some("text")
        );

        fs::write(
            src_dir.join("ssl").join("private-key.pem"),
            b"super-secret-2",
        )
        .unwrap();
        import_assets_bundle(
            &src_dir,
            &out_file,
            AssetImportMode::Secured,
            None,
            &ResolveCtx {
                keydir: Some(key_dir.clone()),
                private_key: None,
                source_cfg: &source_cfg,
                legacy_mode: true,
            },
        )
        .unwrap();

        let bundle = load_assets_bundle(
            FileInput {
                file: Some(out_file.clone()),
                input: None,
            },
            &ResolveCtx {
                keydir: Some(key_dir.clone()),
                private_key: None,
                source_cfg: &source_cfg,
                legacy_mode: true,
            },
        )
        .unwrap();
        let bytes = decode_asset_base64(
            "ssl/private-key.pem",
            &bundle.assets.get("ssl/private-key.pem").unwrap().content,
        )
        .unwrap();
        assert_eq!(bytes, b"super-secret-2");
        assert_eq!(
            effective_asset_kind(bundle.assets.get("ssl/private-key.pem").unwrap()),
            AssetKind::Text
        );

        let _ = fs::remove_file(out_file);
        let _ = fs::remove_dir_all(src_dir);
        let _ = fs::remove_dir_all(key_dir);
    }

    #[test]
    fn validate_asset_path_rejects_absolute_and_parent_paths() {
        let err = validate_asset_path("/etc/passwd").unwrap_err();
        assert!(err.to_string().contains("must be relative"));

        let err = validate_asset_path("../secret.pem").unwrap_err();
        assert!(err.to_string().contains("must not contain '..'"));
    }

    #[test]
    fn infer_asset_import_mode_uses_output_suffix() {
        assert!(matches!(
            infer_asset_import_mode(Path::new("assets.secured.json")).unwrap(),
            AssetImportMode::Secured
        ));
        assert!(matches!(
            infer_asset_import_mode(Path::new("assets.unsecured.json")).unwrap(),
            AssetImportMode::Unsecured
        ));
    }

    #[test]
    fn infer_asset_import_mode_rejects_unknown_suffix() {
        let err = infer_asset_import_mode(Path::new("assets.json")).unwrap_err();
        assert!(err.to_string().contains("cannot infer asset bundle mode"));
    }

    #[test]
    fn export_assets_bundle_refuses_existing_file_without_overwrite() {
        let out_dir = unique_path("assets-export-out", "");
        fs::create_dir_all(out_dir.join("ssl")).unwrap();
        fs::write(out_dir.join("ssl").join("cert.pem"), b"old").unwrap();

        let mut assets = BTreeMap::new();
        assets.insert(
            "ssl/cert.pem".to_string(),
            AssetEntry {
                content: base64::engine::general_purpose::STANDARD.encode(b"new"),
                kind: Some(AssetKind::Text),
            },
        );
        let bundle = AssetsBundle { assets };

        let err = export_assets_bundle(&bundle, &out_dir, false).unwrap_err();
        assert!(err.to_string().contains("already exists"));

        let _ = fs::remove_dir_all(out_dir);
    }

    #[test]
    fn export_assets_bundle_writes_decoded_bytes() {
        let out_dir = unique_path("assets-export-write", "");
        let mut assets = BTreeMap::new();
        assets.insert(
            "ssl/cert.pem".to_string(),
            AssetEntry {
                content: base64::engine::general_purpose::STANDARD.encode(b"decoded-cert"),
                kind: Some(AssetKind::Text),
            },
        );
        let bundle = AssetsBundle { assets };

        export_assets_bundle(&bundle, &out_dir, false).unwrap();

        let bytes = fs::read(out_dir.join("ssl").join("cert.pem")).unwrap();
        assert_eq!(bytes, b"decoded-cert");

        let _ = fs::remove_dir_all(out_dir);
    }

    #[test]
    fn assets_import_marks_binary_kind() {
        let src_dir = unique_path("assets-import-binary-src", "");
        let out_file = unique_path("assets-import-binary-out", ".unsecured.json");
        fs::create_dir_all(src_dir.join("bin")).unwrap();
        fs::write(src_dir.join("bin").join("logo.bin"), [0_u8, 159, 146, 150]).unwrap();

        let source_cfg = empty_source_cfg();
        import_assets_bundle(
            &src_dir,
            &out_file,
            AssetImportMode::Unsecured,
            None,
            &ResolveCtx {
                keydir: None,
                private_key: None,
                source_cfg: &source_cfg,
                legacy_mode: true,
            },
        )
        .unwrap();

        let bundle = load_assets_bundle(
            FileInput {
                file: Some(out_file.clone()),
                input: None,
            },
            &ResolveCtx {
                keydir: None,
                private_key: None,
                source_cfg: &source_cfg,
                legacy_mode: true,
            },
        )
        .unwrap();
        assert_eq!(
            effective_asset_kind(bundle.assets.get("bin/logo.bin").unwrap()),
            AssetKind::Binary
        );

        let _ = fs::remove_file(out_file);
        let _ = fs::remove_dir_all(src_dir);
    }

    #[test]
    fn import_assets_bundle_requires_public_key_for_new_secured_bundle() {
        let src_dir = unique_path("assets-import-secured-missing-key-src", "");
        let out_file = unique_path("assets-import-secured-missing-key-out", ".secured.json");
        fs::create_dir_all(src_dir.join("ssl")).unwrap();
        fs::write(src_dir.join("ssl").join("private-key.pem"), b"super-secret").unwrap();

        let source_cfg = empty_source_cfg();
        let err = import_assets_bundle(
            &src_dir,
            &out_file,
            AssetImportMode::Secured,
            None,
            &ResolveCtx {
                keydir: None,
                private_key: None,
                source_cfg: &source_cfg,
                legacy_mode: true,
            },
        )
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("--public-key is required when creating a new secured assets bundle")
        );

        let _ = fs::remove_file(out_file);
        let _ = fs::remove_dir_all(src_dir);
    }

    #[test]
    fn import_assets_bundle_rejects_mismatched_existing_public_key() {
        let src_dir = unique_path("assets-import-secured-mismatch-src", "");
        let out_file = unique_path("assets-import-secured-mismatch-out", ".secured.json");
        let key_dir = unique_path("assets-import-secured-mismatch-keys", "");
        fs::create_dir_all(src_dir.join("ssl")).unwrap();
        fs::create_dir_all(&key_dir).unwrap();
        fs::write(src_dir.join("ssl").join("private-key.pem"), b"super-secret").unwrap();

        let (private_hex, public_hex) = generate_pair_consistent_key_pair();
        save_private_key(&public_hex, &private_hex, Some(&key_dir)).unwrap();

        let source_cfg = empty_source_cfg();
        import_assets_bundle(
            &src_dir,
            &out_file,
            AssetImportMode::Secured,
            Some(public_hex.clone()),
            &ResolveCtx {
                keydir: Some(key_dir.clone()),
                private_key: None,
                source_cfg: &source_cfg,
                legacy_mode: true,
            },
        )
        .unwrap();

        let (_, other_public_hex) = generate_pair_consistent_key_pair();
        let err = import_assets_bundle(
            &src_dir,
            &out_file,
            AssetImportMode::Secured,
            Some(other_public_hex),
            &ResolveCtx {
                keydir: Some(key_dir.clone()),
                private_key: None,
                source_cfg: &source_cfg,
                legacy_mode: true,
            },
        )
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("does not match existing _public_key")
        );

        let _ = fs::remove_file(out_file);
        let _ = fs::remove_dir_all(src_dir);
        let _ = fs::remove_dir_all(key_dir);
    }

    #[test]
    fn sidecar_schema_priority_exact_then_prefix_then_wildcard() {
        let mut schema = SidecarSchema::new();
        schema.insert(
            "*".to_string(),
            SidecarRule {
                encoding: Some(SidecarEncoding::Plain),
                normalize_line_endings: false,
            },
        );
        schema.insert(
            "MTLS_*".to_string(),
            SidecarRule {
                encoding: Some(SidecarEncoding::Base64),
                normalize_line_endings: false,
            },
        );
        schema.insert(
            "MTLS_A".to_string(),
            SidecarRule {
                encoding: Some(SidecarEncoding::Base64),
                normalize_line_endings: true,
            },
        );

        let exact = select_sidecar_rule(&schema, "MTLS_A").unwrap();
        assert!(exact.normalize_line_endings);

        let prefix = select_sidecar_rule(&schema, "MTLS_B").unwrap();
        assert!(!prefix.normalize_line_endings);
        assert!(matches!(
            prefix.encoding.as_ref().unwrap(),
            SidecarEncoding::Base64
        ));

        let wildcard = select_sidecar_rule(&schema, "OTHER").unwrap();
        assert!(matches!(
            wildcard.encoding.as_ref().unwrap(),
            SidecarEncoding::Plain
        ));
    }

    #[test]
    fn apply_sidecar_schema_decodes_base64_and_normalizes_crlf() {
        let mut schema = SidecarSchema::new();
        schema.insert(
            "MTLS_*".to_string(),
            SidecarRule {
                encoding: Some(SidecarEncoding::Base64),
                normalize_line_endings: true,
            },
        );
        let payload = base64::engine::general_purpose::STANDARD.encode("line1\r\nline2\rline3");
        let mut root = serde_json::json!({
            "environment": {
                "MTLS_CERT": payload
            }
        });
        apply_sidecar_schema(&mut root, &schema).unwrap();
        let out = root["environment"]["MTLS_CERT"].as_str().unwrap();
        assert_eq!(out, "line1\nline2\nline3");
    }

    #[test]
    fn parse_from_env_mappings_parses_pairs() {
        let out =
            parse_from_env_mappings(&["A=tls.crt".to_string(), "B=tls.key".to_string()]).unwrap();
        assert_eq!(out[0], ("A".to_string(), "tls.crt".to_string()));
        assert_eq!(out[1], ("B".to_string(), "tls.key".to_string()));
    }

    #[test]
    fn parse_from_env_secret_mappings_parses_triples() {
        let out = parse_from_env_secret_mappings(&[
            "A=sec-a/tls.crt".to_string(),
            "B=sec-b/tls.key".to_string(),
        ])
        .unwrap();
        assert_eq!(
            out[0],
            ("A".to_string(), "sec-a".to_string(), "tls.crt".to_string())
        );
        assert_eq!(
            out[1],
            ("B".to_string(), "sec-b".to_string(), "tls.key".to_string())
        );
    }

    #[test]
    fn build_secret_manifests_groups_multi_secret_mode() {
        let env_obj = serde_json::json!({
            "A": "crt",
            "B": "key",
            "C": "ca"
        })
        .as_object()
        .unwrap()
        .clone();
        let manifests = build_secret_manifests(
            &env_obj,
            Some("nac-test"),
            None,
            K8sSecretType::Opaque,
            &[],
            &[
                ("A".to_string(), "sec-a".to_string(), "tls.crt".to_string()),
                ("B".to_string(), "sec-a".to_string(), "tls.key".to_string()),
                ("C".to_string(), "sec-b".to_string(), "ca.crt".to_string()),
            ],
        )
        .unwrap();
        assert_eq!(manifests.len(), 2);
        assert_eq!(manifests[0].metadata.name, "sec-a");
        assert_eq!(manifests[1].metadata.name, "sec-b");
        assert_eq!(
            manifests[0].data.get("tls.crt").map(|s| s.as_str()),
            Some("Y3J0")
        );
        assert_eq!(
            manifests[0].data.get("tls.key").map(|s| s.as_str()),
            Some("a2V5")
        );
        assert_eq!(
            manifests[1].data.get("ca.crt").map(|s| s.as_str()),
            Some("Y2E=")
        );
    }

    #[test]
    fn build_secret_manifests_requires_secret_name_in_single_mode() {
        let env_obj = serde_json::json!({"A": "x"}).as_object().unwrap().clone();
        let err = build_secret_manifests(
            &env_obj,
            None,
            None,
            K8sSecretType::KubernetesIoTls,
            &[],
            &[],
        )
        .unwrap_err();
        assert!(format!("{err}").contains("--name is required"));
    }

    #[test]
    fn build_secret_manifests_tls_requires_standard_keys() {
        let env_obj = serde_json::json!({"A": "x"}).as_object().unwrap().clone();
        let err = build_secret_manifests(
            &env_obj,
            None,
            Some("sec"),
            K8sSecretType::KubernetesIoTls,
            &[],
            &[],
        )
        .unwrap_err();
        assert!(format!("{err}").contains("requires key 'ca.crt'"));
    }

    #[test]
    fn build_register_payload_from_local_key_uses_legacy_private_hex() {
        let key_dir = unique_path("register-legacy-keys", "");
        fs::create_dir_all(&key_dir).unwrap();
        let source_cfg = empty_source_cfg();

        let (private_hex, public_hex) = encjson_core::crypto::generate_pair_consistent_key_pair();
        save_private_key(&public_hex, &private_hex, Some(&key_dir)).unwrap();

        let payload = build_register_payload_from_local_key(
            &public_hex,
            "demo".to_string(),
            "legacy note".to_string(),
            vec!["a".to_string(), "b".to_string()],
            &ResolveCtx {
                keydir: Some(key_dir.clone()),
                private_key: None,
                source_cfg: &source_cfg,
                legacy_mode: true,
            },
        )
        .unwrap();

        match payload {
            RegisterPayload::Legacy(payload) => {
                assert_eq!(payload.public_hex, public_hex);
                assert_eq!(payload.private_hex, private_hex);
                assert_eq!(payload.tenant, "demo");
                assert_eq!(payload.note, "legacy note");
                assert_eq!(payload.tags, vec!["a", "b"]);
            }
            _ => panic!("expected legacy register payload"),
        }

        let _ = fs::remove_dir_all(key_dir);
    }

    #[test]
    fn build_register_payload_from_local_key_uses_v3_bundle() {
        let key_dir = unique_path("register-v3-keys", "");
        fs::create_dir_all(&key_dir).unwrap();
        let source_cfg = empty_source_cfg();

        let bundle = encjson_core::crypto::generate_v3_key_bundle().unwrap();
        save_v3_key_bundle(&bundle, Some(&key_dir)).unwrap();

        let payload = build_register_payload_from_local_key(
            &bundle.key_id,
            "demo".to_string(),
            "bundle note".to_string(),
            vec!["x".to_string()],
            &ResolveCtx {
                keydir: Some(key_dir.clone()),
                private_key: None,
                source_cfg: &source_cfg,
                legacy_mode: true,
            },
        )
        .unwrap();

        match payload {
            RegisterPayload::V3(payload) => {
                assert_eq!(payload.key_id, bundle.key_id);
                assert_eq!(payload.version, 3);
                assert_eq!(payload.algorithm, bundle.algorithm);
                assert_eq!(payload.tenant, "demo");
                assert_eq!(payload.note, "bundle note");
                assert_eq!(payload.tags, vec!["x"]);
                assert_eq!(payload.public_bundle.components.len(), 2);
                assert_eq!(payload.private_bundle.components.len(), 2);
            }
            _ => panic!("expected v3 register payload"),
        }

        let _ = fs::remove_dir_all(key_dir);
    }
}
