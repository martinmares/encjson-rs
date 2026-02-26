mod tui_edit;
mod tui_register;

use clap::{Parser, Subcommand, ValueEnum};
use base64::Engine as _;
use serde_json::Value;
use std::ffi::OsStr;
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;
use std::sync::Once;
use std::collections::BTreeMap;

use encjson_core::crypto::{SecureBox, generate_pair_consistent_key_pair};
use encjson_core::error::Error;
use encjson_core::json_utils::{TransformMode, dotenv_exports, env_exports, transform_json};
use encjson_core::key_sources::{
    CliKeyInput, ConjurConfig, KeySourceKind, KeySourceOptions, RemoteMtlsConfig, VaultConfig,
    derive_public_hex_from_private, load_from_cli, load_from_source, require_policy_context,
};
use encjson_core::key_store::{default_key_dir, list_public_keys, load_private_key, save_private_key};
use encjson_core::oidc_session;
use crate::tui_edit::run_edit_ui;

type Result<T> = std::result::Result<T, Error>;

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

    #[arg(long, global = true)]
    insecure: Option<bool>,

    #[arg(long, global = true, env = "ENCJSON_PRIVATE_KEY")]
    private_key: Option<String>,

    #[arg(long, global = true, env = "ENCJSON_TENANT")]
    tenant: Option<String>,

    #[arg(long = "env", global = true, env = "ENCJSON_ENV")]
    env_name: Option<String>,

    #[arg(long, global = true, env = "ENCJSON_SCOPE_REQUIRED", default_value_t = false)]
    scope_required: bool,
    #[arg(long, global = true, env = "ENCJSON_LEGACY_MODE", default_value_t = true)]
    legacy_mode: bool,

    #[arg(long, global = true, env = "ENCJSON_KEY_SOURCE", value_enum)]
    key_source: Option<KeySourceCli>,
    #[arg(long, global = true, env = "ENCJSON_REMOTE_KEYS_URL")]
    remote_keys_url: Option<String>,
    #[arg(long, global = true, env = "ENCJSON_REMOTE_TLS_CERT_FILE")]
    remote_tls_cert_file: Option<PathBuf>,
    #[arg(long, global = true, env = "ENCJSON_REMOTE_TLS_KEY_FILE")]
    remote_tls_key_file: Option<PathBuf>,
    #[arg(long, global = true, env = "ENCJSON_REMOTE_TLS_CA_FILE")]
    remote_tls_ca_file: Option<PathBuf>,
    #[arg(long, global = true, env = "ENCJSON_VAULT_ADDR")]
    vault_addr: Option<String>,
    #[arg(long, global = true, env = "ENCJSON_VAULT_PATH")]
    vault_path: Option<String>,
    #[arg(long, global = true, env = "ENCJSON_VAULT_TOKEN")]
    vault_token: Option<String>,
    #[arg(long, global = true, env = "ENCJSON_VAULT_PUBLIC_FIELD")]
    vault_public_field: Option<String>,
    #[arg(long, global = true, env = "ENCJSON_VAULT_PRIVATE_FIELD")]
    vault_private_field: Option<String>,
    #[arg(long, global = true, env = "ENCJSON_CONJUR_APPLIANCE_URL")]
    conjur_appliance_url: Option<String>,
    #[arg(long, global = true, env = "ENCJSON_CONJUR_ACCOUNT")]
    conjur_account: Option<String>,
    #[arg(long, global = true, env = "ENCJSON_CONJUR_AUTHN_LOGIN")]
    conjur_authn_login: Option<String>,
    #[arg(long, global = true, env = "ENCJSON_CONJUR_AUTHN_API_KEY")]
    conjur_authn_api_key: Option<String>,
    #[arg(long, global = true, env = "ENCJSON_CONJUR_PUBLIC_VARIABLE_ID")]
    conjur_public_variable_id: Option<String>,
    #[arg(long, global = true, env = "ENCJSON_CONJUR_PRIVATE_VARIABLE_ID")]
    conjur_private_variable_id: Option<String>,
    #[arg(long, global = true, env = "ENCJSON_CONJUR_CA_CERT_FILE")]
    conjur_ca_cert_file: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Commands>,
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

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate a new public/private key pair
    Init {
        /// Optional key directory (overrides ENCJSON_KEYDIR, default is OS-specific via dirs)
        #[arg(short, long, env = "ENCJSON_KEYDIR")]
        keydir: Option<PathBuf>,

        /// Also create `env.secured.json` in current directory with generated public key
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

    /// Show key info for a secured JSON file (_public_key + resolved private key)
    Info {
        /// Input file
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Optional positional input (e.g. path); conflicts with -f/--file
        #[arg(value_name = "INPUT", conflicts_with = "file")]
        input: Option<PathBuf>,

        /// Optional key directory (overrides ENCJSON_KEYDIR, default is OS-specific via dirs)
        #[arg(short = 'k', long, env = "ENCJSON_KEYDIR")]
        keydir: Option<PathBuf>,
    },

    /// Encrypt all string values in a JSON file
    Encrypt {
        /// Input file (otherwise reads from stdin)
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Optional positional input (e.g. "-" for stdin).
        /// Conflicts with -f/--file to avoid ambiguity.
        #[arg(value_name = "INPUT", conflicts_with = "file")]
        input: Option<PathBuf>,

        /// Overwrite the input file in place
        #[arg(short = 'w', long)]
        write: bool,

        /// Optional key directory (overrides ENCJSON_KEYDIR, default is OS-specific via dirs)
        #[arg(short = 'k', long, env = "ENCJSON_KEYDIR")]
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
        /// Input file (otherwise reads from stdin).
        ///
        /// You can also pass "-" as a positional argument to read from stdin:
        ///   encjson decrypt -o shell -
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Optional positional input (e.g. "-" for stdin).
        /// Conflicts with -f/--file to avoid ambiguity.
        #[arg(value_name = "INPUT", conflicts_with = "file")]
        input: Option<PathBuf>,

        /// Overwrite the input file in place (only valid with -o json)
        #[arg(short = 'w', long)]
        write: bool,

        /// Optional key directory (overrides ENCJSON_KEYDIR, default is OS-specific via dirs)
        #[arg(short = 'k', long, env = "ENCJSON_KEYDIR")]
        keydir: Option<PathBuf>,

        /// Output format (json / shell / dot-env)
        #[arg(short = 'o', long = "output", value_enum, default_value_t = OutputFormat::Json)]
        output: OutputFormat,

        /// Print expansion trace to stderr (use RUST_LOG=debug to see it)
        #[arg(long)]
        debug: bool,

        /// Return only one concrete value from `environment` / `env` object (raw value to stdout)
        #[arg(long = "env-name", conflicts_with = "write")]
        env_name: Option<String>,
    },

    /// (Deprecated) shortcut for `decrypt -o shell`
    Env {
        /// Input file (otherwise reads from stdin)
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Optional key directory (overrides ENCJSON_KEYDIR, default is OS-specific via dirs)
        #[arg(short = 'k', long, env = "ENCJSON_KEYDIR")]
        keydir: Option<PathBuf>,

        /// Print expansion trace to stderr (use RUST_LOG=debug to see it)
        #[arg(long)]
        debug: bool,
    },

    /// Decrypt file and render Kubernetes Secret YAML (with optional sidecar schema transforms)
    #[command(name = "render-k8s-secret")]
    RenderK8sSecret {
        /// Input file
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Optional positional input (e.g. path); conflicts with -f/--file
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
        #[arg(short = 'k', long, env = "ENCJSON_KEYDIR")]
        keydir: Option<PathBuf>,
    },

    /// Render Secret containing public/private key pair resolved from JSON _public_key
    #[command(name = "render-k8s-pair-secret")]
    RenderK8sPairSecret {
        /// Input file
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Optional positional input (e.g. path); conflicts with -f/--file
        #[arg(value_name = "INPUT", conflicts_with = "file")]
        input: Option<PathBuf>,

        /// Secret name
        #[arg(long)]
        name: String,

        /// Optional namespace
        #[arg(long)]
        namespace: Option<String>,

        /// Public key field name in data
        #[arg(long, default_value = "public-key")]
        public_key_name: String,

        /// Private key field name in data
        #[arg(long, default_value = "private-key")]
        private_key_name: String,

        /// Optional output file (default stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Optional key directory (overrides ENCJSON_KEYDIR, default is OS-specific via dirs)
        #[arg(short = 'k', long, env = "ENCJSON_KEYDIR")]
        keydir: Option<PathBuf>,
    },

    /// Edit key/value pairs in `environment` or `env` using a terminal UI
    Edit {
        /// Input file (required for UI editing)
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Optional positional input (kept for symmetry; not valid for UI)
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
        #[arg(short = 'k', long, env = "ENCJSON_KEYDIR")]
        keydir: Option<PathBuf>,
    },

    /// Remove a key from `environment`/`env` for CI/CD automation
    Unset {
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
        #[arg(short = 'k', long, env = "ENCJSON_KEYDIR")]
        keydir: Option<PathBuf>,
    },

    /// Rotate file encryption key (decrypt -> replace _public_key -> encrypt)
    #[command(name = "rotate-key", alias = "rekey", alias = "migrate-key")]
    RotateKey {
        /// Input file
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Optional positional input (e.g. path); conflicts with -f/--file
        #[arg(value_name = "INPUT", conflicts_with = "file")]
        input: Option<PathBuf>,

        /// Overwrite the input file in place
        #[arg(short = 'w', long)]
        write: bool,

        /// Optional key directory (overrides ENCJSON_KEYDIR, default is OS-specific via dirs)
        #[arg(short = 'k', long, env = "ENCJSON_KEYDIR")]
        keydir: Option<PathBuf>,
    },

    /// Register local keys to keys server (pending approval)
    Register {
        /// Optional public key to register explicitly
        #[arg(value_name = "PUBLIC_HEX")]
        public_hex: Option<String>,

        /// Keys server URL (overrides ENCJSON_KEYS_URL)
        #[arg(long, env = "ENCJSON_KEYS_URL")]
        keys_url: Option<String>,

        /// Access token (overrides ENCJSON_ACCESS_TOKEN)
        #[arg(long, env = "ENCJSON_ACCESS_TOKEN")]
        token: Option<String>,

        /// Tenant name (required for explicit public_hex)
        #[arg(long)]
        tenant: Option<String>,

        /// Note (required for explicit public_hex)
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
        /// Input file (reads _public_key)
        #[arg(short, long, conflicts_with = "key")]
        file: Option<PathBuf>,

        /// Public key to sync explicitly
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
enum SessionsCommand {
    #[command(alias = "ls")]
    List,
    Use {
        #[arg(value_name = "SERVER")]
        server: String,
    },
}

fn main() {
    let cli = Cli::parse();

    // Support `encjson -v`
    if cli.version {
        println!("encjson {} (rust)", env!("CARGO_PKG_VERSION"));
        return;
    }

    if let Some(cmd) = cli.command {
        if cli.scope_required
            && let Err(e) = require_policy_context(cli.tenant.as_deref(), cli.env_name.as_deref()) {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        let source_cfg = KeySourceRuntimeConfig {
            key_source: cli.key_source.clone(),
            remote_keys_url: cli.remote_keys_url.clone(),
            remote_tls_cert_file: cli.remote_tls_cert_file.clone(),
            remote_tls_key_file: cli.remote_tls_key_file.clone(),
            remote_tls_ca_file: cli.remote_tls_ca_file.clone(),
            vault_addr: cli.vault_addr.clone(),
            vault_path: cli.vault_path.clone(),
            vault_token: cli.vault_token.clone(),
            vault_public_field: cli.vault_public_field.clone(),
            vault_private_field: cli.vault_private_field.clone(),
            conjur_appliance_url: cli.conjur_appliance_url.clone(),
            conjur_account: cli.conjur_account.clone(),
            conjur_authn_login: cli.conjur_authn_login.clone(),
            conjur_authn_api_key: cli.conjur_authn_api_key.clone(),
            conjur_public_variable_id: cli.conjur_public_variable_id.clone(),
            conjur_private_variable_id: cli.conjur_private_variable_id.clone(),
            conjur_ca_cert_file: cli.conjur_ca_cert_file.clone(),
        };
        if let Err(e) = run(
            cmd,
            cli.insecure.unwrap_or(false),
            cli.private_key.clone(),
            source_cfg,
            cli.legacy_mode,
        ) {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    }
}

fn run(
    command: Commands,
    insecure: bool,
    private_key: Option<String>,
    source_cfg: KeySourceRuntimeConfig,
    legacy_mode: bool,
) -> Result<()> {
    match command {
        Commands::Init {
            keydir,
            create_file,
        } => cmd_init(keydir, create_file),
        Commands::List { keydir } => cmd_list(keydir),
        Commands::Info { file, input, keydir } => cmd_info(
            FileInput { file, input },
            &ResolveCtx {
                keydir,
                private_key: private_key.as_deref(),
                source_cfg: &source_cfg,
                legacy_mode,
            },
        ),
        Commands::Encrypt {
            file,
            input,
            write,
            keydir,
        } => cmd_encrypt(
            FileInput { file, input },
            write,
            &ResolveCtx {
                keydir,
                private_key: private_key.as_deref(),
                source_cfg: &source_cfg,
                legacy_mode,
            },
            true,
        ),
        Commands::Decrypt {
            file,
            input,
            write,
            keydir,
            output,
            debug,
            env_name,
        } => cmd_decrypt(
            FileInput { file, input },
            write,
            output,
            debug,
            env_name,
            &ResolveCtx {
                keydir,
                private_key: private_key.as_deref(),
                source_cfg: &source_cfg,
                legacy_mode,
            },
            true,
        ),
        Commands::Env {
            file,
            keydir,
            debug,
        } => cmd_decrypt(
            FileInput { file, input: None },
            false,
            OutputFormat::Shell,
            debug,
            None,
            &ResolveCtx {
                keydir,
                private_key: private_key.as_deref(),
                source_cfg: &source_cfg,
                legacy_mode,
            },
            false,
        ),
        Commands::RenderK8sSecret {
            file,
            input,
            name,
            namespace,
            secret_type,
            from_env,
            from_env_secret,
            output,
            keydir,
        } => cmd_render_k8s_secret(
            FileInput { file, input },
            RenderK8sSecretOptions {
                name,
                namespace,
                secret_type,
                from_env,
                from_env_secret,
                output,
            },
            &ResolveCtx {
                keydir,
                private_key: private_key.as_deref(),
                source_cfg: &source_cfg,
                legacy_mode,
            },
        ),
        Commands::RenderK8sPairSecret {
            file,
            input,
            name,
            namespace,
            public_key_name,
            private_key_name,
            output,
            keydir,
        } => cmd_render_k8s_pair_secret(
            FileInput { file, input },
            name,
            namespace,
            public_key_name,
            private_key_name,
            output,
            &ResolveCtx {
                keydir,
                private_key: private_key.as_deref(),
                source_cfg: &source_cfg,
                legacy_mode,
            },
        ),
        Commands::Edit {
            file,
            input,
            keydir,
            ui,
            web,
        } => cmd_edit(file, input, keydir, ui, web),
        Commands::Set {
            file,
            key,
            value,
            json_value,
            write,
            keydir,
        } => cmd_set(
            FileInput { file, input: None },
            key,
            value,
            json_value,
            write,
            &ResolveCtx {
                keydir,
                private_key: private_key.as_deref(),
                source_cfg: &source_cfg,
                legacy_mode,
            },
        ),
        Commands::Unset {
            file,
            key,
            write,
            keydir,
        } => cmd_unset(
            FileInput { file, input: None },
            key,
            write,
            &ResolveCtx {
                keydir,
                private_key: private_key.as_deref(),
                source_cfg: &source_cfg,
                legacy_mode,
            },
        ),
        Commands::RotateKey {
            file,
            input,
            write,
            keydir,
        } => cmd_rekey(
            FileInput { file, input },
            write,
            &ResolveCtx {
                keydir,
                private_key: private_key.as_deref(),
                source_cfg: &source_cfg,
                legacy_mode,
            },
        ),
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
        } => cmd_register(
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
            &ResolveCtx {
                keydir,
                private_key: private_key.as_deref(),
                source_cfg: &source_cfg,
                legacy_mode,
            },
        ),
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
            url,
            client,
            port,
            server,
        } => run_async(oidc_session::handle_login(
            "encjson",
            &url,
            &client,
            port,
            &server,
            insecure,
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
    println!("Status: {}", if valid { "✓ Logged in" } else { "✗ Token expired" });
    println!("Active server: {}", config.active);
    println!("Server URL: {}", session.base_url);
    println!("Token expires in: {} seconds ({} minutes)", expires_in, expires_in / 60);
    println!("Session created: {}", session.created_at.format("%Y-%m-%d %H:%M:%S"));
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
}

#[derive(serde::Deserialize)]
struct KeysRequest {
    public_hex: String,
}

#[derive(serde::Serialize)]
struct RegisterPayload {
    public_hex: String,
    private_hex: String,
    tenant: String,
    note: String,
    tags: Vec<String>,
}

#[derive(serde::Deserialize)]
struct KeysPrivateKey {
    public_hex: String,
    private_hex: String,
}

#[derive(Debug, serde::Serialize)]
struct K8sSecretManifest {
    #[serde(rename = "apiVersion")]
    api_version: String,
    kind: String,
    metadata: K8sMetadata,
    #[serde(rename = "type")]
    secret_type: String,
    data: BTreeMap<String, String>,
}

#[derive(Debug, serde::Serialize)]
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

    let conjur = match kind {
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
            public_variable_id: source_cfg
                .conjur_public_variable_id
                .clone()
                .ok_or_else(|| Error::Http("missing --conjur-public-variable-id".to_string()))?,
            private_variable_id: source_cfg
                .conjur_private_variable_id
                .clone()
                .ok_or_else(|| Error::Http("missing --conjur-private-variable-id".to_string()))?,
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
        let private_hex = if ctx.private_key.is_some()
            || private_key_file.is_some()
            || private_key_fd.is_some()
            || private_key_stdin
        {
            let loaded = load_from_cli(&CliKeyInput {
                public_key: Some(public_hex.clone()),
                private_key: ctx.private_key.map(ToString::to_string),
                private_key_file: private_key_file
                    .as_ref()
                    .map(|p| p.display().to_string()),
                private_key_fd,
                private_key_stdin,
                allow_insecure_cli_private_key,
            })
            .map_err(|e| Error::Http(e.to_string()))?;
            loaded.private_hex
        } else {
            resolve_private_key_for_public(&public_hex, ctx)?
            .private_hex
        };
        send_register_request(&keys_url, &token, RegisterPayload {
            public_hex,
            private_hex,
            tenant,
            note,
            tags,
        })?;
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
        .map(|k| k.public_hex)
        .chain(pending.into_iter().map(|r| r.public_hex))
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
    tui_register::run_register_tui(
        new_keys,
        tenants,
        keys_url,
        token,
        ctx.keydir.clone(),
    )
    .map_err(|e| Error::Http(e.to_string()))?;

    Ok(())
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
    let public_key_hex = extract_public_key(&root)?.to_string();
    let resolved = resolve_private_key_for_public(&public_key_hex, ctx)?;

    println!("public_key: {public_key_hex}");
    println!("private_key: {}", resolved.private_hex);
    println!("pair_consistent: {}", resolved.pair_consistent);
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
    let body = response
        .text()
        .map_err(|e| Error::Http(e.to_string()))?;
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
    let body = response
        .text()
        .map_err(|e| Error::Http(e.to_string()))?;
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
    let body = response
        .text()
        .map_err(|e| Error::Http(e.to_string()))?;
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
    let body = response
        .text()
        .map_err(|e| Error::Http(e.to_string()))?;
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
    let body = response
        .text()
        .map_err(|e| Error::Http(e.to_string()))?;
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

    let mut public_keys: Vec<String> = if let Some(public_hex) = key {
        vec![public_hex]
    } else if let Some(path) = file.as_ref() {
        let json = read_json(Some(path))?;
        vec![extract_public_key(&json)?.to_string()]
    } else {
        fetch_remote_keys(&keys_url, &token)?
            .into_iter()
            .map(|k| k.public_hex)
            .collect()
    };

    if public_keys.is_empty() {
        println!("No keys to sync.");
        return Ok(());
    }

    public_keys.sort();
    public_keys.dedup();

    let mut downloaded = 0;
    let mut skipped = 0;
    for public_hex in public_keys {
        let private_key = fetch_private_key(&keys_url, &token, &public_hex)?;
        if private_key.public_hex != public_hex {
            return Err(Error::Http(format!(
                "keys server returned mismatched key {}",
                private_key.public_hex
            )));
        }
        let dir = keydir.clone().unwrap_or_else(default_key_dir);
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(&public_hex);
        if path.exists() {
            skipped += 1;
            continue;
        }
        save_private_key(&public_hex, &private_key.private_hex, Some(&dir))?;
        downloaded += 1;
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


fn cmd_init(keydir: Option<PathBuf>, create_file: bool) -> Result<()> {
    let (priv_hex, pub_hex) = generate_pair_consistent_key_pair();
    let path = save_private_key(&pub_hex, &priv_hex, keydir.as_deref())?;

    println!("OK init");
    println!("  public key : {pub_hex}");
    println!("  private key: {priv_hex}");
    println!("  key file   : {}", path.display());

    if create_file {
        let out = PathBuf::from("env.secured.json");
        if out.exists() {
            return Err(Error::FileAlreadyExists(out.display().to_string()));
        }
        let template = serde_json::json!({
            "_public_key": pub_hex,
            "environment": {}
        });
        fs::write(&out, serde_json::to_string_pretty(&template)?)?;
        println!("  created    : {}", out.display());
    }

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

    let mut pair_mismatch = false;
    match extract_public_key(&value) {
        Ok(public_key_hex) => {
            // _public_key existuje, normálně šifrujeme
            let resolved = resolve_private_key_for_public(public_key_hex, ctx)?;
            pair_mismatch = !resolved.pair_consistent;
            let sb = SecureBox::new_from_hex(&resolved.private_hex, public_key_hex)?;
            transform_json(&mut value, &sb, TransformMode::Encrypt)?;
        }
        Err(Error::MissingPublicKey) => {
            // Bez _public_key nedává crypto smysl -> jen pass-through.
            // JSON necháme jak je; volitelně upozorníme na stderr.
            eprintln!("Warning: _public_key not found in JSON, nothing encrypted");
        }
        Err(e) => {
            // jiné chyby (např. špatný formát klíče) jsou pořád fatální
            return Err(e);
        }
    }

    write_json_to(effective_path.as_ref(), write, &value)?;
    if pair_mismatch && warn_pair_mismatch {
        eprintln!(
            "Warning: legacy inconsistent key pair detected for _public_key; encryption proceeded because ENCJSON_LEGACY_MODE=true. Run `encjson rotate-key -f <file> -w`."
        );
    }
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
        init_tracing();
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
    let (value, pair_mismatch) = decrypt_json_with_sidecar(effective_path.as_ref(), ctx)?;

    if let Some(name) = env_name {
        let raw = get_env_value_raw(&value, &name)?;
        print!("{raw}");
        if pair_mismatch && warn_pair_mismatch {
            eprintln!(
                "Warning: legacy inconsistent key pair detected for _public_key; decryption proceeded because ENCJSON_LEGACY_MODE=true. Run `encjson rotate-key -f <file> -w`."
            );
        }
        return Ok(());
    }

    match output {
        OutputFormat::Json => {
            write_json_to(effective_path.as_ref(), write, &value)?;
            if pair_mismatch && warn_pair_mismatch {
                eprintln!(
                    "Warning: legacy inconsistent key pair detected for _public_key; decryption proceeded because ENCJSON_LEGACY_MODE=true. Run `encjson rotate-key -f <file> -w`."
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
) -> Result<(Value, bool)> {
    let mut value = read_json(effective_path)?;
    let sidecar_schema = load_sidecar_schema(effective_path)?;

    let mut pair_mismatch = false;
    if let Ok(public_key_hex) = extract_public_key(&value) {
        let resolved = resolve_private_key_for_public(public_key_hex, ctx)?;
        pair_mismatch = !resolved.pair_consistent;
        let sb = SecureBox::new_from_hex(&resolved.private_hex, public_key_hex)?;
        transform_json(&mut value, &sb, TransformMode::Decrypt)?;
    } else if let Err(e) = extract_public_key(&value) {
        match e {
            Error::MissingPublicKey => {}
            other => return Err(other),
        }
    }

    if let Some(schema) = sidecar_schema.as_ref() {
        apply_sidecar_schema(&mut value, schema)?;
    }

    Ok((value, pair_mismatch))
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
    let (value, pair_mismatch) = decrypt_json_with_sidecar(effective_path.as_ref(), ctx)?;

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
    if pair_mismatch {
        eprintln!(
            "Warning: legacy inconsistent key pair detected for _public_key; decryption proceeded because ENCJSON_LEGACY_MODE=true. Run `encjson rotate-key -f <file> -w`."
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
    let public_key = extract_public_key(&value)?.to_string();
    let resolved = resolve_private_key_for_public(&public_key, ctx)?;

    let mut data = BTreeMap::new();
    data.insert(public_key_name, encode_k8s_data(&public_key));
    data.insert(private_key_name, encode_k8s_data(&resolved.private_hex));

    let manifest = K8sSecretManifest {
        api_version: "v1".to_string(),
        kind: "Secret".to_string(),
        metadata: K8sMetadata { name, namespace },
        secret_type: "Opaque".to_string(),
        data,
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
                Error::Http(format!("missing env key '{}' for --from-env-secret mapping", env_key))
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
                Error::Http(format!("missing env key '{}' for --from-env mapping", env_key))
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

fn init_tracing() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("debug"));
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

    let sb = match extract_public_key(&root) {
        Ok(public_key_hex) => {
            let private_key_hex = resolve_private_key_for_public(public_key_hex, ctx)?
            .private_hex;
            Some(SecureBox::new_from_hex(&private_key_hex, public_key_hex)?)
        }
        Err(Error::MissingPublicKey) => None,
        Err(e) => return Err(e),
    };

    // For secured files, decrypt only env subtree, update, then re-encrypt only that subtree.
    if let Some(sb) = sb.as_ref() {
        let env_value = root.get_mut(env_key).ok_or(Error::MissingEnvObject)?;
        transform_json(env_value, sb, TransformMode::Decrypt)?;
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

    if let Some(sb) = sb.as_ref() {
        let env_value = root.get_mut(env_key).ok_or(Error::MissingEnvObject)?;
        transform_json(env_value, sb, TransformMode::Encrypt)?;
    }

    write_json_to(effective_path.as_ref(), write, &root)
}

fn cmd_unset(input: FileInput, key: String, write: bool, ctx: &ResolveCtx<'_>) -> Result<()> {
    let effective_path = input.file.or(input.input);
    let mut root = read_json(effective_path.as_ref())?;

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

    let sb = match extract_public_key(&root) {
        Ok(public_key_hex) => {
            let private_key_hex = resolve_private_key_for_public(public_key_hex, ctx)?
            .private_hex;
            Some(SecureBox::new_from_hex(&private_key_hex, public_key_hex)?)
        }
        Err(Error::MissingPublicKey) => None,
        Err(e) => return Err(e),
    };

    if let Some(sb) = sb.as_ref() {
        let env_value = root.get_mut(env_key).ok_or(Error::MissingEnvObject)?;
        transform_json(env_value, sb, TransformMode::Decrypt)?;
    }

    let env_obj = root
        .get_mut(env_key)
        .and_then(Value::as_object_mut)
        .ok_or(Error::MissingEnvObject)?;
    env_obj.remove(&key);

    if let Some(sb) = sb.as_ref() {
        let env_value = root.get_mut(env_key).ok_or(Error::MissingEnvObject)?;
        transform_json(env_value, sb, TransformMode::Encrypt)?;
    }

    write_json_to(effective_path.as_ref(), write, &root)
}

fn cmd_rekey(input: FileInput, write: bool, ctx: &ResolveCtx<'_>) -> Result<()> {
    let effective_path = input.file.or(input.input);
    let mut root = read_json(effective_path.as_ref())?;

    let old_public = extract_public_key(&root)?.to_string();
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
    let target = effective_path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "stdin/stdout".to_string());
    println!("OK rotate-key");
    println!("  target file: {target}");
    println!("  old public : {old_public}");
    println!("  new public : {new_public}");
    println!("  new key    : {}", key_path.display());
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

/// Extract `_public_key` from JSON and validate length (64 hex chars).
pub(crate) fn extract_public_key(root: &Value) -> Result<&str> {
    if let Some(pk) = root.get("_public_key").and_then(Value::as_str) {
        if pk.len() == 64 {
            return Ok(pk);
        } else {
            return Err(Error::InvalidPublicKey);
        }
    }
    Err(Error::MissingPublicKey)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn empty_source_cfg() -> KeySourceRuntimeConfig {
        KeySourceRuntimeConfig::default()
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
            "encjson", "info", "-k", "keys-dir", "-f", "env.secured.json",
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
            "mtls-test-tsm-dms-tsm-dms",
            "--namespace",
            "nac-test",
            "--from-env",
            "MTLS_TEST_TSM_DMS_TLS_CRT=tls.crt",
            "--from-env",
            "MTLS_TEST_TSM_DMS_TLS_KEY=tls.key",
            "--from-env",
            "MTLS_TEST_TSM_DMS_CA_CRT=ca.crt",
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
                assert_eq!(name.as_deref(), Some("mtls-test-tsm-dms-tsm-dms"));
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
            "tsm-secrets",
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
                assert_eq!(name, "tsm-secrets");
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
            "TSM_DB_PASSWORD",
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
            "TSM_DB_PASSWORD",
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
    fn parse_register_accepts_secure_private_key_inputs() {
        let cli = Cli::parse_from([
            "encjson",
            "register",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--tenant",
            "tsm",
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
            "--scope-required",
            "--tenant",
            "tsm",
            "--env",
            "test",
            "list",
        ]);
        assert!(cli.scope_required);
        assert_eq!(cli.tenant.as_deref(), Some("tsm"));
        assert_eq!(cli.env_name.as_deref(), Some("test"));
    }

    #[test]
    fn parse_global_conjur_key_source_options() {
        let cli = Cli::parse_from([
            "encjson",
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
            "list",
        ]);
        assert!(matches!(cli.key_source, Some(KeySourceCli::Conjur)));
        assert_eq!(
            cli.conjur_appliance_url.as_deref(),
            Some("https://conjur.example.com")
        );
    }

    #[test]
    fn cmd_set_updates_unsecured_environment() {
        let path = unique_path("set", ".json");
        let source_cfg = empty_source_cfg();
        fs::write(
            &path,
            r#"{"environment":{"TSM_A":"a","TSM_B":"b"}}"#,
        )
        .unwrap();

        cmd_set(
            FileInput {
                file: Some(path.clone()),
                input: None,
            },
            "TSM_B".to_string(),
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
        assert_eq!(env.get("TSM_A").unwrap().as_str(), Some("a"));
        assert_eq!(env.get("TSM_B").unwrap().as_str(), Some("new-b"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn cmd_set_json_value_stores_number() {
        let path = unique_path("set-json", ".json");
        let source_cfg = empty_source_cfg();
        fs::write(&path, r#"{"environment":{"TSM_UI_PUBLIC_PORT":443}}"#).unwrap();

        cmd_set(
            FileInput {
                file: Some(path.clone()),
                input: None,
            },
            "TSM_UI_PUBLIC_PORT".to_string(),
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
        assert_eq!(env.get("TSM_UI_PUBLIC_PORT").unwrap().as_i64(), Some(8443));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn cmd_unset_removes_key_from_env_alias() {
        let path = unique_path("unset", ".json");
        let source_cfg = empty_source_cfg();
        fs::write(&path, r#"{"env":{"TSM_A":"a","TSM_B":"b"}}"#).unwrap();

        cmd_unset(
            FileInput {
                file: Some(path.clone()),
                input: None,
            },
            "TSM_A".to_string(),
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
        assert!(env.get("TSM_A").is_none());
        assert_eq!(env.get("TSM_B").unwrap().as_str(), Some("b"));

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
            "TSM_A".to_string(),
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
                r#"{{"_public_key":"{old_public}","environment":{{"TSM_DB_PASSWORD":"secret"}}}}"#
            ),
        )
        .unwrap();

        cmd_rekey(
            FileInput {
                file: Some(path.clone()),
                input: None,
            },
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
                r#"{{"_public_key":"{old_public}","environment":{{"TSM_DB_PASSWORD":"secret"}}}}"#
            ),
        )
        .unwrap();

        cmd_rekey(
            FileInput {
                file: Some(path.clone()),
                input: None,
            },
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
        let new_public = root.get("_public_key").and_then(Value::as_str).unwrap().to_string();
        let new_private = fs::read_to_string(dir.join(&new_public)).unwrap();
        let derived = derive_public_hex_from_private(new_private.trim()).unwrap();
        assert_eq!(derived, new_public);

        let _ = fs::remove_file(path);
        let _ = fs::remove_dir_all(dir);
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
        let payload = base64::engine::general_purpose::STANDARD
            .encode("line1\r\nline2\rline3");
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
        let out = parse_from_env_mappings(&[
            "A=tls.crt".to_string(),
            "B=tls.key".to_string(),
        ])
        .unwrap();
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
            manifests[0]
                .data
                .get("tls.crt")
                .map(|s| s.as_str()),
            Some("Y3J0")
        );
        assert_eq!(
            manifests[0]
                .data
                .get("tls.key")
                .map(|s| s.as_str()),
            Some("a2V5")
        );
        assert_eq!(
            manifests[1]
                .data
                .get("ca.crt")
                .map(|s| s.as_str()),
            Some("Y2E=")
        );
    }

    #[test]
    fn build_secret_manifests_requires_secret_name_in_single_mode() {
        let env_obj = serde_json::json!({"A": "x"})
            .as_object()
            .unwrap()
            .clone();
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
        let env_obj = serde_json::json!({"A": "x"})
            .as_object()
            .unwrap()
            .clone();
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
}
