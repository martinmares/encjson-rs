mod crypto;
mod error;
mod json_utils;
mod key_store;
mod oidc_session;
mod tui_edit;
mod tui_register;

use clap::{Parser, Subcommand, ValueEnum};
use serde_json::Value;
use std::ffi::OsStr;
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;
use std::sync::Once;

use crate::crypto::{SecureBox, generate_key_pair};
use crate::error::Error;
use crate::json_utils::{TransformMode, dotenv_exports, env_exports, transform_json};
use crate::key_store::{default_key_dir, list_public_keys, load_private_key, save_private_key};
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

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate a new public/private key pair
    Init {
        /// Optional key directory (overrides ENCJSON_KEYDIR, default is OS-specific via dirs)
        #[arg(short, long)]
        keydir: Option<PathBuf>,

        /// Also create `env.secured.json` in current directory with generated public key
        #[arg(long)]
        create_file: bool,
    },

    /// List local public keys
    #[command(alias = "ls")]
    List {
        /// Optional key directory (overrides ENCJSON_KEYDIR, default is OS-specific via dirs)
        #[arg(short = 'k', long)]
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
        #[arg(short = 'k', long)]
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
        #[arg(short = 'k', long)]
        keydir: Option<PathBuf>,

        /// Output format (json / shell / dot-env)
        #[arg(short = 'o', long = "output", value_enum, default_value_t = OutputFormat::Json)]
        output: OutputFormat,

        /// Print expansion trace to stderr (use RUST_LOG=debug to see it)
        #[arg(long)]
        debug: bool,
    },

    /// (Deprecated) shortcut for `decrypt -o shell`
    Env {
        /// Input file (otherwise reads from stdin)
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Optional key directory (overrides ENCJSON_KEYDIR, default is OS-specific via dirs)
        #[arg(short = 'k', long)]
        keydir: Option<PathBuf>,

        /// Print expansion trace to stderr (use RUST_LOG=debug to see it)
        #[arg(long)]
        debug: bool,
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
        #[arg(short = 'k', long)]
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
        #[arg(short = 'k', long)]
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
        #[arg(short = 'k', long)]
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
        #[arg(short = 'k', long)]
        keydir: Option<PathBuf>,
    },

    /// Register local keys to keys server (pending approval)
    Register {
        /// Optional public key to register explicitly
        #[arg(value_name = "PUBLIC_HEX")]
        public_hex: Option<String>,

        /// Keys server URL (overrides ENCJSON_KEYS_URL)
        #[arg(long, alias = "vault-url")]
        keys_url: Option<String>,

        /// Access token (overrides ENCJSON_ACCESS_TOKEN)
        #[arg(long)]
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
        #[arg(short = 'k', long)]
        keydir: Option<PathBuf>,
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
        #[arg(long, alias = "vault-url")]
        keys_url: Option<String>,

        /// Access token (overrides ENCJSON_ACCESS_TOKEN)
        #[arg(long)]
        token: Option<String>,

        /// Optional key directory (overrides ENCJSON_KEYDIR, default is OS-specific via dirs)
        #[arg(short = 'k', long)]
        keydir: Option<PathBuf>,
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
        if let Err(e) = run(cmd, cli.insecure.unwrap_or(false)) {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    }
}

fn run(command: Commands, insecure: bool) -> Result<()> {
    match command {
        Commands::Init {
            keydir,
            create_file,
        } => cmd_init(keydir, create_file),
        Commands::List { keydir } => cmd_list(keydir),
        Commands::Encrypt {
            file,
            input,
            write,
            keydir,
        } => cmd_encrypt(file, input, write, keydir),
        Commands::Decrypt {
            file,
            input,
            write,
            keydir,
            output,
            debug,
        } => cmd_decrypt(file, input, write, keydir, output, debug),
        Commands::Env {
            file,
            keydir,
            debug,
        } => cmd_decrypt(file, None, false, keydir, OutputFormat::Shell, debug),
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
        } => cmd_set(file, None, key, value, json_value, write, keydir),
        Commands::Unset {
            file,
            key,
            write,
            keydir,
        } => cmd_unset(file, None, key, write, keydir),
        Commands::RotateKey {
            file,
            input,
            write,
            keydir,
        } => cmd_rekey(file, input, write, keydir),
        Commands::Register {
            public_hex,
            keys_url,
            token,
            tenant,
            note,
            tag,
            keydir,
        } => cmd_register(public_hex, keys_url, token, tenant, note, tag, keydir),
        Commands::Sync {
            file,
            key,
            keys_url,
            token,
            keydir,
        } => cmd_sync(file, key, keys_url, token, keydir),
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

fn cmd_register(
    public_hex: Option<String>,
    keys_url: Option<String>,
    token: Option<String>,
    tenant: Option<String>,
    note: Option<String>,
    tags: Vec<String>,
    keydir: Option<PathBuf>,
) -> Result<()> {
    let keys_url = keys_url
        .or_else(|| std::env::var("ENCJSON_KEYS_URL").ok())
        .or_else(|| std::env::var("ENCJSON_VAULT_URL").ok())
        .ok_or(Error::MissingKeysUrl)?;
    let token = token
        .or_else(|| std::env::var("ENCJSON_ACCESS_TOKEN").ok())
        .or_else(load_token_from_session)
        .ok_or(Error::MissingAccessToken)?;

    if let Some(public_hex) = public_hex {
        let tenant = tenant.ok_or(Error::RegisterMissingFields)?;
        let note = note.ok_or(Error::RegisterMissingFields)?;
        let private_hex = load_private_key(&public_hex, keydir.as_deref())?;
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

    let local_keys = list_public_keys(keydir.as_deref())?;
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
        keydir,
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

fn load_token_from_session() -> Option<String> {
    let config = oidc_session::load_sessions("encjson").ok()?;
    let session = config.servers.get(&config.active)?;
    Some(session.access_token.clone())
}

fn fetch_remote_keys(keys_url: &str, token: &str) -> Result<Vec<KeysKey>> {
    let url = format!("{}/v1/keys", keys_url.trim_end_matches('/'));
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
    let url = format!("{}/v1/tenants", keys_url.trim_end_matches('/'));
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
        "{}/v1/requests?status=pending",
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
    let url = format!("{}/v1/requests", keys_url.trim_end_matches('/'));
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
        "{}/v1/keys/{}/private",
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
    let keys_url = keys_url
        .or_else(|| std::env::var("ENCJSON_KEYS_URL").ok())
        .or_else(|| std::env::var("ENCJSON_VAULT_URL").ok())
        .ok_or(Error::MissingKeysUrl)?;
    let token = token
        .or_else(|| std::env::var("ENCJSON_ACCESS_TOKEN").ok())
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


fn cmd_init(keydir: Option<PathBuf>, create_file: bool) -> Result<()> {
    let (priv_hex, pub_hex) = generate_key_pair();
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
    file: Option<PathBuf>,
    input: Option<PathBuf>,
    write: bool,
    keydir: Option<PathBuf>,
) -> Result<()> {
    // sjednotíme -f a pozicní argument (např. "-")
    let effective_path = file.or(input);

    let mut value = read_json(effective_path.as_ref())?;

    match extract_public_key(&value) {
        Ok(public_key_hex) => {
            // _public_key existuje, normálně šifrujeme
            let private_key_hex = load_private_key(public_key_hex, keydir.as_deref())?;
            let sb = SecureBox::new_from_hex(&private_key_hex, public_key_hex)?;
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

    write_json_to(effective_path.as_ref(), write, &value)
}

fn cmd_decrypt(
    file: Option<PathBuf>,
    input: Option<PathBuf>,
    write: bool,
    keydir: Option<PathBuf>,
    output: OutputFormat,
    debug: bool,
) -> Result<()> {
    if debug {
        init_tracing();
    }

    // `-w` dává smysl jen pro JSON výstup
    if write && !matches!(output, OutputFormat::Json) {
        return Err(Error::InvalidWriteForOutput);
    }

    // sjednotíme -f a pozicní argument (např. "-")
    let effective_path = file.or(input);

    let mut value = read_json(effective_path.as_ref())?;

    // Pokusíme se načíst public key.
    // - Když _public_key chybí -> jen NEBUDEME dělat dešifrování,
    //   ale pokračujeme a použijeme JSON tak, jak je.
    // - Když je _public_key špatný -> pořád chyba (to je bug / špatná konfigurace).
    if let Ok(public_key_hex) = extract_public_key(&value) {
        // _public_key existuje, takže se pokusíme normálně dešifrovat
        let private_key_hex = load_private_key(public_key_hex, keydir.as_deref())?;

        let sb = SecureBox::new_from_hex(&private_key_hex, public_key_hex)?;
        transform_json(&mut value, &sb, TransformMode::Decrypt)?;
    } else {
        // Pokud extract_public_key skončil chybou MissingPublicKey,
        // ignorujeme ji a NEděláme žádné crypto.
        // Ostatní chyby pořád propadnou ven.
        if let Err(e) = extract_public_key(&value) {
            match e {
                Error::MissingPublicKey => {
                    // Bez _public_key prostě jen "pass-through":
                    // -o json      -> vytiskne stejný JSON
                    // -o shell     -> vezme env/environment tak jak je
                    // -o dot-env   -> dtto
                }
                other => return Err(other),
            }
        }
    }

    match output {
        OutputFormat::Json => write_json_to(effective_path.as_ref(), write, &value),
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
    file: Option<PathBuf>,
    input: Option<PathBuf>,
    key: String,
    value: String,
    json_value: bool,
    write: bool,
    keydir: Option<PathBuf>,
) -> Result<()> {
    let effective_path = file.or(input);
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
            let private_key_hex = load_private_key(public_key_hex, keydir.as_deref())?;
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

fn cmd_unset(
    file: Option<PathBuf>,
    input: Option<PathBuf>,
    key: String,
    write: bool,
    keydir: Option<PathBuf>,
) -> Result<()> {
    let effective_path = file.or(input);
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
            let private_key_hex = load_private_key(public_key_hex, keydir.as_deref())?;
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

fn cmd_rekey(
    file: Option<PathBuf>,
    input: Option<PathBuf>,
    write: bool,
    keydir: Option<PathBuf>,
) -> Result<()> {
    let effective_path = file.or(input);
    let mut root = read_json(effective_path.as_ref())?;

    let old_public = extract_public_key(&root)?.to_string();
    let old_private = load_private_key(&old_public, keydir.as_deref())?;
    let old_sb = SecureBox::new_from_hex(&old_private, &old_public)?;
    transform_json(&mut root, &old_sb, TransformMode::Decrypt)?;

    let (new_private, new_public) = generate_key_pair();
    let new_sb = SecureBox::new_from_hex(&new_private, &new_public)?;
    if let Some(obj) = root.as_object_mut() {
        obj.insert("_public_key".to_string(), Value::String(new_public.clone()));
    } else {
        return Err(Error::MissingEnvObject);
    }
    transform_json(&mut root, &new_sb, TransformMode::Encrypt)?;
    let key_path = save_private_key(&new_public, &new_private, keydir.as_deref())?;

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
    fn cmd_set_updates_unsecured_environment() {
        let path = unique_path("set", ".json");
        fs::write(
            &path,
            r#"{"environment":{"TSM_A":"a","TSM_B":"b"}}"#,
        )
        .unwrap();

        cmd_set(
            Some(path.clone()),
            None,
            "TSM_B".to_string(),
            "new-b".to_string(),
            false,
            true,
            None,
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
        fs::write(&path, r#"{"environment":{"TSM_UI_PUBLIC_PORT":443}}"#).unwrap();

        cmd_set(
            Some(path.clone()),
            None,
            "TSM_UI_PUBLIC_PORT".to_string(),
            "8443".to_string(),
            true,
            true,
            None,
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
        fs::write(&path, r#"{"env":{"TSM_A":"a","TSM_B":"b"}}"#).unwrap();

        cmd_unset(
            Some(path.clone()),
            None,
            "TSM_A".to_string(),
            true,
            None,
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
        fs::write(&path, r#"{"foo":"bar"}"#).unwrap();

        let err = cmd_set(
            Some(path.clone()),
            None,
            "TSM_A".to_string(),
            "x".to_string(),
            false,
            true,
            None,
        )
        .unwrap_err();
        assert!(matches!(err, Error::MissingEnvObject));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn cmd_rotate_key_rewrites_public_key() {
        let dir = unique_path("rotate-key-dir", "");
        fs::create_dir_all(&dir).unwrap();

        let (old_private, old_public) = generate_key_pair();
        save_private_key(&old_public, &old_private, Some(&dir)).unwrap();

        let path = unique_path("rotate-key-file", ".json");
        fs::write(
            &path,
            format!(
                r#"{{"_public_key":"{old_public}","environment":{{"TSM_DB_PASSWORD":"secret"}}}}"#
            ),
        )
        .unwrap();

        cmd_rekey(Some(path.clone()), None, true, Some(dir.clone())).unwrap();

        let root: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let new_public = root.get("_public_key").and_then(Value::as_str).unwrap();
        assert_ne!(new_public, old_public);
        assert!(dir.join(new_public).exists());

        let _ = fs::remove_file(path);
        let _ = fs::remove_dir_all(dir);
    }
}
