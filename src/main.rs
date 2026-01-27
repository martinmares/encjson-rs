mod crypto;
mod error;
mod json_utils;
mod key_store;
mod oidc_session;
mod tui_edit;

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

    /// Register local keys to vault (pending approval)
    Register {
        /// Optional public key to register explicitly
        #[arg(value_name = "PUBLIC_HEX")]
        public_hex: Option<String>,

        /// Vault URL (overrides ENCJSON_VAULT_URL)
        #[arg(long)]
        vault_url: Option<String>,

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

    /// Sync private keys from the vault into the local key directory
    Sync {
        /// Input file (reads _public_key)
        #[arg(short, long, conflicts_with = "key")]
        file: Option<PathBuf>,

        /// Public key to sync explicitly
        #[arg(long, conflicts_with = "file")]
        key: Option<String>,

        /// Vault URL (overrides ENCJSON_VAULT_URL)
        #[arg(long)]
        vault_url: Option<String>,

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
        Commands::Init { keydir } => cmd_init(keydir),
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
        Commands::Register {
            public_hex,
            vault_url,
            token,
            tenant,
            note,
            tag,
            keydir,
        } => cmd_register(public_hex, vault_url, token, tenant, note, tag, keydir),
        Commands::Sync {
            file,
            key,
            vault_url,
            token,
            keydir,
        } => cmd_sync(file, key, vault_url, token, keydir),
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
struct VaultKey {
    public_hex: String,
}

#[derive(serde::Deserialize)]
struct VaultRequest {
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
struct VaultPrivateKey {
    public_hex: String,
    private_hex: String,
}

fn cmd_register(
    public_hex: Option<String>,
    vault_url: Option<String>,
    token: Option<String>,
    tenant: Option<String>,
    note: Option<String>,
    tags: Vec<String>,
    keydir: Option<PathBuf>,
) -> Result<()> {
    let vault_url = vault_url
        .or_else(|| std::env::var("ENCJSON_VAULT_URL").ok())
        .ok_or(Error::MissingVaultUrl)?;
    let token = token
        .or_else(|| std::env::var("ENCJSON_ACCESS_TOKEN").ok())
        .or_else(load_token_from_session)
        .ok_or(Error::MissingAccessToken)?;

    if let Some(public_hex) = public_hex {
        let tenant = tenant.ok_or(Error::RegisterMissingFields)?;
        let note = note.ok_or(Error::RegisterMissingFields)?;
        let private_hex = load_private_key(&public_hex, keydir.as_deref())?;
        send_register_request(&vault_url, &token, RegisterPayload {
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

    let remote_keys = fetch_remote_keys(&vault_url, &token)?;
    let pending = fetch_pending_requests(&vault_url, &token)?;
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

    for key in new_keys {
        println!("Register key: {key}");
        let tenant = prompt_input("tenant")?;
        let note = prompt_input("note")?;
        let tags = prompt_input("tags (comma-separated, optional)")?;
        let tags = tags
            .split(',')
            .map(|t| t.trim())
            .filter(|t| !t.is_empty())
            .map(|t| t.to_string())
            .collect::<Vec<_>>();
        let private_hex = load_private_key(&key, keydir.as_deref())?;
        send_register_request(&vault_url, &token, RegisterPayload {
            public_hex: key,
            private_hex,
            tenant,
            note,
            tags,
        })?;
        println!("Submitted.");
    }

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

fn prompt_input(label: &str) -> Result<String> {
    print!("{label}: ");
    io::Write::flush(&mut io::stdout())?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

fn load_token_from_session() -> Option<String> {
    let config = oidc_session::load_sessions("encjson").ok()?;
    let session = config.servers.get(&config.active)?;
    Some(session.access_token.clone())
}

fn fetch_remote_keys(vault_url: &str, token: &str) -> Result<Vec<VaultKey>> {
    let url = format!("{}/v1/keys", vault_url.trim_end_matches('/'));
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

fn fetch_pending_requests(vault_url: &str, token: &str) -> Result<Vec<VaultRequest>> {
    let url = format!(
        "{}/v1/requests?status=pending",
        vault_url.trim_end_matches('/')
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

fn send_register_request(vault_url: &str, token: &str, payload: RegisterPayload) -> Result<()> {
    let url = format!("{}/v1/requests", vault_url.trim_end_matches('/'));
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

fn fetch_private_key(vault_url: &str, token: &str, public_hex: &str) -> Result<VaultPrivateKey> {
    let url = format!(
        "{}/v1/keys/{}/private",
        vault_url.trim_end_matches('/'),
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
    vault_url: Option<String>,
    token: Option<String>,
    keydir: Option<PathBuf>,
) -> Result<()> {
    let vault_url = vault_url
        .or_else(|| std::env::var("ENCJSON_VAULT_URL").ok())
        .ok_or(Error::MissingVaultUrl)?;
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
        fetch_remote_keys(&vault_url, &token)?
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
        let private_key = fetch_private_key(&vault_url, &token, &public_hex)?;
        if private_key.public_hex != public_hex {
            return Err(Error::Http(format!(
                "vault returned mismatched key {}",
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


fn cmd_init(keydir: Option<PathBuf>) -> Result<()> {
    let (priv_hex, pub_hex) = generate_key_pair();
    let path = save_private_key(&pub_hex, &priv_hex, keydir.as_deref())?;

    println!("Generated key pair (hex):");

    // On Windows and/or if ENCJSON_NO_EMOJI is set -> ASCII-only output
    let no_emoji = cfg!(target_os = "windows") || std::env::var("ENCJSON_NO_EMOJI").is_ok();

    if no_emoji {
        println!(" => public:  {pub_hex}");
        println!(" => private: {priv_hex}");
        println!(" => saved to: {}", path.display());
    } else {
        println!(" => 🍺 public:  {pub_hex}");
        println!(" => 🔑 private: {priv_hex}");
        println!(" => 💾 saved to: {}", path.display());
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
}
