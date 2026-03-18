use anyhow::{anyhow, bail, Result};
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{Shell, generate};
use encjson_core::{key_sources::require_policy_context, oidc_session, tui_ctl};
use std::ffi::OsStr;
use std::path::Path;

const APP_NAME: &str = "encjson-keys-ctl";

#[derive(Parser, Debug)]
#[command(name = "encjson-keys-ctl", version, about = "Admin TUI for encjson-keys-server")]
struct Cli {
    #[arg(long, global = true)]
    insecure: Option<bool>,
    #[arg(long, global = true, env = "ENCJSON_KEYS_URL")]
    keys_url: Option<String>,
    #[arg(long, global = true, env = "ENCJSON_TENANT")]
    tenant: Option<String>,
    #[arg(long = "env", global = true, env = "ENCJSON_ENV")]
    env_name: Option<String>,
    #[arg(long, global = true, env = "ENCJSON_SCOPE_REQUIRED", default_value_t = false)]
    scope_required: bool,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    #[command(alias = "ui")]
    Tui,
    Completion {
        #[arg(value_enum)]
        shell: Shell,
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

fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.scope_required {
        require_policy_context(cli.tenant.as_deref(), cli.env_name.as_deref())
            .map_err(|e| anyhow!(e.to_string()))?;
    }
    match &cli.command {
        Commands::Tui => {
            let keys_url = cli
                .keys_url
                .clone();
            let Some(keys_url) = keys_url else {
                bail!("Missing keys server URL (use --keys-url or set ENCJSON_KEYS_URL)");
            };
            let (session, server_name) =
                run_async(oidc_session::ensure_valid_session(APP_NAME))?;
            oidc_session::save_session(APP_NAME, &server_name, session.clone())?;
            tui_ctl::run_ctl_ui_with_remote(keys_url, session.access_token)
                .map_err(|err| anyhow!(err.to_string()))?;
        }
        Commands::Completion { shell } => {
            let mut cmd = Cli::command();
            let bin_name = current_bin_name(APP_NAME);
            generate(*shell, &mut cmd, bin_name, &mut std::io::stdout());
        }
        Commands::Login {
            url,
            client,
            port,
            server,
        } => {
            run_async(oidc_session::handle_login(
                APP_NAME,
                url,
                client,
                *port,
                server,
                cli.insecure.unwrap_or(false),
            ))?;
        }
        Commands::Logout { server, all } => {
            if *all {
                oidc_session::delete_session(APP_NAME, None)?;
                println!("All sessions removed.");
            } else {
                let target = server.as_deref();
                oidc_session::delete_session(APP_NAME, target)?;
                println!("Session removed.");
            }
        }
        Commands::Sessions { command } => handle_sessions(command)?,
        Commands::Status => handle_status()?,
    }

    Ok(())
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

fn run_async<F, T>(future: F) -> Result<T>
where
    F: std::future::Future<Output = anyhow::Result<T>>,
{
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(future)
}

fn handle_sessions(command: &SessionsCommand) -> Result<()> {
    match command {
        SessionsCommand::List => {
            let config = oidc_session::load_sessions(APP_NAME)?;
            if config.servers.is_empty() {
                println!("No sessions found. Run 'encjson-keys-ctl login' first.");
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
            let mut config = oidc_session::load_sessions(APP_NAME)?;
            if !config.servers.contains_key(server) {
                bail!("Session '{}' not found", server);
            }
            config.active = server.to_string();
            oidc_session::save_sessions(APP_NAME, &config)?;
            println!("Active session set to '{}'", server);
        }
    }
    Ok(())
}

fn handle_status() -> Result<()> {
    let config = oidc_session::load_sessions(APP_NAME)?;
    let Some(session) = config.servers.get(&config.active) else {
        println!("Not logged in. Run 'encjson-keys-ctl login --url <SERVER_URL>' first.");
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
        println!("\nToken expired. Run 'encjson-keys-ctl login' to re-authenticate.");
    }
    Ok(())
}
