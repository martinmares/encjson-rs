use anyhow::{anyhow, bail, Result};
use clap::{Parser, Subcommand};
use std::env;

#[path = "../oidc_session.rs"]
mod oidc_session;

#[path = "../tui_ctl.rs"]
mod tui_ctl;

const APP_NAME: &str = "encjson-ctl";

#[derive(Parser, Debug)]
#[command(name = "encjson-ctl", version, about = "Admin TUI for encjson-vault-server")]
struct Cli {
    #[arg(long, global = true)]
    insecure: Option<bool>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    #[command(alias = "ui")]
    Tui,
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

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match &cli.command {
        Commands::Tui => {
            if let Ok(vault_url) = env::var("ENCJSON_VAULT_URL") {
                let (session, server_name) = oidc_session::ensure_valid_session(APP_NAME).await?;
                oidc_session::save_session(APP_NAME, &server_name, session.clone())?;
                tui_ctl::run_ctl_ui_with_remote(vault_url, session.access_token)
                    .map_err(|err| anyhow!(err.to_string()))?;
            } else {
                tui_ctl::run_ctl_ui().map_err(|err| anyhow!(err.to_string()))?;
            }
        }
        Commands::Login {
            url,
            client,
            port,
            server,
        } => {
            oidc_session::handle_login(
                APP_NAME,
                url,
                client,
                *port,
                server,
                cli.insecure.unwrap_or(false),
            )
            .await?;
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

fn handle_sessions(command: &SessionsCommand) -> Result<()> {
    match command {
        SessionsCommand::List => {
            let config = oidc_session::load_sessions(APP_NAME)?;
            if config.servers.is_empty() {
                println!("No sessions found. Run 'encjson-ctl login' first.");
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
        println!("Not logged in. Run 'encjson-ctl login --url <SERVER_URL>' first.");
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
        println!("\nToken expired. Run 'encjson-ctl login' to re-authenticate.");
    }
    Ok(())
}
