mod crypto;
mod error;
mod json_utils;
mod key_store;

use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use serde_json::Value;

use crate::crypto::{SecureBox, generate_key_pair};
use crate::error::Error;
use crate::json_utils::{TransformMode, env_exports, transform_json};
use crate::key_store::{load_private_key, save_private_key};

type Result<T> = std::result::Result<T, Error>;

#[derive(Parser, Debug)]
#[command(
    name = "encjson",
    about = "Encrypted JSON (encrypt/decrypt) přes Monocypher"
)]
struct Cli {
    /// Print version and exit (jako `encjson -v`)
    #[arg(short = 'v', long = "version")]
    version: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Vygeneruje nový pár public/private klíčů
    Init {
        /// Volitelný adresář pro klíče (jinak ENCJSON_KEYDIR nebo ~/.encjson)
        #[arg(short, long)]
        keydir: Option<PathBuf>,
    },

    /// Zašifruje všechny string hodnoty v JSONu
    Encrypt {
        /// Vstupní soubor (jinak čte ze stdin)
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Přepsat vstupní soubor (in-place)
        #[arg(short = 'w', long)]
        write: bool,

        /// Volitelný keydir (přepíše ENCJSON_KEYDIR)
        #[arg(long)]
        keydir: Option<PathBuf>,
    },

    /// Dešifruje EncJson stringy v JSONu
    Decrypt {
        #[arg(short, long)]
        file: Option<PathBuf>,

        #[arg(short = 'w', long)]
        write: bool,

        #[arg(long)]
        keydir: Option<PathBuf>,
    },

    /// Vypíše export řádky z `env`/`environment` v JSONu
    Env {
        #[arg(short, long)]
        file: Option<PathBuf>,

        #[arg(long)]
        keydir: Option<PathBuf>,
    },
}

fn main() {
    let cli = Cli::parse();

    // Podpora `encjson -v`
    if cli.version {
        // CARGO_PKG_VERSION = verze z Cargo.toml
        println!("encjson {} (rust)", env!("CARGO_PKG_VERSION"));
        return;
    }

    if let Some(cmd) = cli.command {
        if let Err(e) = run(cmd) {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    } else {
        eprintln!("No command specified. Try --help.");
        std::process::exit(1);
    }
}

// run teď bere rovnou Commands, ne celý Cli
fn run(command: Commands) -> Result<()> {
    match command {
        Commands::Init { keydir } => cmd_init(keydir),
        Commands::Encrypt {
            file,
            write,
            keydir,
        } => cmd_encrypt(file, write, keydir),
        Commands::Decrypt {
            file,
            write,
            keydir,
        } => cmd_decrypt(file, write, keydir),
        Commands::Env { file, keydir } => cmd_env(file, keydir),
    }
}

fn cmd_init(keydir: Option<PathBuf>) -> Result<()> {
    let (priv_hex, pub_hex) = generate_key_pair();
    let path = save_private_key(&pub_hex, &priv_hex, keydir.as_deref())?;

    println!("Generated key pair (hex):");
    println!(" => 🍺 public:  {}", pub_hex);
    println!(" => 🔑 private: {}", priv_hex);
    println!(" => 💾 saved to: {}", path.display());

    Ok(())
}

fn cmd_encrypt(file: Option<PathBuf>, write: bool, keydir: Option<PathBuf>) -> Result<()> {
    let mut root = read_json_from(file.as_ref())?;
    let pub_hex = extract_public_key(&root)?;

    let priv_hex = load_private_key(pub_hex, keydir.as_deref())?;
    let sb = SecureBox::new_from_hex(&priv_hex, pub_hex)?;

    transform_json(&mut root, &sb, TransformMode::Encrypt)?;

    write_json_to(file.as_ref(), write, &root)?;
    Ok(())
}

fn cmd_decrypt(file: Option<PathBuf>, write: bool, keydir: Option<PathBuf>) -> Result<()> {
    let mut root = read_json_from(file.as_ref())?;
    let pub_hex = extract_public_key(&root)?;

    let priv_hex = load_private_key(pub_hex, keydir.as_deref())?;
    let sb = SecureBox::new_from_hex(&priv_hex, pub_hex)?;

    transform_json(&mut root, &sb, TransformMode::Decrypt)?;

    write_json_to(file.as_ref(), write, &root)?;
    Ok(())
}

fn cmd_env(file: Option<PathBuf>, keydir: Option<PathBuf>) -> Result<()> {
    let mut root = read_json_from(file.as_ref())?;
    let pub_hex = extract_public_key(&root)?;

    let priv_hex = load_private_key(pub_hex, keydir.as_deref())?;
    let sb = SecureBox::new_from_hex(&priv_hex, pub_hex)?;

    transform_json(&mut root, &sb, TransformMode::Decrypt)?;
    if let Some(exports) = env_exports(&root) {
        print!("{exports}");
    }
    Ok(())
}

fn read_json_from(path: Option<&PathBuf>) -> Result<Value> {
    let input = if let Some(p) = path {
        fs::read_to_string(p)?
    } else {
        let mut buf = String::new();
        io::stdin().read_to_string(&mut buf)?;
        buf
    };

    let v: Value = serde_json::from_str(&input)?;
    Ok(v)
}

fn write_json_to(path: Option<&PathBuf>, write_in_place: bool, value: &Value) -> Result<()> {
    let out = serde_json::to_string_pretty(value)?;
    if write_in_place {
        if let Some(p) = path {
            fs::write(p, out)?;
            return Ok(());
        }
    }
    println!("{out}");
    Ok(())
}

/// Vytáhne `_public_key` z JSONu, zkontroluje délku (64 hex znaků).
fn extract_public_key(root: &Value) -> Result<&str> {
    if let Some(pk) = root.get("_public_key").and_then(Value::as_str) {
        if pk.len() == 64 {
            return Ok(pk);
        } else {
            return Err(Error::InvalidPublicKey);
        }
    }
    Err(Error::MissingPublicKey)
}
