mod crypto;
mod error;
mod json_utils;
mod key_store;

use clap::{Parser, Subcommand, ValueEnum};
use serde_json::Value;
use std::ffi::OsStr;
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;

use crate::crypto::{SecureBox, generate_key_pair};
use crate::error::Error;
use crate::json_utils::{TransformMode, dotenv_exports, env_exports, transform_json};
use crate::key_store::{load_private_key, save_private_key};

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
        /// Optional key directory (overrides ENCJSON_KEYDIR, default is ~/.encjson)
        #[arg(short, long)]
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

        /// Optional key directory (overrides ENCJSON_KEYDIR)
        #[arg(long)]
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

        /// Optional key directory (overrides ENCJSON_KEYDIR)
        #[arg(long)]
        keydir: Option<PathBuf>,

        /// Output format (json / shell / dot-env)
        #[arg(short = 'o', long = "output", value_enum, default_value_t = OutputFormat::Json)]
        output: OutputFormat,
    },

    /// (Deprecated) shortcut for `decrypt -o shell`
    Env {
        /// Input file (otherwise reads from stdin)
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Optional key directory (overrides ENCJSON_KEYDIR)
        #[arg(long)]
        keydir: Option<PathBuf>,
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
        if let Err(e) = run(cmd) {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    }
}

fn run(command: Commands) -> Result<()> {
    match command {
        Commands::Init { keydir } => cmd_init(keydir),
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
        } => cmd_decrypt(file, input, write, keydir, output),
        Commands::Env { file, keydir } => {
            cmd_decrypt(file, None, false, keydir, OutputFormat::Shell)
        }
    }
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
) -> Result<()> {
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
