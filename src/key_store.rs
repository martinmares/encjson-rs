use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use crate::error::Error;

#[cfg(not(windows))]
fn home_dir() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(PathBuf::from)
}

#[cfg(windows)]
fn home_dir() -> Option<PathBuf> {
    use std::env;

    // 1) Pokud je nastavené HOME (např. Git Bash / MSYS), použij ho
    if let Ok(home) = env::var("HOME") {
        if !home.is_empty() {
            return Some(PathBuf::from(home));
        }
    }

    // 2) USERPROFILE je nejčastější "domov" na Windows
    if let Ok(up) = env::var("USERPROFILE") {
        if !up.is_empty() {
            return Some(PathBuf::from(up));
        }
    }

    // 3) HOMEDRIVE + HOMEPATH fallback (např. C:\Users\something)
    let drive = env::var("HOMEDRIVE").unwrap_or_default();
    let path = env::var("HOMEPATH").unwrap_or_default();
    if !drive.is_empty() && !path.is_empty() {
        return Some(PathBuf::from(format!("{drive}{path}")));
    }

    None
}

/// Defaultní adresář pro klíče (~/.encjson nebo to, co je v ENCJSON_KEYDIR).
pub fn default_key_dir() -> PathBuf {
    if let Ok(dir) = env::var("ENCJSON_KEYDIR") {
        return PathBuf::from(dir);
    }
    if let Some(home) = home_dir() {
        return home.join(".encjson");
    }
    // nouzový fallback - když fakt není žádný home
    PathBuf::from(".encjson")
}

/// Načte private key pro daný public key.
/// - pokud je nastaven ENCJSON_PRIVATE_KEY, použije ho
/// - jinak hledá soubor `<key_dir>/<public_hex>`
pub fn load_private_key(public_hex: &str, key_dir: Option<&Path>) -> Result<String, Error> {
    if let Ok(pk) = env::var("ENCJSON_PRIVATE_KEY") {
        if !pk.trim().is_empty() {
            return Ok(pk.trim().to_owned());
        }
    }

    let dir = key_dir.map(PathBuf::from).unwrap_or_else(default_key_dir);

    let path = dir.join(public_hex);

    match fs::read_to_string(&path) {
        Ok(s) => Ok(s.trim().to_owned()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err(Error::PrivateKeyNotFound(public_hex.to_owned()))
        }
        Err(e) => Err(Error::Io(e)),
    }
}

/// Uloží private key do souboru `<key_dir>/<public_hex>`.
pub fn save_private_key(
    public_hex: &str,
    private_hex: &str,
    key_dir: Option<&Path>,
) -> Result<PathBuf, Error> {
    let dir = key_dir.map(PathBuf::from).unwrap_or_else(default_key_dir);

    fs::create_dir_all(&dir)?;
    let path = dir.join(public_hex);
    fs::write(&path, private_hex)?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn unique_temp_dir(label: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        dir.push(format!("encjson-{label}-{stamp}-{}", std::process::id()));
        dir
    }

    fn set_env_var(key: &str, value: &Path) -> Option<String> {
        let prev = env::var(key).ok();
        unsafe {
            env::set_var(key, value);
        }
        prev
    }

    fn restore_env_var(key: &str, prev: Option<String>) {
        if let Some(val) = prev {
            unsafe {
                env::set_var(key, val);
            }
        } else {
            unsafe {
                env::remove_var(key);
            }
        }
    }

    #[test]
    fn load_private_key_prefers_cli_keydir_over_env() {
        let _guard = env_lock().lock().unwrap();
        let prev_private = env::var("ENCJSON_PRIVATE_KEY").ok();

        let cli_dir = unique_temp_dir("cli");
        let env_dir = unique_temp_dir("env");
        fs::create_dir_all(&cli_dir).unwrap();
        fs::create_dir_all(&env_dir).unwrap();

        let public_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        fs::write(cli_dir.join(public_hex), "cli-private").unwrap();
        fs::write(env_dir.join(public_hex), "env-private").unwrap();

        let prev_keydir = set_env_var("ENCJSON_KEYDIR", &env_dir);
        unsafe {
            env::remove_var("ENCJSON_PRIVATE_KEY");
        }

        let loaded = load_private_key(public_hex, Some(cli_dir.as_path())).unwrap();
        assert_eq!(loaded, "cli-private");

        restore_env_var("ENCJSON_KEYDIR", prev_keydir);
        restore_env_var("ENCJSON_PRIVATE_KEY", prev_private);
        let _ = fs::remove_dir_all(&cli_dir);
        let _ = fs::remove_dir_all(&env_dir);
    }

    #[test]
    fn load_private_key_falls_back_to_env_keydir() {
        let _guard = env_lock().lock().unwrap();
        let prev_private = env::var("ENCJSON_PRIVATE_KEY").ok();

        let env_dir = unique_temp_dir("env-only");
        fs::create_dir_all(&env_dir).unwrap();

        let public_hex = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        fs::write(env_dir.join(public_hex), "env-private").unwrap();

        let prev_keydir = set_env_var("ENCJSON_KEYDIR", &env_dir);
        unsafe {
            env::remove_var("ENCJSON_PRIVATE_KEY");
        }

        let loaded = load_private_key(public_hex, None).unwrap();
        assert_eq!(loaded, "env-private");

        restore_env_var("ENCJSON_KEYDIR", prev_keydir);
        restore_env_var("ENCJSON_PRIVATE_KEY", prev_private);
        let _ = fs::remove_dir_all(&env_dir);
    }
}
