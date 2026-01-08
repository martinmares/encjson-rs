use crate::crypto::{CryptoError, SecureBox};
use serde_json::Value;
use std::collections::HashMap;
use tracing::debug;

#[derive(Copy, Clone, Debug)]
pub enum TransformMode {
    Encrypt,
    Decrypt,
}

/// Recursively walk JSON and encrypt/decrypt only String values.
/// `_public_key` is always left untouched.
pub fn transform_json(
    v: &mut Value,
    sb: &SecureBox,
    mode: TransformMode,
) -> Result<(), CryptoError> {
    match v {
        Value::Object(map) => {
            for (k, val) in map.iter_mut() {
                if k == "_public_key" {
                    continue;
                }

                match val {
                    Value::String(s) => {
                        let new_s = match mode {
                            TransformMode::Encrypt => sb.encrypt_value(s)?,
                            TransformMode::Decrypt => sb.decrypt_value(s)?,
                        };
                        *s = new_s;
                    }
                    _ => {
                        transform_json(val, sb, mode)?;
                    }
                }
            }
        }
        Value::Array(arr) => {
            for item in arr {
                transform_json(item, sb, mode)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Escape a string so that it is safe inside double quotes in a shell/.env line.
fn escape_env_value(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '`' => out.push_str("\\`"),
            '$' => out.push_str("\\$"),
            _ => out.push(ch),
        }
    }
    out
}

/// Export environment variables as shell `export` lines.
/// Looks for `environment` or `env` at the top level.
pub fn env_exports(root: &Value) -> Result<String, CryptoError> {
    env_exports_internal(root, true)
}

/// Export environment variables as .env format (no `export` prefix).
/// Export environment variables as .env format (no "export" and no quotes).
pub fn dotenv_exports(root: &Value) -> Result<String, CryptoError> {
    dotenv_exports_with_lookup(root, |key| std::env::var(key).ok())
}

fn dotenv_exports_with_lookup<F>(root: &Value, env_lookup: F) -> Result<String, CryptoError>
where
    F: Fn(&str) -> Option<String>,
{
    let obj = root
        .as_object()
        .ok_or_else(|| CryptoError::Invalid("root JSON must be an object".to_string()))?;

    let env_obj = obj
        .get("environment")
        .or_else(|| obj.get("env"))
        .and_then(|v| v.as_object())
        .ok_or_else(|| {
            CryptoError::Invalid("JSON must contain `environment` or `env` object".to_string())
        })?;

    let mut out = String::new();
    let mut cache = HashMap::new();
    let mut stack = Vec::new();

    for (key, val) in env_obj {
        match val {
            // pro strings: KEY=value (bez uvozovek, bez escapování)
            Value::String(s) => {
                let resolved =
                    render_env_string(s, key, env_obj, &mut cache, &mut stack, &env_lookup)?;
                out.push_str(key);
                out.push('=');
                out.push_str(&resolved);
                out.push('\n');
            }
            // pro non-strings: KEY=<json>
            other => {
                out.push_str(key);
                out.push('=');
                out.push_str(&other.to_string());
                out.push('\n');
            }
        }
    }

    Ok(out)
}

fn env_exports_internal(root: &Value, with_export: bool) -> Result<String, CryptoError> {
    env_exports_internal_with_lookup(root, with_export, |key| std::env::var(key).ok())
}

fn env_exports_internal_with_lookup<F>(
    root: &Value,
    with_export: bool,
    env_lookup: F,
) -> Result<String, CryptoError>
where
    F: Fn(&str) -> Option<String>,
{
    let obj = root
        .as_object()
        .ok_or_else(|| CryptoError::Invalid("root JSON must be an object".to_string()))?;

    let env_obj = obj
        .get("environment")
        .or_else(|| obj.get("env"))
        .and_then(|v| v.as_object())
        .ok_or_else(|| {
            CryptoError::Invalid("JSON must contain `environment` or `env` object".to_string())
        })?;

    let mut out = String::new();
    let mut cache = HashMap::new();
    let mut stack = Vec::new();

    for (key, val) in env_obj {
        match val {
            Value::String(s) => {
                let resolved =
                    render_env_string(s, key, env_obj, &mut cache, &mut stack, &env_lookup)?;
                let escaped = escape_env_value(&resolved);
                if with_export {
                    // export KEY="escaped"
                    out.push_str("export ");
                    out.push_str(key);
                    out.push_str("=\"");
                    out.push_str(&escaped);
                    out.push_str("\"\n");
                } else {
                    // KEY="escaped"
                    out.push_str(key);
                    out.push_str("=\"");
                    out.push_str(&escaped);
                    out.push_str("\"\n");
                }
            }
            other => {
                // Non-string values are exported as-is (e.g. numbers/bools)
                if with_export {
                    out.push_str("export ");
                }
                out.push_str(key);
                out.push('=');
                out.push_str(&other.to_string());
                out.push('\n');
            }
        }
    }

    Ok(out)
}

fn render_env_string(
    input: &str,
    current_key: &str,
    env_obj: &serde_json::Map<String, Value>,
    cache: &mut HashMap<String, String>,
    stack: &mut Vec<String>,
    env_lookup: &impl Fn(&str) -> Option<String>,
) -> Result<String, CryptoError> {
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i..].starts_with("{env:") {
            let start = i + "{env:".len();
            if let Some(end_rel) = input[start..].find('}') {
                let end = start + end_rel;
                let key = &input[start..end];
                let resolved = resolve_env_key(key, env_obj, cache, stack, env_lookup)?;
                if let Some(value) = &resolved.value {
                    out.push_str(value);
                } else {
                    out.push_str(&input[i..=end]);
                }
                debug!(
                    key = current_key,
                    placeholder = key,
                    source = resolved.source.as_str(),
                    value = resolved.value.as_deref(),
                    "encjson: expand"
                );
                i = end + 1;
                continue;
            }
        }
        let ch = input[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    Ok(out)
}

fn resolve_env_key(
    key: &str,
    env_obj: &serde_json::Map<String, Value>,
    cache: &mut HashMap<String, String>,
    stack: &mut Vec<String>,
    env_lookup: &impl Fn(&str) -> Option<String>,
) -> Result<ResolvedValue, CryptoError> {
    if let Some(cached) = cache.get(key) {
        return Ok(ResolvedValue::from_json(cached.clone()));
    }

    if stack.iter().any(|k| k == key) {
        let mut path = stack.join(" -> ");
        if !path.is_empty() {
            path.push_str(" -> ");
        }
        path.push_str(key);
        return Err(CryptoError::Invalid(format!(
            "environment reference cycle detected: {path}"
        )));
    }

    if let Some(val) = env_obj.get(key) {
        stack.push(key.to_string());
        let resolved = match val {
            Value::String(s) => render_env_string(s, key, env_obj, cache, stack, env_lookup)?,
            other => other.to_string(),
        };
        stack.pop();
        cache.insert(key.to_string(), resolved.clone());
        return Ok(ResolvedValue::from_json(resolved));
    }

    match env_lookup(key) {
        Some(v) => Ok(ResolvedValue::from_env(v)),
        None => Ok(ResolvedValue::missing()),
    }
}

enum ResolvedSource {
    Json,
    OsEnv,
    Missing,
}

struct ResolvedValue {
    value: Option<String>,
    source: ResolvedSource,
}

impl ResolvedValue {
    fn from_json(value: String) -> Self {
        Self {
            value: Some(value),
            source: ResolvedSource::Json,
        }
    }

    fn from_env(value: String) -> Self {
        Self {
            value: Some(value),
            source: ResolvedSource::OsEnv,
        }
    }

    fn missing() -> Self {
        Self {
            value: None,
            source: ResolvedSource::Missing,
        }
    }
}

impl ResolvedSource {
    fn as_str(&self) -> &'static str {
        match self {
            ResolvedSource::Json => "json",
            ResolvedSource::OsEnv => "env",
            ResolvedSource::Missing => "missing",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn encrypts_only_strings_and_leaves_numbers() {
        let mut v = json!({
            "_public_key": "91c359808554f94d4a84208630f386d65a70fb9f843756953cf83a5c1b488640",
            "environment": {
                "DB_PASS": "secret",
                "DB_PORT": 5432,
                "FLAG": true
            }
        });

        // Dummy key pair - just needs to be valid hex of correct length.
        let sb = SecureBox::new_from_hex(
            "24e55b25c598d4df78387de983b455144e197e3e63239d0c1fc92f862bbd7c0c",
            "91c359808554f94d4a84208630f386d65a70fb9f843756953cf83a5c1b488640",
        )
        .unwrap();

        transform_json(&mut v, &sb, TransformMode::Encrypt).unwrap();

        let env = v.get("environment").unwrap().as_object().unwrap();
        assert!(
            env.get("DB_PASS")
                .unwrap()
                .as_str()
                .unwrap()
                .starts_with("EncJson[@api=")
        );
        assert_eq!(env.get("DB_PORT").unwrap(), &json!(5432));
        assert_eq!(env.get("FLAG").unwrap(), &json!(true));
    }

    #[test]
    fn env_exports_after_decrypt_shell() {
        let v = json!({
            "_public_key": "dummy",
            "environment": {
                "DB_PASS": "secret",
                "DB_PORT": 5432,
                "FLAG": true
            }
        });

        let exports = env_exports(&v).unwrap();
        assert!(exports.contains("export DB_PASS=\"secret\""));
        assert!(exports.contains("export DB_PORT=5432"));
        assert!(exports.contains("export FLAG=true"));
    }

    #[test]
    fn env_exports_after_decrypt_dotenv() {
        let v = json!({
            "_public_key": "dummy",
            "environment": {
                "DB_PASS": "secret",
                "DB_PORT": 5432,
                "FLAG": true
            }
        });

        let dotenv = dotenv_exports(&v).unwrap();
        assert!(dotenv.contains("DB_PASS=secret"));
        assert!(dotenv.contains("DB_PORT=5432"));
        assert!(dotenv.contains("FLAG=true"));
        assert!(!dotenv.contains("export "));
        assert!(!dotenv.contains('"'));
    }

    #[test]
    fn env_exports_escapes_backslashes() {
        let v = json!({
            "environment": {
                "P": r#"/tmp/foo\bar"#,
            }
        });

        let exports = env_exports(&v).unwrap();

        // export P="/tmp/foo\\bar"
        assert_eq!(exports, "export P=\"/tmp/foo\\\\bar\"\n");
    }

    #[test]
    fn env_exports_escapes_quotes_and_dollar() {
        let v = json!({
            "environment": {
                "P": r#"He said: "hi" and $HOME"#,
            }
        });

        let exports = env_exports(&v).unwrap();

        // export P="He said: \"hi\" and \$HOME"
        assert_eq!(exports, "export P=\"He said: \\\"hi\\\" and \\$HOME\"\n");
    }

    #[test]
    fn env_exports_escapes_backticks() {
        let v = json!({
            "environment": {
                "P": "echo `uname -s`",
            }
        });

        let exports = env_exports(&v).unwrap();

        // export P="echo \`uname -s\`"
        assert_eq!(exports, "export P=\"echo \\`uname -s\\`\"\n");
    }

    #[test]
    fn env_exports_escapes_combo_of_specials() {
        let v = json!({
            "environment": {
                "P": r#"`weird "$VALUE" path\with\stuff`"#,
            }
        });

        let exports = env_exports(&v).unwrap();

        // originál: `weird "$VALUE" path\with\stuff`
        // po escapu: \`weird \"\$VALUE\" path\\with\\stuff\`
        assert_eq!(
            exports,
            "export P=\"\\`weird \\\"\\$VALUE\\\" path\\\\with\\\\stuff\\`\"\n"
        );
    }

    #[test]
    fn env_exports_resolves_references_from_json() {
        let v = json!({
            "environment": {
                "DB_USERNAME": "other",
                "DB_HOST": "localhost",
                "DB_NAME": "otherdb",
                "DB_CONNECTION_STRING": "postgresql://{env:DB_USERNAME}@{env:DB_HOST}/{env:DB_NAME}"
            }
        });

        let exports = env_exports(&v).unwrap();
        assert!(
            exports
                .contains("export DB_CONNECTION_STRING=\"postgresql://other@localhost/otherdb\"")
        );
    }

    #[test]
    fn env_exports_resolves_references_from_os_env() {
        let v = json!({
            "environment": {
                "DB_URL": "postgresql://{env:ENCJSON_TEST_HOST}/db"
            }
        });

        let exports = env_exports_internal_with_lookup(&v, true, |key| {
            if key == "ENCJSON_TEST_HOST" {
                Some("example.local".to_string())
            } else {
                None
            }
        })
        .unwrap();
        assert!(exports.contains("export DB_URL=\"postgresql://example.local/db\""));
    }

    #[test]
    fn env_exports_detects_reference_cycles() {
        let v = json!({
            "environment": {
                "A": "{env:B}",
                "B": "{env:A}"
            }
        });

        let err = env_exports(&v).unwrap_err();
        assert!(
            err.to_string()
                .contains("environment reference cycle detected")
        );
    }
}
