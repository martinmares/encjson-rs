use crate::crypto::{CryptoError, SecureBox};
use serde_json::Value;

#[derive(Copy, Clone, Debug)]
pub enum TransformMode {
    Encrypt,
    Decrypt,
}

/// Rekurzivně projde JSON a šifruje/dešifruje **jen String** hodnoty.
/// `_public_key` nechává vždy být.
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
                transform_json(val, sb, mode)?;
            }
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                transform_json(item, sb, mode)?;
            }
        }
        Value::String(s) => {
            let new_val = match mode {
                TransformMode::Encrypt => sb.encrypt_value(s)?,
                TransformMode::Decrypt => sb.decrypt_value(s)?,
            };
            *s = new_val;
        }
        _ => {
            // čísla/bool/null necháváme jak jsou
        }
    }
    Ok(())
}

fn escape_env_value(v: &str) -> String {
    v.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('`', "\\`")
        .replace('$', "\\$")
}

/// Z top-levelu vytáhne `env` nebo `environment` a vygeneruje
/// řádky typu `export KEY="value"`.
pub fn env_exports(root: &Value) -> Option<String> {
    let obj = root.as_object()?;

    let env_obj = obj
        .get("env")
        .or_else(|| obj.get("environment"))?
        .as_object()?;

    let mut out = String::new();
    for (k, v) in env_obj {
        if let Some(s) = v.as_str() {
            let esc = escape_env_value(s);
            out.push_str(&format!("export {}=\"{}\"\n", k, esc));
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SecureBox;
    use serde_json::json;

    const PUBLIC_KEY: &str = "4c016009ce7246bebb08ec6856e76839a5c690cf01b30357914020aac9eebc8b";
    const PRIVATE_KEY: &str = "24e55b25c598d4df78387de983b455144e197e3e63239d0c1fc92f862bbd7c0c";

    #[test]
    fn encrypts_only_strings_and_leaves_numbers() {
        let sb = SecureBox::new_from_hex(PRIVATE_KEY, PUBLIC_KEY).unwrap();

        let mut v = json!({
            "_public_key": PUBLIC_KEY,
            "environment": {
                "DB_PASS": "tajne-heslo-do-db",
                "DB_PORT": 123
            }
        });

        transform_json(&mut v, &sb, TransformMode::Encrypt).unwrap();

        let env = v.get("environment").unwrap().as_object().unwrap();
        let db_pass = env.get("DB_PASS").unwrap().as_str().unwrap();
        let db_port = env.get("DB_PORT").unwrap().as_i64().unwrap();

        assert!(db_pass.starts_with("EncJson[@api=2.0:@box="));
        assert_eq!(db_port, 123);
        assert_eq!(v.get("_public_key").unwrap().as_str().unwrap(), PUBLIC_KEY);
    }

    #[test]
    fn env_exports_after_decrypt() {
        let sb = SecureBox::new_from_hex(PRIVATE_KEY, PUBLIC_KEY).unwrap();

        let mut v = json!({
            "_public_key": PUBLIC_KEY,
            "environment": {
                "DB_PASS": "tajne-heslo-do-db",
                "KAFKA_PASS": "tajne-heslo-do-kafka"
            }
        });

        // zašifrujeme
        transform_json(&mut v, &sb, TransformMode::Encrypt).unwrap();
        // a znovu dešifrujeme (simulace `encjson env`)
        transform_json(&mut v, &sb, TransformMode::Decrypt).unwrap();

        let exports = env_exports(&v).unwrap();
        assert!(exports.contains("export DB_PASS=\"tajne-heslo-do-db\""));
        assert!(exports.contains("export KAFKA_PASS=\"tajne-heslo-do-kafka\""));
    }
}
