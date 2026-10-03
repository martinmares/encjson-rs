use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

struct Sandbox(PathBuf);

impl Sandbox {
    fn new() -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("encjson-examples-{}-{unique}", std::process::id()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_encjson"));
        command
            .env_clear()
            .current_dir(&self.0)
            .env("HOME", &self.0)
            .env("ENCJSON_KEYDIR", self.0.join("keys"));
        command
    }

    fn run(&self, args: &[&str]) -> Output {
        let output = self.command().args(args).output().unwrap();
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn guide_is_read_only_even_with_unusable_key_provider_settings() {
    let sandbox = Sandbox::new();
    let output = sandbox
        .command()
        .args(["examples"])
        .env("ENCJSON_KEY_SOURCE", "not-a-provider")
        .env("ENCJSON_PRIVATE_KEY", "not-a-private-key")
        .env("ENCJSON_REMOTE_KEYS_URL", "http://127.0.0.1:1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    assert!(String::from_utf8_lossy(&output.stdout).starts_with("ENCJSON EXAMPLES\n"));
    assert!(!output.stdout.contains(&0x1b));
    assert_eq!(fs::read_dir(&sandbox.0).unwrap().count(), 0);
    let alias = sandbox.run(&["example", "--color", "never"]);
    assert_eq!(output.stdout, alias.stdout);
    let colored = sandbox.run(&["examples", "--color", "always"]);
    assert!(colored.stdout.contains(&0x1b));
}

#[test]
fn documented_v3_quickstart_roundtrips_and_exports_values() {
    let sandbox = Sandbox::new();
    sandbox.run(&["init", "--api", "3.0", "--create-file"]);
    sandbox.run(&["set", "-f", "env.secured.json", "APP_NAME", "demo", "-w"]);
    sandbox.run(&[
        "set",
        "-f",
        "env.secured.json",
        "DB_PASSWORD",
        "demo-password",
        "-w",
    ]);
    let stored: Value =
        serde_json::from_slice(&fs::read(sandbox.0.join("env.secured.json")).unwrap()).unwrap();
    assert!(stored.get("_recipient_key").is_some());
    assert_ne!(stored["environment"]["DB_PASSWORD"], "demo-password");
    let json = sandbox.run(&["decrypt", "-f", "env.secured.json"]);
    let decrypted: Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(decrypted["environment"]["APP_NAME"], "demo");
    assert_eq!(decrypted["environment"]["DB_PASSWORD"], "demo-password");
    let raw = sandbox.run(&[
        "decrypt",
        "-f",
        "env.secured.json",
        "--env-name",
        "DB_PASSWORD",
    ]);
    assert_eq!(
        String::from_utf8(raw.stdout).unwrap().trim(),
        "demo-password"
    );
    let dotenv = sandbox.run(&["decrypt", "-f", "env.secured.json", "-o", "dot-env"]);
    assert!(String::from_utf8_lossy(&dotenv.stdout).contains("DB_PASSWORD=demo-password"));
}
