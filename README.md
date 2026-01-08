# encjson-rs

A small command-line tool for storing secrets in JSON files using public/private key encryption and modern authenticated encryption built on pure Rust crypto crates.

It is designed so you can safely commit configuration files into Git, while keeping only the actual secrets encrypted, and still easily decrypt them at application startup.

## Overview

`encjson-rs` is designed for files like:

```json
{
  "_public_key": "91c359808554f94d4a84208630f386d65a70fb9f843756953cf83a5c1b488640",
  "environment": {
    "DB_PASS": "super-secret-password",
    "DB_PORT": 5432,
    "KAFKA_PASS": "another-secret"
  }
}
```

It:

- uses `_public_key` to find the matching private key,
- encrypts **only string values** in the JSON (numbers / booleans / null stay as-is),
- never encrypts `_public_key`,
- stores encrypted values as:

```text
EncJson[@api=2.0:@box=<base64(nonce || ciphertext || tag)>]
```

where the payload is a base64-encoded concatenation of:

- 24-byte nonce,
- ciphertext (`XChaCha20`),
- 16-byte authentication tag (`Poly1305`).

The symmetric key is derived from the public/private key pair using **X25519** + **BLAKE2b**, and encryption uses **XChaCha20-Poly1305** AEAD - all implemented in pure Rust (no C libraries).

## Cryptography

This section documents the cryptographic design in more detail.

### Keys

- You work with a pair of 32-byte keys, both represented as 64-hex strings:
  - a “public” key, stored in the JSON file under `_public_key`,
  - a “private” key, stored locally in a file (or in `ENCJSON_PRIVATE_KEY`).

Internally:

- The private key is interpreted as an **X25519 static secret** (`x25519-dalek::StaticSecret`).
- The public key is interpreted as an **X25519 public key** (`x25519-dalek::PublicKey`).
- A shared secret is computed as:

  ```text
  shared = X25519(private, public)
  ```

### Key derivation (KDF)

From the 32-byte X25519 shared secret, a 32-byte symmetric key is derived using **BLAKE2b**:

```text
key = Blake2b512(shared)[0..32]
```

That `key` is then used as the AEAD key.

### AEAD: XChaCha20-Poly1305

Authenticated encryption is performed using **XChaCha20-Poly1305**:

- Algorithm: `XChaCha20Poly1305` from the `chacha20poly1305` crate.
- Nonce: 24 bytes, generated randomly using `OsRng`.
- Associated data: currently **none** (empty).
- Output: `ciphertext || tag` (16-byte `Poly1305` tag).

The final stored payload is:

```text
nonce (24 bytes) || ciphertext (N bytes) || tag (16 bytes)
```

and this concatenation is base64-encoded and wrapped as:

```text
EncJson[@api=2.0:@box=<base64(...)].
```

Properties:

- Confidentiality: an attacker cannot read plaintext without the correct key pair.
- Integrity / authenticity: any modification of the ciphertext/nonce/tag or use of a wrong key results in decryption failure.

> Note: The exact format is marked with `@api=2.0` in the string. This acts as a protocol version marker and makes it explicit that the format is different from the old Crystal implementation (`@api=1.0`).

## Features

- Generate random public/private key pairs (`encjson init`)
- Encrypt JSON files in place or to stdout (`encjson encrypt`)
- Decrypt JSON files with multiple output formats (`encjson decrypt -o json|shell|dot-env`)
- Edit environment values in a terminal UI (`encjson edit --ui`)
- Export environment variables from JSON as shell exports or .env format (`encjson decrypt -o shell` / `encjson decrypt -o dot-env`)
- Uses `ENCJSON_KEYDIR` and `ENCJSON_PRIVATE_KEY` in a simple, predictable way
- Pure Rust implementation, no C libraries or `libclang` required
- Simple text format, suitable for committing encrypted configs into Git

## Installation

### Prerequisites

- Rust toolchain (stable), e.g. via [rustup](https://rustup.rs)

On most Linux systems, you only need a standard build environment:

```bash
# Example for Debian/Ubuntu-like systems
apt-get update
apt-get install -y build-essential curl ca-certificates
curl https://sh.rustup.rs -sSf | sh -s -- -y
```

No C Monocypher library or `libclang` is needed.

### Build from source

Clone the repository and run:

```bash
cargo build --release
```

The resulting binary will be in:

```text
target/release/encjson
```

(You can copy or symlink it somewhere in `$PATH`, e.g. `/usr/local/bin/encjson`.)

## Command-line usage

### Version

```bash
encjson -v
# encjson 0.6.0 (rust)
```

### Help / `--help`

Example for `encrypt` (the same `-k/--keydir` option is available for `init`, `decrypt` and `env`):

```bash
encjson encrypt --help
```

```text
Usage: encjson encrypt [OPTIONS]

Options:
  -f, --file <FILE>      Input file (otherwise reads from stdin)
  -w, --write            Overwrite the input file in place
  -k, --keydir <KEYDIR>  Optional key directory (overrides ENCJSON_KEYDIR)
  -h, --help             Print help
```

Examples:

```bash
encjson decrypt -f env.secured.json -k /etc/encjson
encjson env -f env.secured.json -k /etc/encjson
```

### 1. Generate key pair (`init`)

```bash
encjson init
```

Typical output:

```text
Generated key pair (hex):
 => 🍺 public:  91c359808554f94d4a84208630f386d65a70fb9f843756953cf83a5c1b488640
 => 🔑 private: 24e55b25c598d4df78387de983b455144e197e3e63239d0c1fc92f862bbd7c0c
 => 💾 saved to: /home/user/.encjson/91c359808554f94d4a84208630f386d65a70fb9f843756953cf83a5c1b488640
```

By default, the private key is saved to:

- `$ENCJSON_KEYDIR/<public_hex>` if `ENCJSON_KEYDIR` is set, or
- `~/.encjson/<public_hex>` otherwise.

You can override the directory:

```bash
encjson init -k /etc/encjson
```

### 2. Encrypt a JSON file (`encrypt`)

Given a file `env.secured.json`:

```json
{
  "_public_key": "91c359808554f94d4a84208630f386d65a70fb9f843756953cf83a5c1b488640",
  "environment": {
    "DB_PASS": "super-secret-password",
    "DB_PORT": 5432,
    "KAFKA_PASS": "another-secret"
  }
}
```

You can encrypt it in place:

```bash
encjson encrypt -f env.secured.json -w
```

To override the key directory:

```bash
encjson encrypt -f env.secured.json -w -k /etc/encjson
```

After encryption:

```json
{
  "_public_key": "91c359808554f94d4a84208630f386d65a70fb9f843756953cf83a5c1b488640",
  "environment": {
    "DB_PASS": "EncJson[@api=2.0:@box=…]",
    "DB_PORT": 5432,
    "KAFKA_PASS": "EncJson[@api=2.0:@box=…]"
  }
}
```

Notes:

- Only string values are encrypted.
- `_public_key` is never touched.
- If a string is already in `EncJson[@api=…:@box=…]` format, it is left unchanged (idempotent encrypt).

#### Reading from stdin

If you do not specify `-f`, `encjson encrypt` reads JSON from stdin:

```bash
cat env.secured.json | encjson encrypt
```

You can also explicitly use `-f -` or a positional `-` to mean “read from stdin” (Unix-style):

```bash
cat env.secured.json | encjson encrypt -f -
cat env.secured.json | encjson encrypt -
```

Both variants read JSON from stdin and print encrypted JSON to stdout.

### 3. Decrypt a JSON file (`decrypt`)

By default, `decrypt` prints decrypted JSON:

```bash
encjson decrypt -f env.secured.json
```

To overwrite the file in place (only valid for JSON output):

```bash
encjson decrypt -f env.secured.json -w
```

The `-o/--output` flag controls the output format:

If decryption fails, you will see a clear error such as:

- `-o json` (default) - decrypted JSON (as above)
- `-o shell` - shell `export` lines, suitable for `eval`
- `-o dot-env` - `.env` file format (`KEY="value"` per line)

To override the key directory:

```bash
encjson decrypt -f env.secured.json -w -k /etc/encjson
```

#### Reading from stdin

If you do not specify `-f`, `encjson decrypt` reads JSON from stdin:

```bash
cat env.secured.json | encjson decrypt -o shell
```

You can also explicitly use `-f -` or a positional `-` to mean “read from stdin” (Unix-style):

```bash
cat env.secured.json | encjson decrypt -f - -o shell
cat env.secured.json | encjson decrypt -o shell -
cat env.secured.json | encjson decrypt -
```

Examples:

#### Decrypt to shell exports

```bash
encjson decrypt -f env.secured.json -o shell
# or stdin:
cat env.secured.json | encjson decrypt -o shell
# or explicitly stdin:
cat env.secured.json | encjson decrypt -f - -o shell
cat env.secured.json | encjson decrypt -o shell -
```

To override the key directory:

```bash
encjson env -f env.secured.json -k /etc/encjson
```

Output:

```bash
export DB_PASS="super-secret-password"
export KAFKA_PASS="another-secret"
```

This is safe to use with:

```bash
eval "$(encjson decrypt -f env.secured.json -o shell)"
# or:
eval "$(cat env.secured.json | encjson decrypt -o shell)"
```

Special characters like `\`, `"`, `` ` `` and `$` are escaped so that the export lines are shell-safe.

#### Decrypt to .env format

```bash
encjson decrypt -f env.secured.json -o dot-env > .env
# or:
cat env.secured.json | encjson decrypt -o dot-env > .env
# or:
cat env.secured.json | encjson decrypt -o dot-env - > .env
```

Output (in `.env`):

```bash
DB_PASS="super-secret-password"
KAFKA_PASS="another-secret"
```

Non-string values (numbers, booleans) are written as-is, e.g.:

```bash
DB_PORT=5432
FLAG=true
```

If decryption fails, you will see a clear error such as:

```text
Error: decryption failed: ciphertext may be corrupted, use a wrong key, or come from an incompatible encjson version
```

### 4. Export environment variables (`decrypt -o shell` / `env`)

The recommended way to export environment variables from the JSON is:

```bash
encjson decrypt -f env.secured.json -o shell
# or:
cat env.secured.json | encjson decrypt -o shell
```

or directly:

```bash
eval "$(encjson decrypt -f env.secured.json -o shell)"
```

The tool looks for either `env` or `environment` at the top level, decrypts string values, resolves `{env:VAR}` placeholders, and prints one line per key:

```bash
export DB_PASS="super-secret-password"
export KAFKA_PASS="another-secret"
export DB_PORT=5432
export FLAG=true
```

Placeholders are resolved in this order:
1. If `VAR` exists in the same JSON `env`/`environment` object, use that value.
2. Otherwise fall back to the OS environment.

If you want to inspect how `{env:...}` expansions were resolved, enable debug tracing:

```bash
RUST_LOG=debug encjson decrypt -f env.secured.json -o shell --debug
```

Logs are written to stderr so they won't break `eval`.

The legacy command:

```bash
encjson env -f env.secured.json
```

is kept as a shortcut/compatibility wrapper for:

```bash
encjson decrypt -f env.secured.json -o shell
```

and behaves the same way.

### 5. Edit environment variables (`edit`)

`encjson edit` opens a terminal UI for editing the `environment` / `env` object directly.

```bash
encjson edit -f env.secured.json
```

Notes:

- Values are shown decrypted so you can edit them easily.
- Only edited values are re-encrypted; untouched values keep their original ciphertext.
- On exit you will be prompted to `Save` or `Discard` changes.
- Works even if `_public_key` is missing (treated as plain JSON).
- `Values` list shows `<empty>` or `<spaces:N>` for empty/whitespace-only values.
- Edit modal includes a hex preview so trailing spaces and non-printable bytes are visible.
- Keys: `Up/Down` select, `e` edit, `/` filter (key/value), `+` add, `r` rename, `d` delete, `v` diff, `s` save, `q` quit.
- Diff view: `v` opens a colored diff of added/removed/changed values.

Screen-style examples:

```text
Editing env.secured.json in /path/to/project | modified 2025-02-14 10:32:11 +01:00
┌ Keys ────────────────────────────────────┐┌ Values ─────────────────────────────────┐
│ > SPRING_DATASOURCE_USERNAME             ││ > tsm_admin                             │
│   SPRING_DATASOURCE_PASSWORD             ││   <empty>                               │
│   KAFKA_SASL_JAAS_CONFIG                 ││   org.apache.kafka...                   │
└──────────────────────────────────────────┘└─────────────────────────────────────────┘
key: SPRING_DATASOURCE_USERNAME
Up/Down select | e edit | / filter | + add | r rename | d delete | v diff | s save | q quit
```

```text
┌ Diff (unsaved) ───────────────────────────────────────────────────────────────┐
│ - SPRING_DATASOURCE_PASSWORD=old-secret                                       │
│ + SPRING_DATASOURCE_PASSWORD=new-secret                                       │
│ + NEW_FLAG=true                                                               │
└-──────────────────────────────────────────────────────────────────────────────┘
```

### Key lookup

The tool finds the private key in this order:

1. If `ENCJSON_PRIVATE_KEY` is set and non-empty, it is used directly as a 64-hex string.
2. Otherwise it looks up a file named `<public_hex>` in:
   - the `-k/--keydir` CLI argument (if provided), or
   - `$ENCJSON_KEYDIR` (if set), or
   - `~/.encjson`.

If no key can be found, the command fails with a clear error.

## Windows specifics

`encjson-rs` is primarily developed and tested on Unix-like systems, but it also works on Windows (including cross-compiled binaries).

### Emoji output in `init`

On Unix-like systems, `encjson init` prints some small emoji decorations:

```text
Generated key pair (hex):
 => 🍺 public:  ...
 => 🔑 private: ...
 => 💾 saved to: ...
```

On Windows consoles (especially older `cmd.exe`), Unicode/emoji rendering can be unreliable. To avoid broken glyphs:

- On Windows builds, `encjson init` automatically falls back to **ASCII-only** output:

  ```text
  Generated key pair (hex):
   => public:  ...
   => private: ...
   => saved to: ...
  ```

- On Unix-like systems, you can also disable emoji explicitly by setting:

  ```bash
  ENCJSON_NO_EMOJI=1 encjson init
  ```

This makes the output more predictable in logs and on terminals with limited font/encoding support.

### Key directory on Windows

The default key directory is determined as follows:

1. If `ENCJSON_KEYDIR` is set, it is always used (on all platforms).
2. Otherwise:
   - On Unix-like systems:
     - `~/.encjson` (based on `$HOME`).
   - On Windows:
     - If `HOME` is set (e.g. Git Bash / MSYS), use `%HOME%\.encjson`.
     - Else, if `USERPROFILE` is set, use `%USERPROFILE%\.encjson`
       (typical case: `C:\Users\<name>\.encjson`).
     - Else, if both `HOMEDRIVE` and `HOMEPATH` are set, use `%HOMEDRIVE%%HOMEPATH%\.encjson`.
     - As a last-resort fallback, `.\.encjson` in the current working directory.

In practice, on a “normal” Windows 10/11 installation, the default ends up under the user’s profile directory, e.g.:

```text
C:\Users\YourName\.encjson
```

If you want complete control (for example, to share a key directory between WSL, Git Bash and native Windows binaries), set `ENCJSON_KEYDIR` explicitly on that machine.

## Migration from the Crystal version

The original Crystal implementation and this Rust implementation use **different key derivation / encryption format** under the hood:

- Crystal used `@api=1.0` with a Monocypher-based scheme.
- This Rust implementation uses `@api=2.0` with X25519 + BLAKE2b + XChaCha20-Poly1305.

Therefore:

- **Old (`@api=1.0`) encrypted values cannot be decrypted by `encjson-rs`.**
- **New (`@api=2.0`) encrypted values cannot be decrypted by the old Crystal tool.**

Recommended migration path:

1. Using the Crystal `encjson`:
   - Decrypt your existing `env.secured.json` files:
     ```bash
     encjson decrypt -f env.secured.json -w
     ```
2. Using `encjson-rs`:
   - Re-encrypt them:
     ```bash
     encjson encrypt -f env.secured.json -w
     ```
3. Commit the newly encrypted files into Git.
4. Update your containers / scripts to use the Rust binary (`encjson-rs`) going forward.

During migration, you can keep both binaries installed with different names, e.g.:

- `/usr/bin/encjson-crystal`
- `/usr/bin/encjson-rs`

and choose which one to symlink as `encjson` based on an environment variable (e.g. in your entrypoint script).

## Relationship to the Crystal project

- Original Crystal implementation: <https://github.com/martinmares/encjson>
- This Rust rewrite (`encjson-rs`) aims to be:
  - behaviour-compatible at the JSON / CLI level,
  - but with a clearly distinct and fully Rust-native crypto stack.

## License

This project is licensed under the [MIT License](./LICENSE).
