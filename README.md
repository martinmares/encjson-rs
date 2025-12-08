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

The symmetric key is derived from the public/private key pair using **X25519** + **BLAKE2b**, and encryption uses **XChaCha20-Poly1305** AEAD — all implemented in pure Rust (no C libraries).

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
- Decrypt JSON files (`encjson decrypt`)
- Export environment variables from JSON (`encjson env`)
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
# encjson 0.2.0 (rust)
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
encjson init --keydir /etc/encjson
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

### 3. Decrypt a JSON file (`decrypt`)

To decrypt back to plain JSON:

```bash
encjson decrypt -f env.secured.json
```

By default, the result is printed to stdout.  
To overwrite the file in place:

```bash
encjson decrypt -f env.secured.json -w
```

If decryption fails, you will see a clear error such as:

```text
Error: decryption failed: ciphertext may be corrupted, use a wrong key, or come from an incompatible encjson version
```

### 4. Export environment variables (`env`)

`encjson env` is intended for `startup.sh` scripts, Docker entrypoints, Kubernetes init containers, etc.  
It looks for either `env` or `environment` at the top level, decrypts string values and prints `export` lines.

For example:

```json
{
  "_public_key": "91c3598085...",
  "environment": {
    "DB_PASS": "EncJson[@api=2.0:@box=…]",
    "KAFKA_PASS": "EncJson[@api=2.0:@box=…]"
  }
}
```

Command:

```bash
encjson env -f env.secured.json
```

Output:

```bash
export DB_PASS="super-secret-password"
export KAFKA_PASS="another-secret"
```

Special characters like `\`, `"`, `` ` `` and `$` are escaped so that the output is safe to `eval`:

```bash
eval "$(encjson env -f env.secured.json)"
```

### Key lookup

The tool finds the private key in this order:

1. If `ENCJSON_PRIVATE_KEY` is set and non-empty, it is used directly as a 64-hex string.
2. Otherwise it looks up a file named `<public_hex>` in:
   - `$ENCJSON_KEYDIR` (if set), or
   - `~/.encjson`.

If no key can be found, the command fails with a clear error.

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
