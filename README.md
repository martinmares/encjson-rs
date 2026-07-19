# encjson-rs

A small command-line tool for storing secrets in JSON files using public/private key encryption and modern authenticated encryption built on pure Rust crypto crates.

It is designed so you can safely commit configuration files into Git, while keeping only the actual secrets encrypted, and still easily decrypt them at application startup.

## Workspace Layout

This repository now uses Cargo workspace layout:

- `crates/encjson-core`: shared modules (crypto, JSON transforms, key store, OIDC session helpers, TUI control helpers)
- `crates/encjson-cli`: `encjson` binary
- `crates/encjson-keys-ctl`: `encjson-keys-ctl` binary
- `crates/encjson-keys-server`: `encjson-keys-server` binary
- `crates/encjson-keys-web`: `encjson-keys-web` binary (Tabler + Alpine + SSE)

Goal: keep binaries thin and move reusable logic into shared crate(s) for next split (`encjson-keys-web`, etc.).

## Design Docs

- Architecture anchor: `docs/ARCHITECTURE.md`
- Key sources and secure loading model: `docs/KEY_SOURCES.md` (proposed design)
- Key sources implementation plan: `docs/KEY_SOURCES_RFC.md` (phase checklist + acceptance criteria)


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

The Rust implementation also reads and writes the legacy Crystal-compatible
`EncJson[@api=1.0:...]` format. API 1.0 uses the original Monocypher-compatible
X25519/HChaCha20 construction and its historical `nonce || tag || ciphertext`
layout. New files still default to API 3.0; API 1.0 is supported only for
controlled compatibility and migration.

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
- Show key mapping for secured file (`encjson info`)
- Encrypt JSON files in place or to stdout (`encjson encrypt`)
- Decrypt JSON files with multiple output formats (`encjson decrypt -o json|shell|dot-env`)
- Edit environment values in a terminal UI (`encjson edit`)
- Export environment variables from JSON as shell exports or .env format (`encjson decrypt -o shell` / `encjson decrypt -o dot-env`)
- Uses `ENCJSON_KEYDIR` and `ENCJSON_PRIVATE_KEY` in a simple, predictable way
- Pure Rust implementation, no C libraries or `libclang` required
- Simple text format, suitable for committing encrypted configs into Git

## Installation

### Prerequisites

- Rust toolchain (stable), e.g. via [rustup](https://rustup.rs)
- Docker (optional, for local Postgres)

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

## Local Postgres (docker-compose)

```bash
docker compose up -d
```

Then set `.env` (see `.env.example`) and run the keys server:

```bash
export DATABASE_URL=postgres://encjson_admin:encjson_admin@localhost:5432/encjson
cargo run --bin encjson-keys-server
```

Keys server requires:

```bash
export ENCRYPTION_SECRET=change-me-to-a-secure-random-secret-at-least-32-chars
export ENCJSON_KEYS_AUTH=required
export ENCJSON_KEYS_JWT_ISSUER=https://sso.example.com
```

`ENCJSON_KEYS_JWT_*` configures the default `simple-idm-jwt` issuer.

Optional Kubernetes/OpenShift projected ServiceAccount JWT issuer:

```bash
export ENCJSON_KEYS_KUBE_SA_ISSUER=https://kubernetes.default.svc
export ENCJSON_KEYS_KUBE_SA_AUDIENCE=key-server
```

This enables the `kube-sa-jwt` issuer. The server validates the token signature,
issuer, audience and ServiceAccount identity claims, then normalizes the caller
into the internal principal model.

JWKS discovery order:

1. use `ENCJSON_KEYS_KUBE_SA_JWKS_URL` when set,
2. otherwise use `ENCJSON_KEYS_KUBE_SA_DISCOVERY_URL` when set,
3. otherwise use `{ENCJSON_KEYS_KUBE_SA_ISSUER}/.well-known/openid-configuration`.

JWKS are loaded at startup and refreshed once when a token arrives with an
unknown `kid`. This allows issuer key rotation without restarting the server.

Bearer-token authorization is local to the keys server. Use
`ENCJSON_KEYS_POLICY_FILE` to map normalized principals to key-server roles and
tenant access:

```bash
export ENCJSON_KEYS_POLICY_FILE=/etc/encjson/policy.yaml
```

Example `policy.yaml`:

```yaml
bindings:
  - id: admin-group
    subjects:
      issuer: simple-idm-jwt
      groups:
        - encjson:role:admin
    permissions:
      - resource: keys
        actions: [admin]

  - id: order-api-read-o2
    subjects:
      issuer: kube-sa-jwt
      kind: workload
      namespace: zis-test
      service_account: order-api
    permissions:
      - resource: keys
        actions: [read]
        tenants: [o2]
```

Optional trusted proxy header authentication:

```bash
export ENCJSON_KEYS_TRUSTED_PROXY_HEADERS=true
```

When enabled and no `Authorization: Bearer ...` header is present, the server
accepts identity from a protected proxy through:

```http
X-Auth-Subject: 97173b5f-6277-4aa7-b15e-a6c0b03cf0fd
X-Auth-User: mares
X-Auth-Email: mares@example.com
X-Auth-Groups: encjson:role:scoped,encjson:tenant:o2
```

The normalized issuer is `proxy`. This mode is safe only when direct public
access to `encjson-keys-server` is blocked and the edge proxy strips all
client-supplied `X-Auth-*` headers before setting trusted values.

## Keys Server Runtime Modes

`encjson-keys-server` supports both CLI arguments and environment variables (same names via `clap` `env = ...` mapping).

### Important: Single Port Behavior

The server always listens on one plain HTTP address (`ENCJSON_KEYS_ADDR`).
Terminate TLS at reverse proxy / ingress.

### HTTP + Bearer JWT

Use when TLS is terminated by reverse proxy / ingress (wildcard cert).

```bash
export ENCJSON_KEYS_AUTH=required
export ENCJSON_KEYS_JWT_ISSUER=https://sso.example.com
# optional:
# export ENCJSON_KEYS_JWKS_URL=https://sso.example.com/.well-known/jwks.json
# export ENCJSON_KEYS_JWT_AUDIENCE=encjson-keys
```

The default bearer-token issuer is named `simple-idm-jwt`.

Optional workload issuer:

```bash
export ENCJSON_KEYS_KUBE_SA_ISSUER=https://kubernetes.default.svc
export ENCJSON_KEYS_KUBE_SA_AUDIENCE=key-server
```

The workload issuer is named `kube-sa-jwt`.
By default the server loads JWKS URL from
`{ENCJSON_KEYS_KUBE_SA_ISSUER}/.well-known/openid-configuration`. Set
`ENCJSON_KEYS_KUBE_SA_DISCOVERY_URL` to override the discovery document URL, or
`ENCJSON_KEYS_KUBE_SA_JWKS_URL` to bypass discovery entirely.
JWKS cache is refreshed automatically on unknown `kid`.

To grant workloads access to tenants, configure local policy:

```bash
export ENCJSON_KEYS_POLICY_FILE=/etc/encjson/policy.yaml
```

### HTTP + Trusted Proxy Headers

Use when `encjson-keys-server` is reachable only behind a trusted auth proxy.

```bash
export ENCJSON_KEYS_AUTH=required
export ENCJSON_KEYS_TRUSTED_PROXY_HEADERS=true
```

Accepted headers:

- `X-Auth-Subject`
- `X-Auth-User`
- `X-Auth-Email`
- `X-Auth-Groups`

`X-Auth-Groups` is comma-separated. Built-in group conventions are the same as
for Simple IDM JWTs: `encjson:role:admin`, `encjson:role:scoped` and
`encjson:tenant:<tenant>`. Local policy can also grant access to `issuer:
proxy`.

```yaml
bindings:
  - id: order-api-read-o2
    subjects:
      issuer: kube-sa-jwt
      kind: workload
      namespace: zis-test
      service_account: order-api
    permissions:
      - resource: keys
        actions: [read]
        tenants: [o2]
```

## ENV <-> CLI Matrix

This project now uses a unified model: every supported runtime environment variable has a corresponding CLI option.

### `encjson` CLI

| ENV | CLI |
| --- | --- |
| `ENCJSON_KEYDIR` | `-k, --keydir` |
| `ENCJSON_KEYS_URL` | `--keys-url` (`register`, `sync`) |
| `ENCJSON_ACCESS_TOKEN` | `--token` (`register`, `sync`) |
| `ENCJSON_PRIVATE_KEY` | `--private-key` (global) |
| `ENCJSON_TENANT` | `--tenant` (global) |
| `ENCJSON_ENV` | `--env` (global) |
| `ENCJSON_SCOPE_REQUIRED` | `--scope-required` (global) |
| `ENCJSON_LEGACY_MODE` | `--legacy-mode` (global) |
| `ENCJSON_KEY_SOURCE` | `--key-source` (global: `env|dir|remote-mtls|vault|conjur`) |
| `ENCJSON_REMOTE_KEYS_URL` | `--remote-keys-url` (global) |
| `ENCJSON_REMOTE_TLS_CERT_FILE` | `--remote-tls-cert-file` (global) |
| `ENCJSON_REMOTE_TLS_KEY_FILE` | `--remote-tls-key-file` (global) |
| `ENCJSON_REMOTE_TLS_CA_FILE` | `--remote-tls-ca-file` (global) |
| `ENCJSON_VAULT_ADDR` | `--vault-addr` (global) |
| `ENCJSON_VAULT_PATH` | `--vault-path` (global) |
| `ENCJSON_VAULT_TOKEN` | `--vault-token` (global) |
| `ENCJSON_VAULT_PUBLIC_FIELD` | `--vault-public-field` (global) |
| `ENCJSON_VAULT_PRIVATE_FIELD` | `--vault-private-field` (global) |
| `ENCJSON_CONJUR_APPLIANCE_URL` | `--conjur-appliance-url` (global) |
| `ENCJSON_CONJUR_ACCOUNT` | `--conjur-account` (global) |
| `ENCJSON_CONJUR_AUTHN_LOGIN` | `--conjur-authn-login` (global) |
| `ENCJSON_CONJUR_AUTHN_API_KEY` | `--conjur-authn-api-key` (global) |
| `ENCJSON_CONJUR_PUBLIC_VARIABLE_ID` | `--conjur-public-variable-id` (global) |
| `ENCJSON_CONJUR_PRIVATE_VARIABLE_ID` | `--conjur-private-variable-id` (global) |
| `ENCJSON_CONJUR_CA_CERT_FILE` | `--conjur-ca-cert-file` (global) |

### `encjson-keys-ctl` CLI

| ENV | CLI |
| --- | --- |
| `ENCJSON_KEYS_URL` | `--keys-url` |
| `ENCJSON_TENANT` | `--tenant` (global) |
| `ENCJSON_ENV` | `--env` (global) |
| `ENCJSON_SCOPE_REQUIRED` | `--scope-required` (global) |

### `encjson-keys-server`

| ENV | CLI |
| --- | --- |
| `DATABASE_URL` | `--database-url` |
| `ENCRYPTION_SECRET` | `--encryption-secret` |
| `ENCJSON_KEYS_ADDR` | `--keys-addr` |
| `ENCJSON_KEYS_AUTH` | `--keys-auth` |
| `ENCJSON_KEYS_JWT_ISSUER` | `--keys-jwt-issuer` |
| `ENCJSON_KEYS_JWKS_URL` | `--keys-jwks-url` |
| `ENCJSON_KEYS_JWT_AUDIENCE` | `--keys-jwt-audience` |
| `ENCJSON_KEYS_KUBE_SA_ISSUER` | `--keys-kube-sa-issuer` |
| `ENCJSON_KEYS_KUBE_SA_JWKS_URL` | `--keys-kube-sa-jwks-url` |
| `ENCJSON_KEYS_KUBE_SA_DISCOVERY_URL` | `--keys-kube-sa-discovery-url` |
| `ENCJSON_KEYS_KUBE_SA_AUDIENCE` | `--keys-kube-sa-audience` |
| `ENCJSON_KEYS_POLICY_FILE` | `--keys-policy-file` |
| `ENCJSON_KEYS_TRUSTED_PROXY_HEADERS` | `--keys-trusted-proxy-headers` |
| `ENCJSON_KEYS_RATE_LIMIT_PER_MINUTE` | `--keys-rate-limit-per-minute` |
| `ENCJSON_KEYS_REQUESTS_RATE_LIMIT_PER_MINUTE` | `--keys-requests-rate-limit-per-minute` |
| `ENCJSON_KEYS_UI_ENABLED` | `--keys-ui-enabled` |
| `ENCJSON_KEYS_UI_ISSUER` | `--keys-ui-issuer` |
| `ENCJSON_KEYS_UI_CLIENT_ID` | `--keys-ui-client-id` |
| `ENCJSON_KEYS_UI_CLIENT_SECRET` | `--keys-ui-client-secret` |
| `ENCJSON_KEYS_UI_BASE_URL` | `--keys-ui-base-url` |
| `ENCJSON_KEYS_UI_COOKIE_SECURE` | `--keys-ui-cookie-secure` |
| `ENCJSON_KEYS_SERVER_SCOPE_REQUIRED` | `--keys-server-scope-required` |
| `ENCJSON_TENANT` | `--tenant` |
| `ENCJSON_ENV` | `--env` |
| `ENCJSON_KEYS_BOOTSTRAP_FROM_SOURCE` | `--keys-bootstrap-from-source` |
| `ENCJSON_KEYS_BOOTSTRAP_STATUS` | `--keys-bootstrap-status` |
| `ENCJSON_KEYS_BOOTSTRAP_NOTE` | `--keys-bootstrap-note` |
| `ENCJSON_KEY_SOURCE` | `--key-source` (`env|dir|remote-mtls|vault|conjur`) |
| `ENCJSON_REMOTE_KEYS_URL` | `--remote-keys-url` |
| `ENCJSON_REMOTE_TLS_CERT_FILE` | `--remote-tls-cert-file` |
| `ENCJSON_REMOTE_TLS_KEY_FILE` | `--remote-tls-key-file` |
| `ENCJSON_REMOTE_TLS_CA_FILE` | `--remote-tls-ca-file` |
| `ENCJSON_VAULT_ADDR` | `--vault-addr` |
| `ENCJSON_VAULT_PATH` | `--vault-path` |
| `ENCJSON_VAULT_TOKEN` | `--vault-token` |
| `ENCJSON_VAULT_PUBLIC_FIELD` | `--vault-public-field` |
| `ENCJSON_VAULT_PRIVATE_FIELD` | `--vault-private-field` |
| `ENCJSON_CONJUR_APPLIANCE_URL` | `--conjur-appliance-url` |
| `ENCJSON_CONJUR_ACCOUNT` | `--conjur-account` |
| `ENCJSON_CONJUR_AUTHN_LOGIN` | `--conjur-authn-login` |
| `ENCJSON_CONJUR_AUTHN_API_KEY` | `--conjur-authn-api-key` |
| `ENCJSON_CONJUR_PUBLIC_VARIABLE_ID` | `--conjur-public-variable-id` |
| `ENCJSON_CONJUR_PRIVATE_VARIABLE_ID` | `--conjur-private-variable-id` |
| `ENCJSON_CONJUR_CA_CERT_FILE` | `--conjur-ca-cert-file` |

### `encjson-keys-server` Bootstrap

Startup import (source -> validate -> encrypt -> upsert DB):

```bash
export ENCJSON_KEYS_BOOTSTRAP_FROM_SOURCE=true
export ENCJSON_KEY_SOURCE=dir
export ENCJSON_KEYDIR=/etc/encjson/keys
export ENCJSON_TENANT=tsm
export ENCJSON_ENV=test
```

Behavior:
- loads one keypair from selected source (`env|dir|remote-mtls|vault|conjur`)
- validates public/private match
- encrypts private key with `ENCRYPTION_SECRET`
- upserts into `keys` table
- ensures `tenants` row exists
- sets tags `bootstrap`, `source:<kind>`, `env:<env>`

Admin API variant (same pipeline):

`POST /api/v1/bootstrap/import`

```json
{
  "tenant": "tsm",
  "env": "test",
  "status": "active",
  "note": "manual bootstrap"
}
```

### `encjson-keys-web`

| ENV | CLI |
| --- | --- |
| `ENCJSON_KEYS_WEB_BIND` | `--bind` |
| `ENCJSON_KEYS_WEB_KEYS_SERVER` | `--keys-server` |
| `ENCJSON_KEYS_WEB_AUTH_MODE` | `--auth-mode` (`local`/`oidc`) |
| `ENCJSON_KEYS_WEB_OPEN` | `--open` |
| `ENCJSON_KEYS_WEB_OIDC_ISSUER` | `--oidc-issuer` |
| `ENCJSON_KEYS_WEB_OIDC_CLIENT_ID` | `--oidc-client-id` |
| `ENCJSON_KEYS_WEB_OIDC_CLIENT_SECRET` | `--oidc-client-secret` |
| `ENCJSON_KEYS_WEB_OIDC_REDIRECT_BASE_URL` | `--oidc-redirect-base-url` |
| `ENCJSON_KEYS_WEB_OIDC_SCOPES` | `--oidc-scopes` |
| `ENCJSON_KEYS_WEB_OIDC_ADMIN_ROLE` | `--oidc-admin-role` |
| `ENCJSON_KEYS_WEB_OIDC_SCOPED_ROLE` | `--oidc-scoped-role` |
| `ENCJSON_KEYS_WEB_OIDC_COOKIE_SECURE` | `--oidc-cookie-secure` |

Key source unification (`env`/`dir`/`remote-mtls`/`vault`/`conjur`/`cli`) is documented in `docs/KEY_SOURCES.md`.

Local admin mode (loopback only, no OIDC):

```bash
cargo run -p encjson-keys-web -- --bind 127.0.0.1:8189 --auth-mode local --open
```

OIDC mode:

```bash
cargo run -p encjson-keys-web -- \
  --bind 0.0.0.0:8189 \
  --auth-mode oidc \
  --keys-server https://encjson-keys-server.internal \
  --oidc-issuer https://sso.example.com \
  --oidc-client-id encjson-keys-web \
  --oidc-client-secret '***' \
  --oidc-redirect-base-url https://encjson-keys-web.example.com
```

Web UI (optional):

```bash
export ENCJSON_KEYS_UI_ENABLED=true
export ENCJSON_KEYS_UI_ISSUER=https://sso.example.com
export ENCJSON_KEYS_UI_CLIENT_ID=encjson-keys-ui
export ENCJSON_KEYS_UI_CLIENT_SECRET=...
export ENCJSON_KEYS_UI_BASE_URL=https://keys.example.com
export ENCJSON_KEYS_UI_COOKIE_SECURE=true
```

Optional rate limit for private key access:

```bash
export ENCJSON_KEYS_RATE_LIMIT_PER_MINUTE=60
```

Optional rate limit for key registration requests:

```bash
export ENCJSON_KEYS_REQUESTS_RATE_LIMIT_PER_MINUTE=30
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

### Register: secure private key input

For explicit key registration to keys server, prefer secure private key input.

`KEY_REF` means:

- legacy `api=2.0`: `<public_hex>`
- `api=3.0`: `<key_id>`

```bash
encjson register <KEY_REF> \
  --tenant app \
  --note "bootstrap" \
  --private-key-file /secure/path/private.key \
  --keys-url http://127.0.0.1:8080 \
  --token "$ENCJSON_ACCESS_TOKEN"
```

Alternative secure options:

- `--private-key-fd <N>`
- `--private-key-stdin`

Raw private key argument is insecure and requires explicit opt-in:

- `--private-key <HEX> --allow-insecure-cli-private-key`

### Vault login (OIDC)

```bash
encjson login --url https://sso.cloud-app.cz
encjson status
encjson logout
```

Sessions file:

- macOS: `~/Library/Application Support/encjson/sessions.json`
- Linux: `~/.config/encjson/sessions.json`
- Windows: `%APPDATA%\\encjson\\sessions.json`
- perms `0600` (Unix)

### 1. Generate key pair (`init`)

```bash
encjson init
```

Default behavior:

- `encjson init` creates a new `api=3.0` hybrid key bundle
- `encjson init --api 2.0` creates the legacy key pair explicitly

Typical `api=3.0` output:

```text
OK init
  api       : 3.0
  key_id    : 2b29881f6f08063315b232a00a0f6276e1eaac4d76a0f16a1d435093f77890f8
  algorithm : ml-kem-768+x25519
  key file  : /home/user/.local/share/encjson/2b29881f6f08063315b232a00a0f6276e1eaac4d76a0f16a1d435093f77890f8
```

Legacy `api=2.0` output (`encjson init --api 2.0`):

```text
OK init
  public key : 91c359808554f94d4a84208630f386d65a70fb9f843756953cf83a5c1b488640
  private key: 24e55b25c598d4df78387de983b455144e197e3e63239d0c1fc92f862bbd7c0c
  key file   : /home/user/.local/share/encjson/91c359808554f94d4a84208630f386d65a70fb9f843756953cf83a5c1b488640
```

By default, key material is saved to:

- `$ENCJSON_KEYDIR/<filename>` if `ENCJSON_KEYDIR` is set, or
- a **dirs-based OS data directory** otherwise:
  - macOS: `~/Library/Application Support/encjson/<filename>`
  - Linux: `~/.local/share/encjson/<filename>`
  - Windows: `%APPDATA%\\encjson\\<filename>` (or user profile fallback)

Where `<filename>` is:

- legacy `api=2.0`: `<public_hex>`
- `api=3.0`: `<key_id>`

You can override the directory:

```bash
encjson init -k /etc/encjson
```

### 1.1 Show key info for file (`info`)

Use `info` when you need to inspect which key material a secured file currently uses:

```bash
encjson info -f env.secured.json
```

Example `api=2.0` output:

```text
public_key: 5be9bd0c23a4b402d7f8549147002047359d182be8452f7fcc607ffd3387a732
private_key: e50c09e30d48486a39e976c5c7addd6d4ccb320a581806d310a12d3e75eeda7b
pair_consistent: true
```

`pair_consistent: false` means the file still uses a legacy inconsistent pair.

Example `api=3.0` output includes `_recipient_key` metadata such as:

```text
version: 3
key_id: 2b29881f6f08063315b232a00a0f6276e1eaac4d76a0f16a1d435093f77890f8
algorithm: ml-kem-768+x25519
x25519_public_hex: ...
mlkem768_public_b64: ...
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

#### Optional sidecar schema for post-decrypt transforms

If a sidecar file exists next to the decrypted file, `encjson` applies key-level transforms
after decryption and before output:

- `mtls.secured.json` -> sidecar `mtls.secured.schema.json`
- `foo.json` -> sidecar `foo.schema.json`

Minimal schema format:

```json
{
  "MTLS_*": {
    "encoding": "base64",
    "normalize_line_endings": true
  },
  "*": {
    "encoding": "plain",
    "normalize_line_endings": false
  }
}
```

Matching priority:

1. exact key (`FOO_BAR`)
2. prefix pattern (`MTLS_*`, longest prefix wins)
3. wildcard (`*`)

Supported values:

- `encoding`: `plain` | `base64`
- `normalize_line_endings`: `true` | `false`

#### Virtual assets bundles

`encjson` also supports virtual filesystem bundles stored in JSON:

- `assets.unsecured.json`
- `assets.secured.json`

Format:

```json
{
  "_public_key": "optional-for-secured-only",
  "assets": {
    "ssl/private-key.pem": "EncJson[@api=2.0:@box=...]",
    "ssl/cert.pem": "EncJson[@api=2.0:@box=...]"
  }
}
```

For unsecured bundles, values in `assets` are plain base64 strings.  
For secured bundles, values in `assets` are encrypted `EncJson[@api=2.0:...]` strings, where
the decrypted plaintext is still base64.

Available commands:

```bash
encjson assets list -f assets.secured.json
encjson assets get -f assets.secured.json --path ssl/private-key.pem > private-key.pem
encjson assets export -f assets.secured.json --out-dir ./out
encjson assets import --from-dir ./assets -o assets.unsecured.json --unsecured
encjson assets import --from-dir ./assets -o assets.secured.json --secured --public-key <HEX>
```

Notes:

- asset paths must be relative
- `..` is rejected
- export fails on existing files unless `--overwrite` is used
- for existing secured bundles, `assets import` reuses `_public_key`
- `--public-key` is required only when creating a new secured bundle

#### Render Kubernetes Secret YAML

You can decrypt + apply sidecar schema transforms and directly render Kubernetes Secret YAML:

```bash
encjson render-k8s-secret \
  -f mtls.secured.json \
  --name mtls-test-api-api \
  --namespace nac-test \
  --from-env MTLS_TEST_API_TLS_CRT=tls.crt \
  --from-env MTLS_TEST_API_TLS_KEY=tls.key \
  --from-env MTLS_TEST_API_CA_CRT=ca.crt
```

- If `--from-env` is omitted, all string keys from `environment`/`env` are included.
- Output is `Secret` manifest with `data` (base64-encoded values).
- Default secret type is `kubernetes.io/tls`.
- For `kubernetes.io/tls`, required keys are: `ca.crt`, `tls.crt`, `tls.key`.
- Optional override: `--secret-type Opaque`

Render key material secret:

- `api=2.0`: legacy `_public_key` + resolved private key
- `api=3.0`: expanded runtime env vars derived from `_recipient_key`

```bash
encjson render-k8s-pair-secret \
  -f env.secured.json \
  --name app-secrets \
  --namespace nac-test
```

Optional key names (`api=2.0` only):

```bash
encjson render-k8s-pair-secret \
  -f env.secured.json \
  --name app-secrets \
  --namespace nac-test \
  --public-key-name public-key \
  --private-key-name private-key
```

Multi-secret mode (`---` multi-doc YAML):

```bash
encjson render-k8s-secret \
  -f mtls.secured.json \
  --namespace nac-test \
  --from-env-secret MTLS_TEST_API_TLS_CRT=mtls-test-api-api/tls.crt \
  --from-env-secret MTLS_TEST_API_TLS_KEY=mtls-test-api-api/tls.key \
  --from-env-secret MTLS_TEST_API_CA_CRT=mtls-test-api-api/ca.crt \
  --from-env-secret MTLS_TEST_WEB_TLS_CRT=mtls-test-web-web/tls.crt \
  --from-env-secret MTLS_TEST_WEB_TLS_KEY=mtls-test-web-web/tls.key \
  --from-env-secret MTLS_TEST_WEB_CA_CRT=mtls-test-web-web/ca.crt
```

- `--from-env-secret` format: `ENV_KEY=secretName/secretKey`
- `--name` is optional in this mode
- Do not mix `--from-env` and `--from-env-secret`

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
- Works even if `_public_key` / `_recipient_key` is missing (treated as plain JSON).
- `Values` list shows `<empty>` or `<spaces:N>` for empty/whitespace-only values.
- Edit modal includes a hex preview so trailing spaces and non-printable bytes are visible.
- Keys: `Up/Down` select, `Shift+Up/Down` move, `e` edit, `/` filter (key/value), `a` add (`A` adds above cursor), `r` rename, `d` delete, `t` sort, `v` diff, `s` save, `q` quit.
- `s` saves without exiting (shows a small confirmation dialog).
- Diff view: `v` opens a colored diff of added/removed/changed values.

Screen-style examples:

```text
Editing env.secured.json in /path/to/project | modified 2025-02-14 10:32:11 +01:00
┌ Keys ────────────────────────────────────┐┌ Values ─────────────────────────────────┐
│ > SPRING_DATASOURCE_USERNAME             ││ > app_admin                             │
│   SPRING_DATASOURCE_PASSWORD             ││   <empty>                               │
│   KAFKA_SASL_JAAS_CONFIG                 ││   org.apache.kafka...                   │
└──────────────────────────────────────────┘└─────────────────────────────────────────┘
key: SPRING_DATASOURCE_USERNAME
Up/Down select | Shift+Up/Down move | e edit | / filter | a add | r rename | d delete | t sort | v diff | s save | q quit
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
2. If `ENCJSON_KEYS_URL` is set **and** `ENCJSON_ACCESS_TOKEN` is present, it fetches the key remotely.
3. Otherwise it looks up a file named `<filename>` in:
   - the `-k/--keydir` CLI argument (if provided), or
   - `$ENCJSON_KEYDIR` (if set), or
   - the dirs-based data directory:
     - macOS: `~/Library/Application Support/encjson`
     - Linux: `~/.local/share/encjson`
     - Windows: `%APPDATA%\\encjson`

Where `<filename>` is either:

- legacy `api=2.0`: `<public_hex>`
- `api=3.0`: `<key_id>`

If no key can be found, the command fails with a clear error.

## Windows specifics

`encjson-rs` is primarily developed and tested on Unix-like systems, but it also works on Windows (including cross-compiled binaries).

### Emoji output in `init`

On Unix-like systems, legacy `encjson init --api 2.0` historically printed some small emoji decorations:

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
2. Otherwise use OS data directory (via `dirs` crate):
   - macOS: `~/Library/Application Support/encjson`
   - Linux: `~/.local/share/encjson`
   - Windows: `%APPDATA%\\encjson` (or user profile fallback)

In practice, on a “normal” Windows 10/11 installation, the default ends up under the user’s profile directory, e.g.:

```text
C:\Users\YourName\AppData\Roaming\encjson
```

If you want complete control (for example, to share a key directory between WSL, Git Bash and native Windows binaries), set `ENCJSON_KEYDIR` explicitly on that machine.

## Building static Linux binaries (musl)

On macOS, plain:

```bash
cargo build --release --target x86_64-unknown-linux-musl
```

usually fails at the linker step, because the system `cc`/`ld` is a Darwin toolchain, not a Linux musl linker.

Recommended approach: use `cargo-zigbuild`.

Prerequisites:

```bash
brew install zig
cargo install cargo-zigbuild
```

Build examples:

```bash
cargo zigbuild --release --bin encjson --target x86_64-unknown-linux-musl
cargo zigbuild --release --bin encjson --target aarch64-unknown-linux-musl
```

The same approach also works for other binaries in this workspace, for example:

```bash
cargo zigbuild --release --bin encjson-keys-server --target x86_64-unknown-linux-musl
```

## Shell completion

`encjson` and `encjson-keys-ctl` can generate shell completion scripts.

Examples:

```bash
encjson completion zsh > ~/.zsh/completions/_encjson
encjson-keys-ctl completion zsh > ~/.zsh/completions/_encjson-keys-ctl
```

Then make sure the directory is on `fpath` in `~/.zshrc`, for example:

```bash
fpath=(~/.zsh/completions $fpath)
autoload -Uz compinit
compinit
```

Supported shells:

- `bash`
- `zsh`
- `fish`
- `powershell`
- `elvish`

### Migration from legacy `~/.encjson`

On startup, if `~/.encjson` exists and the new dirs-based directory does not,
keys are migrated automatically (only files with hex names).

Note: sessions and key files intentionally use different OS-standard locations:

- sessions: config directory (`sessions.json`)
- key files: data directory (`<public_hex>` for `api=2.0`, `<key_id>` for `api=3.0`)

## Migration from the Crystal version

The original Crystal implementation used `@api=1.0` with a pinned
Monocypher fork. `encjson-rs` now implements that format natively in Rust, so
the old Crystal binary is no longer required just to read existing files.
The Rust tool also supports the later API 2.0 format, while new files default
to API 3.0.

Recommended migration path:

1. Verify that the matching legacy private key is available to `encjson-rs`.
2. Migrate directly to the current format:
   ```bash
   encjson migrate-format -f env.secured.json --to 3.0 -w
   ```
3. Commit the newly encrypted file and deploy the matching API 3.0 key bundle.

The Crystal binary can remain installed during a gradual rollout, but it is
not needed by the Rust CLI for API 1.0 decryption or migration.

## Relationship to the Crystal project

- Original Crystal implementation: <https://github.com/martinmares/encjson>
- This Rust rewrite (`encjson-rs`) aims to be:
  - behaviour-compatible at the JSON / CLI level,
  - but with a clearly distinct and fully Rust-native crypto stack.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Author

Martin Mareš
