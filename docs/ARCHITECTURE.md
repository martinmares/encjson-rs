# EncJson Architecture

This document is the main architecture anchor for the EncJson based deployment
and configuration workflow.

The core rule is:

> Configuration and encrypted values live in Git. EncJson keys do not.

The system is intentionally not a generic Vault replacement. It is a GitOps
oriented configuration and key-management workflow built around encrypted JSON
files.

## Source Of Truth

Git is the source of truth for:

- deployment model inputs
- rendered Kubernetes manifests
- application configuration files
- `env.secured.json`
- `env.unsecured.json`
- encrypted runtime asset bundles, when used

The EncJson keys required to decrypt those files are stored outside Git.

## Responsibility Boundaries

### `encjson-rs`

`encjson-rs` is the cryptographic file utility.

It owns:

- encryption and decryption of EncJson files
- API 2.0 legacy format support
- API 3.0 recipient bundle format support
- local key storage
- `login` / `logout` session handling
- `sync` of required keys from the keys server
- `register` of local keys into the approval workflow
- local file-level key rotation

It must stay usable as a standalone CLI tool.

### `encjson-keys-server`

`encjson-keys-server` is the server for management and safekeeping of EncJson
keys.

It owns:

- key registration requests
- admin approval/rejection workflow
- tenant assignment and access checks
- private key / private bundle storage
- key pull/sync API for authorized clients
- audit of register, approve, reject, pull, sync, rotate and disable actions
- API 2.0 legacy key compatibility
- API 3.0 key bundle compatibility

It is not a general-purpose key-value secret store.

It must not grow features such as:

- arbitrary `GET /secret/foo/bar` style runtime secrets
- dynamic database credentials
- secret leasing
- generic versioned KV storage
- application-level secret values unrelated to EncJson files

If those are needed later, they belong in a separate project.

### `simple-config-server`

`simple-config-server` is the Spring Cloud Config compatible delivery layer.

It owns:

- serving Spring-compatible configuration responses
- serving raw runtime assets
- text templating using `{{ ENV_NAME }}` style placeholders
- environment-specific config delivery

It consumes already resolved environment variables from `.env` files, process
environment, or another prepared input.

It does not decrypt `env.secured.json`.

Correct flow:

1. `encjson-rs` or a bootstrap/pipeline step resolves encrypted env data.
2. The resolved values are made available as `.env` or process environment.
3. `simple-config-server` uses those values for templating.

### `simple-secrets-server`

`simple-secrets-server` is currently considered archived/reference work.

The original goal was env-source management over `env.secured.json` and
`env.unsecured.json`, but in the current architecture this creates an unclear
middle layer between `encjson-rs`, `encjson-keys-server`, and
`simple-config-server`.

Do not build new architecture around it unless the scope is redefined.

### `kube-build-app`

`kube-build-app` renders Kubernetes manifests from deployment model inputs.

It may call `encjson-rs` for backwards compatibility and local workflows, but
it should not own key management or keyserver logic.

Long term, it should describe the bootstrap/runtime flow rather than being the
main secret resolver.

### `kube-deploy-sync`

`kube-deploy-sync` is the GitOps/runtime state dashboard.

It owns:

- comparing rendered manifests with live cluster state
- sync metadata inspection
- operational planning
- deployment/runtime visibility

It must not decrypt secrets, manage EncJson keys, or talk directly to the
EncJson keys server.

## Runtime Model

Applications should not need to call a Vault-like API at runtime to obtain
secret values.

Preferred runtime model:

1. Git contains encrypted configuration.
2. Bootstrap, CI/CD, or local tooling resolves required EncJson keys.
3. `encjson-rs` decrypts the required values.
4. Runtime config is prepared as files or environment variables.
5. Applications start with already prepared config.

This keeps runtime dependencies small and makes configuration changes auditable
through Git.

## Rotation Model

Key rotation is the main missing workflow.

A complete rotation crosses several layers:

1. Generate a new EncJson key bundle.
2. Register the new key in `encjson-keys-server`.
3. Approve and assign it to the correct tenant.
4. Re-encrypt `env.secured.json` with the new recipient.
5. Commit and push the changed encrypted file to Git.
6. Let downstream config/render/deploy workflows consume the new Git state.
7. Verify that consumers can decrypt with the new key.
8. Mark the old key as deprecated.
9. Disable or remove the old key only after a safe grace period.

CLI automation is required for CI/CD. UI/TUI support is required for admin and
support workflows.

## Required Tooling Capabilities

Every important operation should have both an interactive/admin path and an
automation-friendly CLI path.

Required capabilities:

- list local keys
- list remote keys
- register local keys
- approve/reject requests
- sync keys required by an `env.secured.json`
- validate an EncJson file
- rotate a file to a new key
- register a rotated key
- audit key pulls and approvals
- mark old keys deprecated/disabled

## Non-Goals

The current architecture does not aim to provide:

- a generic Vault clone
- runtime secret leasing
- dynamic credentials
- a central database of arbitrary app secret values
- application runtime dependency on a secret server

Those features may be useful in a different product, but they are outside this
architecture.

## Practical Direction

Near-term work should focus on:

1. Stabilizing `encjson-keys-server`.
2. Stabilizing register/approve/sync workflows.
3. Implementing key rotation workflow.
4. Keeping `simple-config-server` focused on config delivery and templating.
5. Keeping `kube-deploy-sync` independent from secrets and key management.

