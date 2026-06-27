# EncJson Keys Server Scope

This document captures the current `encjson-keys-server` inventory and the
cleanup direction.

The server scope is:

> Manage and safeguard EncJson keys. Do not become a generic Vault.

## Core Domain

`encjson-keys-server` owns:

- EncJson key registration requests
- admin approval/rejection workflow
- tenant assignment and tenant-scoped access
- encrypted storage of private key material
- key pull/sync API for authorized clients
- API 2.0 legacy key compatibility
- API 3.0 hybrid key bundle compatibility
- audit for sensitive key operations
- maintenance operations required for key storage safety

It does not own:

- arbitrary application secrets
- generic key/value storage
- dynamic credentials
- secret leases
- runtime configuration rendering
- Kubernetes manifest rendering

## Current API Inventory

Core API:

- `GET /api/v1/me`
- `GET /api/v1/keys`
- `GET /api/v1/keys/{public_hex}`
- `PATCH /api/v1/keys/{public_hex}`
- `GET /api/v1/keys/{public_hex}/private`
- `GET /api/v1/keys/{key_id}/bundle`
- `GET /api/v1/requests`
- `POST /api/v1/requests`
- `PATCH /api/v1/requests/{id}`
- `POST /api/v1/requests/{id}/approve`
- `POST /api/v1/requests/{id}/reject`
- `GET /api/v1/tenants`
- `POST /api/v1/tenants`
- `PATCH /api/v1/tenants/{name}`
- `DELETE /api/v1/tenants/{name}`
- `GET /api/v1/statuses`

Maintenance API:

- `POST /api/v1/keys/reencrypt`
- `POST /api/v1/bootstrap/import`

Built-in server UI:

- `/ui`
- `/ui/login`
- `/ui/callback`
- `/ui/logout`
- `/ui/keys`
- `/ui/requests`
- `/ui/tenants`

The built-in UI is useful for local inspection, but it should not drive the
server architecture. Preferred admin surfaces are:

- `encjson-keys-ctl`
- `encjson-keys-web`

## Current Data Model

Tables:

- `tenants`
- `keys`
- `requests`
- `key_access_log`

Current key identity fields:

- API 2.0 legacy:
  - `public_hex`
  - `private_hex`
- API 3.0:
  - `key_id`
  - `bundle_version`
  - `algorithm`
  - `public_bundle`
  - `private_bundle`

Current request statuses:

- `pending`
- `approved`
- `rejected`

Current key statuses:

- `active`
- `revoked`

## Problems Found

### 1. Server Binary Does Too Much

`crates/encjson-keys-server/src/main.rs` used to contain CLI/env parsing,
DB startup, auth/JWT/mTLS/SPIFFE policy, REST handlers, built-in UI handlers,
OIDC UI login, crypto storage helpers, and tests.

The first split is now done. `main.rs` is kept as the startup/router wiring
surface, while domain areas live in focused modules.

### 2. Built-In UI Duplicates Admin Surfaces

There are three admin/control surfaces:

- built-in `/ui` inside `encjson-keys-server`
- `encjson-keys-ctl`
- `encjson-keys-web`

The built-in UI also has legacy-only paths in places, especially around request
creation and approval.

Decision needed:

- keep built-in `/ui` as minimal local/debug UI only
- or remove/disable it and use `encjson-keys-web` as the web UI

### 3. Legacy And API 3.0 Paths Are Mixed

The API supports both `private_hex` and API 3.0 bundles. This is required for
backward compatibility, but handlers should make the distinction explicit.

Desired naming:

- legacy key path: API 2.0 / `public_hex`
- bundle key path: API 3.0 / `key_id`

### 4. Error Responses Are Not Consistently JSON

Many handlers still return plain text errors.

Target response shape:

```json
{
  "error": "forbidden",
  "message": "admin required"
}
```

This should apply to all REST API endpoints. UI handlers may keep HTML
redirect/error behavior.

### 5. Audit Is Too Narrow

`key_access_log` currently captures private key access. The server should also
audit:

- request create
- request update
- approve
- reject
- key metadata edit
- tenant create/rename/delete
- reencrypt
- bootstrap import
- future rotation actions

### 6. Rotation Model Is Missing

Rotation is currently handled mostly by file-level CLI operations. The server
does not yet model rotation as a first-class workflow.

Needed later:

- new key registration as rotation candidate
- explicit old/new key relationship
- old key deprecation
- disable after grace period
- audit trail linking all steps

## Cleanup Plan

### Phase 1: Stabilize Surface

- [x] define architecture boundary in `docs/ARCHITECTURE.md`
- [x] inventory server API and scope in this document
- [ ] document REST API response conventions
- [ ] document key/request lifecycle states
- [ ] decide whether built-in `/ui` remains supported

### Phase 2: Split Server Code

Refactor `crates/encjson-keys-server/src/main.rs` into modules:

- [x] `args.rs`
- [x] `state.rs`
- [x] `auth.rs`
- [x] `crypto_store.rs`
- [x] `models.rs`
- [x] `rate_limit.rs`
- [x] `key_validation.rs`
- [x] `handlers_keys.rs`
- [x] `handlers_requests.rs`
- [x] `handlers_tenants.rs`
- [x] `maintenance.rs`
- [x] `ui_handlers.rs`
- [x] `ui_html.rs`
- [x] `ui_state.rs`

Acceptance criteria:

- [x] route handlers remain behaviorally unchanged
- [x] `cargo test -p encjson-keys-server` passes
- [x] `cargo clippy -p encjson-keys-server --all-targets` passes
- [x] `cargo test --workspace` passes
- [x] `cargo clippy --workspace --all-targets --all-features` passes

### Phase 3: Normalize REST Errors

- [x] introduce `ApiError`
- [x] return JSON errors for REST endpoints
- [x] keep UI redirects/errors separate from REST errors
- [x] add JSON error contract tests
- [ ] update CLI clients to display better messages

### Phase 4: Strengthen Audit

- [ ] add audit helper
- [ ] log request create/update/approve/reject
- [ ] log key metadata edits
- [ ] log tenant changes
- [ ] log bootstrap and reencrypt

### Phase 5: Rotation Workflow

- [ ] design rotation API
- [ ] design CLI workflow
- [ ] add lifecycle states if needed
- [ ] implement safe old-key deprecation
- [ ] document CI/CD scenario

## Immediate Next Step

The next coding step should finish Phase 3 by updating CLI clients to display
the normalized REST error body.
