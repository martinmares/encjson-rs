# CONCEPT v2 (draft)

## Komponenty

### encjson (bin)
- Lokální práce se soubory `env.secured.json` (encrypt/decrypt).
- Lokální úložiště klíčů přes `dirs` (OS‑specifické).
- **Volitelně** minimální `encjson sync -f env.secured.json` (jen pokud bude potřeba).

#### Migrace klíčů na `dirs`
- Pokud existuje starý `~/.encjson/` a nový adresář neexistuje, vytvořit nový a překopírovat klíče
  (jen soubory s hex názvy).

### encjson-vault-server
- Server pro správu klíčů + metadata.
- Základní metadata: `tenant`, `note`, audit (`created_at`, `updated_at`, `deleted_at`), soft delete.
- Role jsou **serverové**: `admin` vs `scoped` (tenant‑scoped).
- **Bez** `public/default` tenant (zrušeno).
- Tags až v Phase 2.

### encjson-ctl (TUI)
- Admin/DevOps TUI pro vault.
- Přihlášení přes `simple-idm-server` (OIDC).
- Použít stejný TUI stack jako `simple-idm-ctl`:
  - `ratatui`
  - `crossterm`
  - `tui-input`

#### Session storage
- Použít `dirs::config_dir()`.
- macOS: `~/Library/Application Support/encjson-ctl/sessions.json`
- Linux: `~/.config/encjson-ctl/sessions.json`
- Perms `0600` na Unix (stejně jako `simple-idm-ctl`).

### simple-idm-server
- OAuth2/OIDC provider, viz `/Users/mares/Development/Src/Rust/simple-idm-server/README.md`.

## High level architektura

```
┌───────────────────────┐        ┌─────────────────────────┐
│                       │        │       encjson-ctl       │
│ encjson-vault-server  ◀────────│ ADMIN tool (controller) │
│                       │        │                         │
└───────────────────────┘        └─────────────────────────┘
            ▲                                 ▲
            │                                 └── groups z IDM ──┐
            │                                                   │
            ▼                                                   ▼
┌───────────────────────┐                          ┌────────────────────────┐
│        encjson        │                          │   simple-idm-server    │
│  UTILITA pro lokální  │                          │     (OIDC provider)    │
│   klíče + edit file   │                          │                        │
└───────────────────────┘                          └────────────────────────┘
```

## encjson sync (minimální scénář)

### Cíl
Stáhnout privátní klíč pro `_public_key` z `env.secured.json` do lokálního key store.

### Potřebné informace
- `ENCJSON_VAULT_URL` (vault endpoint)
- `IDM_TOKEN_URL` (OIDC token endpoint)
- `ENCJSON_CLIENT_ID`
- `ENCJSON_CLIENT_SECRET`
- `ENCJSON_TENANT` (pokud token nemá jediný tenant)
- `ENCJSON_KEY_DIR` (kam uložit klíče)

### Flow (M2M / initContainer)
1. `encjson sync -f env.secured.json`
2. Načte `_public_key`.
3. Získá OAuth2 access token (`client_credentials`).
4. Zavolá vault: GET private key pro `_public_key` + `tenant`.
5. Uloží privátní klíč lokálně.

### Volitelně (interactive / device flow)
- `encjson sync -f env.secured.json --device`
- Uživatel provede login přes browser a CLI stáhne token + klíč.

## UX checklist (TUI)

- Navigace: `↑/↓` pohyb, `PgUp/PgDn` skoky.
- Dialogy: `Enter` potvrdit, `Esc` zavřít bez uložení.
- Filtr: `/` otevře, `Enter` použije, `Esc` zavře bez změny.
- Status + Help: 2 řádky dole, vždy viditelné.
- Layout: seznam vlevo, detail vpravo, scrollování listu.
