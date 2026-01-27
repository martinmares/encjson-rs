# CONCEPT v3 (draft)

## Komponenty

### encjson (bin)
- Lokální práce se soubory `env.secured.json` (encrypt/decrypt).
- Lokální úložiště klíčů přes `dirs` (OS‑specifické).
- Bez initContainer scénáře.
- OIDC login/logout (session přes `dirs::config_dir()`).

#### Migrace klíčů na `dirs`
- Pokud existuje starý `~/.encjson/` a nový adresář neexistuje, vytvořit nový a překopírovat klíče
  (jen soubory s hex názvy).

#### OAuth2/OIDC howto (encjson)
- Login:
  - `encjson login --url https://sso.cloud-app.cz`
- Sessions:
  - `encjson sessions ls`
  - `encjson sessions use <name>`
- Status:
  - `encjson status`
- Logout:
  - `encjson logout`
  - `encjson logout --all`
- Sessions file:
  - macOS: `~/Library/Application Support/encjson/sessions.json`
  - Linux: `~/.config/encjson/sessions.json`
  - perms `0600` (Unix)

### encjson-vault-server
- Jediný zdroj pravdy pro klíče.
- Role jsou **serverové**: `admin` vs `scoped` (tenant‑scoped).
- Základní metadata: `tenant`, `note`, audit (`created_at`, `updated_at`, `deleted_at`), soft delete.
- Bez `public/default` tenant (zrušeno).
- Tags až v Phase 2.

### simple-secrets-server
- Server‑side decryption pro `encjson`:
  - čte secured env z Gitu,
  - načte klíče z vaultu,
  - dešifruje a poskytuje export (`dot-env/json/yaml`).

### simple-config-server
- Čistý config server (Spring Cloud kompatibilní).
- `apply-env` dělá z env mapy (např. z simple-secrets-server).
- `encjson` neřeší.

### simple-artifacts-server
- Čistý storage (Maven + generic).
- `encjson` neřeší.

### encjson-ctl (TUI)
- Admin/DevOps TUI pro vault.
- Přihlášení přes `simple-idm-server` (OIDC).
- TUI stack shodný s `simple-idm-ctl`:
  - `ratatui`
  - `crossterm`
  - `tui-input`
- Mock data přes JSON soubor (env `ENCJSON_CTL_DATA`).

#### OAuth2/OIDC howto (encjson-ctl)
- Login:
  - `encjson-ctl login --url https://sso.cloud-app.cz`
  - CLI spustí callback server (`http://127.0.0.1:8181/callback`) a otevře browser.
- Remote data:
  - `ENCJSON_VAULT_URL=https://vault.example.com`
  - `encjson-ctl tui`
- Sessions:
  - `encjson-ctl sessions ls`
  - `encjson-ctl sessions use <name>`
- Status:
  - `encjson-ctl status`
- Logout:
  - `encjson-ctl logout`
  - `encjson-ctl logout --all`
- Sessions file:
  - macOS: `~/Library/Application Support/encjson-ctl/sessions.json`
  - Linux: `~/.config/encjson-ctl/sessions.json`
  - perms `0600` (Unix)

#### Session storage
- Použít `dirs::config_dir()`.
- macOS: `~/Library/Application Support/encjson-ctl/sessions.json`
- Linux: `~/.config/encjson-ctl/sessions.json`
- Perms `0600` na Unix (stejně jako `simple-idm-ctl`).
- encjson používá stejné schéma adresářů a práv.

## High level schéma

```
                          ┌──────────────────────────┐
                          │     simple-idm-server    │
                          │       (OIDC provider)    │
                          └─────────────┬────────────┘
                                        │
                                        │ OIDC (login + groups)
                                        │
                             ┌──────────▼──────────┐
                             │     encjson-ctl     │
                             │   admin/devops TUI  │
                             └──────────┬──────────┘
                                        │
                                        │ admin/scoped API
                                        ▼
┌───────────────────────┐     ┌───────────────────────┐
│    encjson (bin)      │     │  encjson-vault-server │
│  encrypt/decrypt file │     │   keys + metadata     │
└──────────┬────────────┘     └──────────┬────────────┘
           │                             │
           │ local keys                  │ key lookup
           │                             │
           ▼                             ▼
┌───────────────────────────┐   ┌───────────────────────────┐
│   simple-secrets-server   │   │   simple-config-server    │
│  decrypt secured envs     │   │  config + apply-env       │
└──────────────┬────────────┘   └──────────────┬────────────┘
               │                              │
               │ export env                   │ config JSON
               ▼                              ▼
                      ┌───────────────────────┐
                      │ simple-artifacts-server │
                      │  binaries / assets     │
                      └───────────────────────┘
```

## Flow v praxi (jednoduchý provozní model)
1) `encjson-vault-server` drží klíče.
2) `simple-secrets-server` si bere klíče z vaultu a dešifruje secured envs.
3) `simple-config-server` si bere env mapu ze secrets serveru (nebo z exportu).
4) `simple-artifacts-server` hostuje build artefakty.

## encjson register (klientský flow)

### CLI varianty
- **A) Register all new (interaktivně)**  
  `encjson register`
  - Diff: lokální `public_hex` vs. remote `public_hex` (approved + pending) v tenant scope uživatele.
  - Nové klíče se nabídnou v TUI.
  - U každého: vybrat `tenant`, zadat `note`, volitelně `tags`.
- **B) Register explicit (automatizace/CI)**  
  `encjson register <public_hex> --tenant <tenant> --note <note> [--tag <tag>...]`

### Request model (staging)
- KLIENT‑CLI nikdy nepíše přímo do tenantu.
- Vytvoří **request**:
  - `public_hex`
  - `private_hex`
  - `tenant` (návrh)
  - `note` (povinné)
  - `tags` (návrh)
  - `requested_by`, `requested_at`
- Admin request **schválí**/**zamítne**; může upravit tenant/tags/note.

### Potenciální problémy (řešení)
- **Duplicitní registrace**: server vrátí “already registered”.
- **Pending vs Approved**: `encjson sync` ignoruje pending.
- **Tag governance**: tagy z requestu jsou návrh; admin je autorita.
- **Tenant návrh**: klient nabízí jen dostupné tenanty; admin může změnit.

### API návrh (requests)
- `POST /v1/requests`  
  Body:
  ```json
  {"public_hex":"...","private_hex":"...","tenant":"cetin","note":"...","tags":["..."]}
  ```
- `GET /v1/requests?status=pending`
- `POST /v1/requests/{id}/approve`  
  Body:
  ```json
  {"tenant":"cetin","status":"active","note":"...","tags":["..."]}
  ```
- `POST /v1/requests/{id}/reject`  
  Body:
  ```json
  {"reason":"..."}
  ```

## encjson sync (klientský flow)

### CLI varianty
- **Sync z env souboru**  
  `encjson sync -f env.secured.json`  
  - přečte `_public_key` a stáhne jen tento klíč.
- **Sync explicitního klíče**  
  `encjson sync --key <public_hex>`
- **Sync všech dostupných klíčů**  
  `encjson sync`  
  - stáhne všechny klíče, na které má user právo (tenant scope).

## UX checklist (TUI)
- Navigace: `↑/↓` pohyb, `PgUp/PgDn` skoky.
- Dialogy: `Enter` potvrdit, `Esc` zavřít bez uložení.
- Filtr: `/` otevře, `Enter` použije, `Esc` zavře bez změny.
- Status + Help: 2 řádky dole, vždy viditelné.
- Layout: seznam vlevo, detail vpravo, scrollování listu.

## Status
- [x] TUI kontrakt sladit s `encjson edit` (ratatui/crossterm/tui-input).
- [x] Implementovat nový key dir přes `dirs` + migrace z `~/.encjson`.
- [x] Základní skeleton `encjson-ctl` (ratatui + crossterm).
- [x] TUI: list + detail + filter + confirm exit (bez API).
- [x] Mock data source pro `encjson-ctl` (JSON přes `ENCJSON_CTL_DATA`).
- [x] Mock persistence: `encjson-ctl` ukládá změny zpět do JSON (`ENCJSON_CTL_DATA`).
- [x] encjson-ctl login/logout/sessions (OIDC flow jako simple-idm-ctl).
- [x] encjson login/logout/sessions (stejné OIDC flow + vlastní session file).
- [x] encjson-ctl remote list/detail + tenants/statuses + key update (read/write).
- [x] encjson register (diff + explicit) → /v1/requests.
