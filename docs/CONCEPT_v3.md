# CONCEPT v3 (draft)

## Komponenty

### encjson (bin)
- Lokální práce se soubory `env.secured.json` (encrypt/decrypt).
- Lokální úložiště klíčů přes `dirs` (OS‑specifické).
- Bez initContainer scénáře.

#### Migrace klíčů na `dirs`
- Pokud existuje starý `~/.encjson/` a nový adresář neexistuje, vytvořit nový a překopírovat klíče
  (jen soubory s hex názvy).

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

#### Session storage
- Použít `dirs::config_dir()`.
- macOS: `~/Library/Application Support/encjson-ctl/sessions.json`
- Linux: `~/.config/encjson-ctl/sessions.json`
- Perms `0600` na Unix (stejně jako `simple-idm-ctl`).

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

## UX checklist (TUI)
- Navigace: `↑/↓` pohyb, `PgUp/PgDn` skoky.
- Dialogy: `Enter` potvrdit, `Esc` zavřít bez uložení.
- Filtr: `/` otevře, `Enter` použije, `Esc` zavře bez změny.
- Status + Help: 2 řádky dole, vždy viditelné.
- Layout: seznam vlevo, detail vpravo, scrollování listu.

## Status
- [x] TUI kontrakt sladit s `encjson edit` (ratatui/crossterm/tui-input).
- [x] Implementovat nový key dir přes `dirs` + migrace z `~/.encjson`.
- [ ] Základní skeleton `encjson-ctl` (ratatui + crossterm).
