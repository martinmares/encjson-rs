# Komponenty

## encjson (binárka)

Utilita, která primárně generuje klíče, typické flow:

1. encjson init (vygeneruje nový klíč)

Takto vypadá soubor s klíčem:

```bash
$ cat ~/.encjson/cfd8d6f834b3f8b0ee2e3963ba752229ad0e8ceaf94161e910b538a08e04916c
5ab8379152e51ef5150bd8546352e75e723947ae428d70bab1a03e2c19cd9b32
```

2. klíč pak použiju v tomto JSON dokumentu ("standardizovaný" formát), typicky se soubor jmenuje podle konvence "env.secured.json"

Tohle je obsah "encrypted":

```json
{
  "_public_key": "cfd8d6f834b3f8b0ee2e3963ba752229ad0e8ceaf94161e910b538a08e04916c",
  "environment": {
    "TSM_DB_USER": "EncJson[@api=2.0:@box=zAhjr7pXxcOgefPLeDhA3U7IlA0aih/7EB6MQiol4Chmq01WX2nXXWynW9CgXPjkJX1l]",
    "TSM_DB_PASSWORD": "EncJson[@api=2.0:@box=qbrO9xa2ovLcvM0DC36AYayEugv3Nr/APfwZ1x20sGWUaf6ATjVEkjuDeny9fcOwLq0BdGXR]"
  }
}
```

A tohle je obsah "decrypted":

```json
{
  "_public_key": "cfd8d6f834b3f8b0ee2e3963ba752229ad0e8ceaf94161e910b538a08e04916c",
  "environment": {
    "TSM_DB_USER": "secure_name",
    "TSM_DB_PASSWORD": "s#cur@_p&ss123"
  }
}
```

Tedy klíče jsou v adresáři ~/.encjson/, jednoduché, prosté, žádná komplikace.
Mám ze jediný problém, že netuším který klíč kam patří, ale odpověď je možná jednoduchá: Vůbec mě to vlastně nezajímá. Když používám utilitu "encjson", nad nějakým souborem "env.secured.json", tak mě vlastně nezajímá nic jiného, než jestli mám právo udělat encrypt/decrypt, a nic víc.

Zápasil jsem totiž s myšlenkou, že klíče budou existovat v nějaké lokální SQLite databázi, a tam budu mít "tagy", "tenanty" a prostě nějaké logické rozdělení klíčů. Ale opět zde padne otázka: Potřebuji to vůbec?

Navruji následující trochu "nekompatibilní úpravu", která se ale vyplatí do budoucna. Dnes ukládám klíče do ~/.encjson/, ale to je zcela špatně. Použil bych crate "dirs" a udělal to správně specifikocky podle OS. Tedy je nutná "migrace" existujících klíčů a to tak, že:
- pokud jsou splněny tyhle dvě podmínky:
  - existuje adresář ~/.encjson/ s klíči
  - ALE neexistuje "správný" nový adresář podle konvence
    - -> tak ten "správný" adresář vytvoř -> a překopíruj tam všechny klíče (soubory kde název je dlouhý XXX znaků)

Tím bychom měli zajistit hladký přechod na "dirs".

## encjson-vault-server

Je to server, který spravuje výše zmíněné klíče, ale ne jen jako plochá struktura public/private, ale měl by mít i nějakou další přidanou hodnotu, tedy v základu minimálně tohle:
- dělení podle tenantů, typicky zákazníci:
  - O2
  - CETIN
  - CEZ
  - jiná další firma
- dělení podle skupin lidí:
  - devops
  - admin
  - reader/writer (asi nemá smysl, protože jakmile mám klíč u sebe, můžu ho technicky použít jak na čtení, tak na zápis, ALE! dává to smysl z pohledu encjson-vault-server, tedy uživatel sy může provést "sync" k sobě, ale nemůže upravit tagy v "remote", takže možná ano i tahle role dává smysl)

## encjson-ctl

Tohle je utilita plánovaná čistě pro adminy a devopsáky. Tzn. v TUI se autorizuju na simple-idm-server a podle "groups" můžu dělat různé věci, edivat, přiřazovat tagy, měnit tenenty atd.

Přihlášení bych udělal identicky jak to má utilita "simple-idm-ctl" z tohoto projektu: /Users/mares/Development/Src/Rust/simple-idm-server/

Pro TUI bych rozhodně doporučil (stejně jako "simple-idm-ctl") požít tyto crates:
- ratatui
- crossterm
- tui-input

Data + session a další stavové informace bych ukládal do správných adresářů k tomu určených, to zajistí crate "dirs" (opět podobně jako "simple-idm-ctl")

## simple-idm-server

Tohle je OAUTH2/IDM/OIDC provider, detaily si prosím pročti zde: /Users/mares/Development/Src/Rust/simple-idm-server/README.md

Jsou různé možnosti autorizace, včetně jednoduché oauth2-proxy, která umí poslat přes nginx jen HTTP autorizační hlavičky. Ale tady bych preferoval udělat to čistě přímo web flow auth.

# High level Architetura

```
┌───────────────────────┐        ┌─────────────────────────┐
│                       │        │       encjson-ctl       │
│ encjson-vault-server  ◀────────│ ADMIN tool (controller) │
│                       │        │                         │
└───────────────────────┘        └─────────────────────────┘
            ▲                                 ▲
            │                                 │
            │                                 └────groups získává z IDM───────┐
            │                                                                 │
            │                                                                 ▼
            │                                                    ┌────────────────────────┐
            │                                                    │                        │
   snychronizace mezi                                            │   simple-idm-server    │
   "local" a "remote"                                            │ (OATH2/OIDC provider)  │
            │                                                    │                        │
            │                                                    └────────────────────────┘
            │
            │
            │
            │
            │
            ▼
┌───────────────────────┐
│        encjson        │
│  UTILITA pro správu   │
│    lokálních klíčů    │
└───────────────────────┘
```


# Další nutné předpoklady

Prověřit, jak přesně je udělaný command "encjson edit", potřebuji aby se choval podobně jako "simple-idm-ctl", co se týče použitého TUI framworku, funkčních kláves, dialogů atd., nestačí jen potvrdit, že se používají stejné "crates":
- ratatui
- crossterm
- tui-input

Je nutné prověřit odlišnosti chování TUI, chci to mít jednotné.
Zatím se zdá, že je vše v pořádku.
