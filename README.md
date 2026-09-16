---
title: Paper
emoji: 📝
colorFrom: purple
colorTo: pink
sdk: docker
pinned: false
---

# Paper ✨

A minimal, secure notepad for temporary notes. Zero tracking, zero accounts — just encrypted notes.

## Features

- 🔐 **Client-side encryption** — Your password never leaves your browser
- 🔗 **Private links** — Each note lives at a random, unguessable URL
- 🗑️ **Auto-delete** — Notes removed after 2 days without being opened or edited
- 🌐 **Access anywhere** — Keep the link + password, open it from any device
- 🚫 **No tracking** — No cookies, no analytics, no accounts, no third-party requests

## How It Works

```
┌─────────────────┐         ┌─────────────────┐
│     Browser     │         │     Server      │
├─────────────────┤         ├─────────────────┤
│                 │         │                 │
│  Random link ───┼────────►│  Note ID (capability) │
│  (# 128-bit id) │         │        │        │
│        │        │         │        ▼        │
│  Password ──────┼─► PBKDF2◄─────── Salt     │
│        │        │         │        │        │
│        ▼        │         │        ▼        │
│  AES-GCM        │         │  Store/Load     │
│  Encrypt/Decrypt│◄───────►│  Encrypted Blob │
└─────────────────┘         └─────────────────┘
```

**Key points:**
- Password + salt → PBKDF2 (512 bits) → AES-256-GCM key + 256-bit write token (client only)
- Random 128-bit link (in the URL) identifies the note — never derived from the password
- The salt is chosen by the browser and stored with the note on its first save
- Server stores only: encrypted content, the salt, and a SHA-256 digest of the write token
- Server never sees: password, encryption key, or decrypted content
- The link lets you fetch the ciphertext; overwriting the note also requires the write token

## Architecture

```
Paper/
├── index.html      # Single-page app (HTML + CSS)
├── app.js          # Frontend logic (external JS enables strict CSP)
├── fonts/          # Self-hosted Plus Jakarta Sans (woff2, SIL OFL 1.1)
├── main.go         # Go backend (single binary, stdlib only)
├── deploy.sh       # VPS deploy (PM2 + Cloudflare Tunnel + rate limiting)
├── cloudflare/
│   └── rate-limit.py  # Edge rate limiting rules (idempotent, Zone.WAF API)
├── Dockerfile      # Multi-stage container build
└── go.mod
```

### Frontend (`index.html` + `app.js`)
- Single HTML file (styles) with the application logic in an external `app.js`
- Crypto API for AES-GCM encryption and PBKDF2 key derivation
- Auto-save with debounce (1.5s after typing stops); edit-safe two-flag save
  (an edit during an active save schedules another save, so no keystroke is lost)
- Chunked base64 conversion (no `Function.apply()` stack blow-up on large notes)
- Two tabs/devices on one note: each save names the version it was based on; if another
  save landed first the editor pauses autosave and offers **Load latest** or **Overwrite with
  mine**. An idle tab picks up newer versions when it regains focus.
- Dark theme with colorful accents; fonts are self-hosted, so the page makes no third-party requests

### Backend (`main.go`)
- Go HTTP server, stdlib only, compiles to a single static binary
- Two endpoints: `/api/load` and `/api/save`
  - `load` is read-only: an unknown link returns an empty note and creates nothing on disk
  - `save` creates the note on first write (salt + token digest + content) and afterwards
    requires the matching write token (`403` otherwise), compared in constant time
  - `save` also requires `base` = the version the edit started from (`load` and `save` both
    return the current `version`); a stale base gets `409` instead of silently overwriting
- File-based storage (configurable via `DATA_DIR`)
- Auto-cleanup: notes not opened or edited for 2 days (a load refreshes the note's mtime), or
  the oldest-active notes when storage exceeds the limit,
  run at startup and on a timer (`CLEANUP_INTERVAL_MINUTES`), never on the request path
- Write budget: saves are rejected (`507`) while storage is at the `MAX_TOTAL_SIZE_MB` cap, so a full disk can't be caused by writes between cleanups. Orphaned salt/token files and stale crash temps are GC'd on every cleanup.
- Strict security headers on every response: CSP (`script-src 'self'` — the
  frontend ships as a separate `app.js`), `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer`, `Permissions-Policy`, `X-Frame-Options: DENY`,
  HSTS. Note IDs never appear in logs (they're bearer capabilities).
- CORS is off by default (same-origin app); set `CORS_ORIGINS` to opt in.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `LISTEN_ADDR` | `0.0.0.0` | Bind address |
| `LISTEN_PORT` | `7860` | Bind port |
| `DATA_DIR` | `/var/lib/paper` (deploy) / `/tmp` (local run) | Storage directory |
| `AGE_LIMIT_DAYS` | `2` | Days before auto-delete |
| `MAX_TOTAL_SIZE_MB` | `100` | Max storage size |
| `MAX_CONTENT_SIZE_MB` | `10` | Max note size |
| `CLEANUP_INTERVAL_MINUTES` | `15` | Background cleanup interval |
| `CORS_ORIGINS` | *(empty)* | Comma-separated allowed origins; empty = CORS disabled |

## Run Locally

```bash
# Build & run
go build -o paper .
./paper
```

Open http://localhost:7860

## Deploy

### Docker
```bash
docker build -t paper .
docker run -p 7860:7860 paper
```

### VPS (PM2 + Cloudflare Tunnel)
```bash
git pull && bash deploy.sh
```

`deploy.sh` stores notes in `/var/lib/paper` (persistent, app-owned — never
`/tmp`, which the OS can reclaim). To also put a real filesystem ceiling under
the 100 MB app budget:

```bash
QUOTA_SIZE_MB=110 bash deploy.sh   # mounts a 110 MB loopback ext4 at /var/lib/paper
```

The quota is opt-in (needs root + loop device support). Set `DATA_DIR` to
override the storage location.

### Cloudflare rate limiting (edge)

The server has no app-level rate limit, so it's enforced at the Cloudflare edge,
just before the tunnel. The rule fits the **Cloudflare Free plan**. `deploy.sh`
applies it when two vars are set:

```bash
export CF_API_TOKEN=<token>   # needs Zone.WAF:Edit on the zone
export CF_ZONE_ID=<zone id>
export CF_RATE=30             # optional, requests per 10 s per IP
git pull && bash deploy.sh
```

The Free plan allows one rate limiting rule per zone, matching on the URI path
only, with a fixed 10 s window and 10 s block. So Paper uses a single rule:

| Matches | Limit | After breach |
|---------|-------|--------------|
| path `/api/save` or `/api/load` | 30 requests / 10 s per IP (shared) | HTTP 429 for 10 s |

Normal use stays well below this: autosave fires at most once per 1.5 s per tab.

Free-plan consequences to be aware of:
- The rule can't filter by hostname or method, so it applies to those two paths on
  **every hostname in the zone**.
- The zone's single rate limiting slot is used by Paper. If another rule already
  holds it, `apply` stops and says so instead of failing halfway.
- It slows abuse down; it doesn't cap it. 30 saves/10 s of 10 MB notes can still fill
  the 100 MB storage budget, after which saves get `507` until cleanup.

`apply` is idempotent (adds, updates in place, or leaves the rule unchanged) and
removes rules left by the older two-rule version. Other subcommands: `list`,
`remove` (Paper rules only), `show` (print the JSON to add by hand in the dashboard).
On a paid plan, `--paid-plan` unlocks other `--period` / `--mitigation` values.

## Security Notes

- All encryption happens in your browser
- Password is never transmitted or stored
- Server cannot decrypt your notes
- Note identity is a random 128-bit URL (capability), not the password
- Someone with the link but not the passphrase can't read or overwrite the note
- Use a strong passphrase — 16+ characters recommended

## License

MIT
