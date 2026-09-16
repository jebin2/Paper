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
- 🗑️ **Auto-delete** — Notes removed after 2 days of inactivity
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
- Auto-cleanup: files older than 2 days or when storage exceeds limit,
  run after each save and on a timer (`CLEANUP_INTERVAL_MINUTES`)
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

The server has no app-level rate limit; the review-priority fix is to put it at
the Cloudflare edge, just before the tunnel. `deploy.sh` does this for you when
two vars are set:

```bash
export CF_API_TOKEN=<token>   # needs Zone.WAF:Edit on paper.voidall.com
export CF_ZONE_ID=<zone id>
git pull && bash deploy.sh
```

The rules are applied to the `http_ratelimit` phase of the zone. They only match
your Paper hostname, only `POST` on `/api/save` and `/api/load`, and are keyed by
visitor IP. Applying is **idempotent and additive**: a pre-existing entry point
and any non-Paper rules are left untouched, so it's safe to re-run. Defaults:

| Rule | Limit | After breach |
|------|-------|--------------|
| `/api/save` (fs writes + fsync) | 120 req/min/IP | blocked 5 min |
| `/api/load` | 600 req/min/IP | blocked 1 min |

Tune with flags: `python3 cloudflare/rate-limit.py apply --token .. --zone-id .. \
--host paper.voidall.com --save-rate 120 --load-rate 600 --period 60 \
--mitigation 300`. Other subcommands: `list`, `remove` (paper rules only),
`show` (print the JSON to apply by hand via the dashboard).

## Security Notes

- All encryption happens in your browser
- Password is never transmitted or stored
- Server cannot decrypt your notes
- Note identity is a random 128-bit URL (capability), not the password
- Someone with the link but not the passphrase can't read or overwrite the note
- Use a strong passphrase — 16+ characters recommended

## License

MIT
