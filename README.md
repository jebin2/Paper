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
├── ratelimit.go    # Per-client rate limiting for the API (token buckets)
├── deploy.sh       # VPS deploy (PM2 + Cloudflare Tunnel)
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
| `MAX_CONTENT_SIZE_MB` | `1` | Max note size, encrypted + base64 (1 MB ≈ 750 KB of text) |
| `CLEANUP_INTERVAL_MINUTES` | `15` | Background cleanup interval |
| `CORS_ORIGINS` | *(empty)* | Comma-separated allowed origins; empty = CORS disabled |
| `RATE_LIMIT_SAVE_PER_MIN` | `60` | `/api/save` requests per client per minute; `0` disables |
| `RATE_LIMIT_LOAD_PER_MIN` | `120` | `/api/load` requests per client per minute; `0` disables |
| `TRUST_PROXY_HEADER` | *(empty)* | Header holding the real client IP behind a proxy (`CF-Connecting-IP` in `deploy.sh`, `X-Forwarded-For` in Docker); empty = connection address |

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

`deploy.sh` stores notes in `/var/lib/paper` (persistent, never `/tmp`, which
the OS can reclaim). Run it as the user the app should run as: it creates the
directory with `sudo` (you may be prompted once) and makes that user its owner.
Without `sudo` it falls back to `~/.local/share/paper`. To also put a real
filesystem ceiling under the 100 MB app budget:

```bash
QUOTA_SIZE_MB=110 bash deploy.sh   # mounts a 110 MB loopback ext4 at /var/lib/paper
```

The quota is opt-in (needs root + loop device support). Set `DATA_DIR` to
override the storage location.

### Rate limiting

The server limits each client itself — no Cloudflare rules or API tokens needed.
Every client gets a token bucket per endpoint:

| Endpoint | Default | Burst |
|----------|---------|-------|
| `/api/save` | 60 / min | 30 |
| `/api/load` | 120 / min | 60 |

Over the limit, requests get `429` with `Retry-After`, before the body is even
read. The editor shows "too many saves" and retries with backoff; the login
screen asks to wait. Normal use stays far below this (autosave fires at most
once per 1.5 s per tab).

**Client identity.** Behind a proxy every request comes from the proxy, so the
real IP must come from a header — set `TRUST_PROXY_HEADER`, but only when the
server can't be reached except through that proxy, or clients could spoof it:

- `deploy.sh` binds to `127.0.0.1` behind the Cloudflare Tunnel and uses
  `CF-Connecting-IP`.
- The Docker image uses `X-Forwarded-For` (first entry) for hosts like Hugging Face
  Spaces. If the container port is exposed directly, set `TRUST_PROXY_HEADER=` so
  the connection address is used instead.

IPv6 clients are grouped by `/64`, so rotating addresses within one allocation
doesn't dodge the limit. Limiter memory is bounded (100k tracked clients; idle
ones are swept); past that, new clients are let through rather than locked out.

Rate limiting slows abuse, it doesn't cap it: many IPs can still fill the
`MAX_TOTAL_SIZE_MB` budget, after which saves get `507` until cleanup. The 1 MB
note cap keeps that slow — 100 MB takes 100 distinct full-size notes.

## Security Notes

- All encryption happens in your browser
- Password is never transmitted or stored
- Server cannot decrypt your notes
- Note identity is a random 128-bit URL (capability), not the password
- Someone with the link but not the passphrase can't read or overwrite the note
- Use a strong passphrase — 16+ characters recommended

## License

MIT
