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
- 🏷️ **Memorable names** — Optionally also reach a note at `/#my-note`
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
- Password + salt → PBKDF2-SHA256, 600,000 iterations (512 bits) → AES-256-GCM key + 256-bit
  write token (client only)
- Each note records the derivation it was created with, so the cost can be raised for new
  notes without locking anyone out of an old one (notes made before this: 250,000)
- Random 128-bit link (in the URL) identifies the note — never derived from the password
- The salt is chosen by the browser and stored with the note on its first save
- Server stores only: encrypted content, the salt, the derivation parameters, and a SHA-256
  digest of the write token
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
├── alias.go        # Optional memorable names for notes (/#my-note)
├── deploy.sh       # VPS deploy (PM2 + Cloudflare Tunnel)
├── Dockerfile      # Multi-stage container build
└── go.mod
```

### Names (`alias.go`)

A note always lives at its random link, and may also answer to **one** memorable
name: `/#my-note` reaches the same note as `/#9f3c…`. Names are 3-32 chars of
lowercase letters, digits and dashes (a 32-hex string is always an ID, never a
name).

- Setting, renaming or removing a name takes the note's write token, so only
  whoever knows the passphrase can do it. First claim wins; a taken name gets `409`.
- Names resolve **server-side** and the random link is never sent back, so guessing
  a name doesn't expose the strong link.
- Typing an unused name into the URL creates a note that takes that name on its
  first save; if someone claims it in between, the note stays at its random link
  and the editor says so.
- Renaming frees the old name immediately. Names are deleted with their note, and
  cleanup reclaims names left behind by an interrupted rename. Capped at 10k names.
- A name is reserved only while its note lives. Once the note expires, the next
  asker gets the name, without waiting for a cleanup pass.
- Because the link is never sent back, a note reopened at its name can no longer
  learn its own random link. The name dialog therefore offers the random link for
  copying while the tab still knows it, and says what is lost without a copy.

**The trade-off:** a name is guessable, so anyone who guesses it can download that
note's ciphertext and attack the passphrase offline, where rate limits don't apply.
Write tokens still stop them changing the note. Unnamed notes keep the original
property that the link itself is the secret — so name the throwaway notes, not
the ones with secrets in them.

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
  - `save` creates the note on first write (salt + derivation + token digest + content) and
    afterwards requires the matching write token (`403` otherwise), compared in constant time
  - the derivation is fixed at creation; a later `save` naming a different one is ignored,
    since changing it would change the key and lock the owner out
  - `save` also requires `base` = the version the edit started from (`load` and `save` both
    return the current `version`); a stale base gets `409` instead of silently overwriting
  - `name` sets, renames or removes a note's memorable name (same write token as `save`)
- File-based storage (configurable via `DATA_DIR`)
- Auto-cleanup: notes not opened or edited for 2 days (a load refreshes the note's mtime), or
  the oldest notes when storage exceeds the limit,
  run at startup and on a timer (`CLEANUP_INTERVAL_MINUTES`), never on the request path
- Eviction floor: a note younger than `EVICT_MIN_AGE_HOURS` is never deleted to make room.
  Purging by size deletes other people's notes, so without a floor one client could flood the
  store and clear it out. When only young notes remain the store stays full and saves get `507`
  instead — being unable to write is recoverable, losing a note is not
- Write budget: saves are rejected (`507`) while storage is at the `MAX_TOTAL_SIZE_MB` cap, so a full disk can't be caused by writes between cleanups. Orphaned salt/token files and stale crash temps are GC'd on every cleanup.
- Strict security headers on every response: CSP (`script-src 'self'` — the
  frontend ships as a separate `app.js`), `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer`, `Permissions-Policy`, `X-Frame-Options: DENY`,
  `Cross-Origin-Opener-Policy` and `Cross-Origin-Resource-Policy` (both `same-origin`),
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
| `EVICT_MIN_AGE_HOURS` | `6` | Notes younger than this are never purged to make room; `0` removes the floor |
| `CORS_ORIGINS` | *(empty)* | Comma-separated allowed origins; empty = CORS disabled |
| `RATE_LIMIT_SAVE_PER_MIN` | `60` | `/api/save` requests per client per minute; `0` disables |
| `RATE_LIMIT_LOAD_PER_MIN` | `120` | `/api/load` requests per client per minute; `0` disables |
| `RATE_LIMIT_NAME_PER_MIN` | `20` | `/api/name` requests per client per minute; `0` disables |
| `RATE_LIMIT_NAME_LOOKUP_PER_MIN` | `10` | name guesses (`/api/load` by a name with no note) per client per minute; `0` disables |
| `RATE_LIMIT_NAME_CLAIM_PER_HOUR` | `10` | **new** names claimed per client per hour (renames and removals are free); `0` disables |
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
| `/api/name` | 20 / min | 10 |
| name guesses | 10 / min | 5 |
| new name claims | 10 / hour | 5 |

A random link is unguessable, so loads by link can be generous. Names are words,
and a guess that lands hands out ciphertext to attack offline — so names get a
second, much smaller bucket on top of the load limit.

Taking a **new** name has its own slow budget, charged only when a note that has
no name takes one. The name space is a fixed, shared 10k and a note holds its name
for as long as it keeps being opened, so at `/api/name`'s own rate one client could
take every name in an afternoon and keep them forever. Renaming and removing add no
name to the world and are never charged.

Only a name that resolves to **nothing** is charged, because only a miss is a
guess: resolving a name that exists is what normal use of a named note does on
every unlock, refresh and conflict check, and never runs out. Once the budget is
gone, every name lookup is refused, hit or miss — answering hits while refusing
misses would tell a guesser exactly what it wanted to know, for free.

Over the limit, requests get `429` with `Retry-After` — for the per-endpoint
buckets, before the body is even read. The editor shows "too many saves" and retries with backoff; the login
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
- Use a strong passphrase — 16+ characters recommended. It is the only thing protecting a
  note whose link someone already has, and the only thing protecting a **named** note at all,
  since the name is guessable by design
- Key derivation is recorded per note, so its cost can be raised later without breaking
  existing notes
- Known limits: the browser runs whatever JavaScript the server sends, so a compromised server
  could serve a malicious client — this is true of every browser-based end-to-end encrypted
  app. Rate limits are per IP and slow abuse rather than stopping it

## License

MIT
