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
- 🗑️ **Auto-delete** — Notes removed after 2 days of inactivity
- 🌐 **Access anywhere** — Same password = same note, from any device
- 🚫 **No tracking** — No cookies, no analytics, no accounts

## How It Works

```
┌─────────────────┐         ┌─────────────────┐
│     Browser     │         │     Server      │
├─────────────────┤         ├─────────────────┤
│                 │         │                 │
│  Password ──────┼─► SHA-256 Hash (16 char)  │
│        │        │         │        │        │
│        ▼        │         │        ▼        │
│  PBKDF2 Key     │         │  File ID        │
│  (250k rounds)  │         │  (no password)  │
│        │        │         │                 │
│        ▼        │         │                 │
│  AES-GCM        │         │                 │
│  Encrypt/Decrypt│◄───────►│  Store/Load     │
│                 │         │  Encrypted Blob │
└─────────────────┘         └─────────────────┘
```

**Key points:**
- Password → PBKDF2 → AES-256-GCM key (client only)
- Password → SHA-256 → File identifier (sent to server)
- Server stores only: encrypted content + random salt
- Server never sees: password or decrypted content

## Architecture

```
Paper/
├── index.html      # Single-page app (HTML + CSS + JS)
├── main.py         # FastAPI backend
├── deploy.sh       # VPS deploy (PM2 + Cloudflare Tunnel)
├── Dockerfile      # Container setup
└── requirements.txt
```

### Frontend (`index.html`)
- Single HTML file with embedded CSS and JavaScript
- Crypto API for AES-GCM encryption and PBKDF2 key derivation
- Auto-save with debounce (1.5s after typing stops)
- Dark theme with colorful accents

### Backend (`main.py`)
- FastAPI server with CORS support
- Two endpoints: `/api/load` and `/api/save`
- File-based storage (configurable via `DATA_DIR`)
- Auto-cleanup: files older than 2 days or when storage exceeds limit

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATA_DIR` | `/tmp` | Storage directory |
| `AGE_LIMIT_DAYS` | `2` | Days before auto-delete |
| `MAX_TOTAL_SIZE_MB` | `100` | Max storage size |
| `MAX_CONTENT_SIZE_MB` | `10` | Max note size |

## Run Locally

```bash
# Install dependencies
pip -r requirements.txt

# Start server
uvicorn main:app --host 0.0.0.0 --port 7860
```

Open http://localhost:7860

## Deploy

### Docker
```bash
docker build -t paper .
docker run -p 7860:7860 paper
```

## Security Notes

- All encryption happens in your browser
- Password is never transmitted or stored
- Server cannot decrypt your notes
- Use a strong, memorable password
- No password recovery possible

## License

MIT
