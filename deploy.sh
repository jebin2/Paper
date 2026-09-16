#!/usr/bin/env bash
set -euo pipefail

APP_NAME="paper"
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFERRED_PORT=7860
PORT_REQUESTED="${PORT:-}"
DOMAIN="${DOMAIN:-paper.voidall.com}"
DATA_DIR="${DATA_DIR:-/var/lib/paper}"
BUILD_DIR="$APP_DIR"

# Always use the toolchain actually installed on this machine. Without this,
# any `go` invocation in a module whose go.mod demands a newer Go silently
# tries to download that toolchain — and fails on VPSes without proxy access.
export GOTOOLCHAIN=local

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${GREEN}[✓]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*"; exit 1; }
step()  { echo -e "\n${BLUE}──${NC} $*"; }

echo ""
echo "  Paper — VPS deploy (Go, Cloudflare Tunnel)"
echo "  ──────────────────────────────────────────────"

# ── Port and route safety ─────────────────────────────────────────────────────

find_cf_config() {
  local candidate
  for candidate in /etc/cloudflared/config.yml /root/.cloudflared/config.yml "$HOME/.cloudflared/config.yml"; do
    [ -f "$candidate" ] && { printf '%s' "$candidate"; return; }
  done
}

tunnel_rules() {
  [ -f "${1:-}" ] || return 0
  python3 - "$1" <<'PYEOF'
import re, sys
text = open(sys.argv[1]).read()
for host, svc in re.findall(r"-\s*hostname:\s*(\S+)\s*\n\s*service:\s*(\S+)", text):
    m = re.search(r":(\d+)\s*$", svc)
    print(host, m.group(1) if m else "")
PYEOF
}

check_tunnel_route() {
  local config="$1" domain="$2" port="$3"
  local host rule_port routed="" clash=""

  while read -r host rule_port; do
    [ -z "$rule_port" ] && continue
    if [ "$host" = "$domain" ]; then
      routed="$rule_port"
    elif [ "$rule_port" = "$port" ]; then
      clash="$host"
    fi
  done < <(tunnel_rules "$config")

  if [ -n "$routed" ]; then
    [ "$routed" = "$port" ] && { printf 'OK'; return; }
    printf 'WRONGPORT %s' "$routed"
    return
  fi

  [ -n "$clash" ] && { printf 'CLASH %s' "$clash"; return; }
  printf 'MISSING'
}

port_holder() {
  ss -ltnp 2>/dev/null | awk -v p=":$1\$" '$4 ~ p {print $NF; exit}'
}

wait_for_port() {
  local timeout="${1:-30}" port="$2" waited=0 appname="${3:-}"
  while [ "$waited" -lt "$timeout" ]; do
    port_holder "$port" >/dev/null && return 0
    if [ -n "$appname" ] && [ -z "$(pm2 pid "$appname" 2>/dev/null || true)" ]; then
      warn "$appname exited before binding port $port."
      return 1
    fi
    sleep 1; waited=$((waited + 1))
  done
  return 1
}

port_is_ours_or_free() {
  local port="$1" me="$2" holder mypid
  holder=$(port_holder "$port")
  [ -z "$holder" ] && return 0
  mypid=$(pm2 pid "$me" 2>/dev/null || true)
  [ -n "$mypid" ] && printf '%s' "$holder" | grep -q "pid=$mypid"
}

assert_port_available() {
  local port="$1" me="$2" holder other
  port_is_ours_or_free "$port" "$me" && return 0
  holder=$(port_holder "$port")
  other=$(pm2 jlist 2>/dev/null | python3 -c "
import json, sys
try: procs = json.load(sys.stdin)
except Exception: procs = []
print(' '.join(p['name'] for p in procs if p.get('name') != '$me'
                and p.get('pm2_env', {}).get('status') == 'online'))
" 2>/dev/null || true)
  error "Port $port is already in use by: $holder
  Starting '$me' here would crash-loop on EADDRINUSE, so this stops now.
  Other PM2 apps online: ${other:-none}
  Free the port, or pick another:  PORT=<free-port> bash deploy.sh"
}

resolve_port() {
  local preferred="$1" domain="$2" me="$3" config="$4"
  local routed="" taken=" " host rule_port candidate

  while read -r host rule_port; do
    [ -z "$rule_port" ] && continue
    [ "$host" = "$domain" ] && routed="$rule_port"
    taken="$taken$rule_port "
  done < <(tunnel_rules "$config")

  if [ -n "${PORT_REQUESTED:-}" ]; then
    PORT="$PORT_REQUESTED"
    assert_port_available "$PORT" "$me"
    info "Port $PORT (set explicitly)"
    return
  fi

  if [ -n "$routed" ]; then
    PORT="$routed"
    assert_port_available "$PORT" "$me"
    info "Port $PORT (from the existing $domain tunnel rule)"
    return
  fi

  for candidate in $(seq "$preferred" $((preferred + 60))); do
    case "$taken" in *" $candidate "*) continue ;; esac
    port_is_ours_or_free "$candidate" "$me" || continue
    PORT="$candidate"
    [ "$candidate" = "$preferred" ] && info "Port $PORT" \
      || info "Port $preferred is taken — using $PORT instead"
    return
  done
  error "No free port in $preferred..$((preferred + 60)). Check: ss -ltnp"
}

print_routes() {
  local config="$1" domain="$2"
  if [ -z "$config" ] || [ ! -f "$config" ]; then
    warn "No cloudflared config found — cannot list the routes."
    return
  fi
  PM2_JSON="$(pm2 jlist 2>/dev/null || echo '[]')" \
  LISTENERS="$(ss -ltnp 2>/dev/null || true)" \
  python3 - "$config" "$domain" <<'PYEOF'
import json, os, re, sys

config, current = sys.argv[1], sys.argv[2]
GREEN, YELLOW, DIM, BOLD, NC = "\033[0;32m", "\033[1;33m", "\033[2m", "\033[1m", "\033[0m"

rules = []
for host, svc in re.findall(r"-\s*hostname:\s*(\S+)\s*\n\s*service:\s*(\S+)",
                            open(config).read()):
    m = re.search(r":(\d+)\s*$", svc)
    rules.append((host, m.group(1) if m else "?"))

listening = {}
for line in os.environ.get("LISTENERS", "").splitlines():
    addr = re.search(r"\s(\S+):(\d+)\s", line)
    pid = re.search(r"pid=(\d+)", line)
    if addr:
        listening[addr.group(2)] = pid.group(1) if pid else ""

try:
    procs = json.loads(os.environ.get("PM2_JSON") or "[]")
except Exception:
    procs = []
by_pid = {str(p.get("pid")): p.get("name", "") for p in procs if p.get("pid")}
by_name = {p.get("name", ""): p.get("pm2_env", {}).get("status", "") for p in procs}

rows = []
for host, port in rules:
    pid = listening.get(port)
    if pid is None:
        state, app = "not running", "—"
    else:
        app = by_pid.get(pid, "")
        state = by_name.get(app, "online") if app else "online"
        app = app or "(not pm2)"
    rows.append((host, port, state, app, host == current))

if not rows:
    print("  (no hostname rules in the tunnel config)")
    sys.exit()

w_host = max(6, max(len(r[0]) for r in rows))
w_app = max(3, max(len(r[3]) for r in rows))
w_state = max(6, max(len(r[2]) for r in rows))
line = "  " + "─" * (w_host + w_app + w_state + 17)

print()
print(f"  {BOLD}Cloudflare Tunnel routes{NC}  {DIM}({config}){NC}")
print(line)
print(f"  {BOLD}{'DOMAIN'.ljust(w_host)}  {'PORT'.rjust(5)}  {'STATUS'.ljust(w_state + 2)}  {'PM2'.ljust(w_app)}{NC}")
print(line)
for host, port, state, app, is_me in rows:
    dot = f"{GREEN}●{NC}" if state == "online" else f"{YELLOW}○{NC}"
    here = f"  {GREEN}← this app{NC}" if is_me else ""
    print(f"  {host.ljust(w_host)}  {port.rjust(5)}  {dot} {state.ljust(w_state)}  {app.ljust(w_app)}{here}")
print(line)
PYEOF
}

ensure_dns_route() {
  local domain="$1" config="$2" tunnel
  tunnel=$(grep -E '^tunnel:' "$config" 2>/dev/null | awk '{print $2}' | tr -d '"' || true)
  [ -z "$tunnel" ] && tunnel="${domain%%.*}"
  if command -v cloudflared >/dev/null 2>&1 && cloudflared tunnel list 2>/dev/null | grep -qw "$tunnel"; then
    cloudflared tunnel route dns --overwrite-dns "$tunnel" "$domain" \
      && info "DNS route ensured: $domain → tunnel '$tunnel'" \
      || warn "Failed to add DNS route — add manually: cloudflared tunnel route dns $tunnel $domain"
  else
    warn "Tunnel '$tunnel' not found — add DNS manually: cloudflared tunnel route dns <TUNNEL_NAME> $domain"
  fi
}

step "Port"
command -v ss >/dev/null 2>&1 || warn "'ss' not found (install iproute2) — cannot verify a port is free."
CF_CONFIG="$(find_cf_config)"
resolve_port "$PREFERRED_PORT" "$DOMAIN" "$APP_NAME" "$CF_CONFIG"

# ── 1. PM2 ────────────────────────────────────────────────────────────────────
step "PM2"
if ! command -v pm2 &>/dev/null; then
  warn "PM2 not found — installing..."
  npm install -g pm2 2>/dev/null || sudo npm install -g pm2
  assert_port_available "$PORT" "$APP_NAME"
fi
info "PM2 $(pm2 --version 2>/dev/null)"

# ── 2. Build ──────────────────────────────────────────────────────────────────
step "Build"
if ! command -v go &>/dev/null; then
  error "Go not found. Install it (https://go.dev/dl/) then re-run."
fi
info "Go $(go version | awk '{print $3}') building..."
(cd "$APP_DIR" && CGO_ENABLED=0 go build -o paper .)
info "Binary built"

# ── 2b. Data directory + optional filesystem quota ────────────────────────────
step "Data directory"
mkdir -p "$DATA_DIR" && chmod 700 "$DATA_DIR" || error "Cannot create $DATA_DIR"
info "Data directory: $DATA_DIR"

# Opt-in loopback filesystem quota. The app has its own 100 MB write budget,
# but an OS-level limit defends against a compromised process or unexpected
# files. Set QUOTA_SIZE_MB=e.g. 110 (slightly above MAX_TOTAL_SIZE_MB) to use.
if [ -n "${QUOTA_SIZE_MB:-}" ]; then
  QUOTA_IMG="$APP_DIR/data/quota.img"
  if mountpoint -q "$DATA_DIR" 2>/dev/null; then
    info "$DATA_DIR is already its own filesystem — quota active"
  else
    mkdir -p "$APP_DIR/data"
    if [ ! -f "$QUOTA_IMG" ]; then
      info "Creating ${QUOTA_SIZE_MB}MB loopback filesystem image..."
      dd if=/dev/zero of="$QUOTA_IMG" bs=1M count="$QUOTA_SIZE_MB" status=none \
        && mkfs.ext4 -F -q "$QUOTA_IMG" \
        || warn "Could not create quota image — continuing without quota"
    fi
    if mount -o loop "$QUOTA_IMG" "$DATA_DIR" 2>/dev/null; then
      info "Mounted ${QUOTA_SIZE_MB}MB filesystem at $DATA_DIR"
    else
      warn "Could not mount quota image (kernel module? permissions?) — continuing without quota"
    fi
  fi
fi

# ── 3. Start / restart with PM2 ───────────────────────────────────────────────
step "PM2 process"
pm2 delete "$APP_NAME" 2>/dev/null || true
info "Starting '$APP_NAME' (paper binary) on 127.0.0.1:$PORT..."
LISTEN_ADDR=127.0.0.1 LISTEN_PORT="$PORT" STATIC_DIR="$APP_DIR" DATA_DIR="$DATA_DIR" pm2 start "$APP_DIR/paper" \
  --name "$APP_NAME" \
  --cwd "$APP_DIR" \
  --interpreter none \
  --time
pm2 save

if ! wait_for_port 30 "$PORT" "$APP_NAME"; then
  error "'$APP_NAME' did not bind port $PORT within 30s.
  Check its logs:  pm2 logs $APP_NAME"
fi
info "'$APP_NAME' up — answering on 127.0.0.1:$PORT"

STARTUP_CMD=$(pm2 startup 2>&1 | grep "sudo" || true)
if [ -n "$STARTUP_CMD" ]; then
  eval "$STARTUP_CMD" && info "PM2 registered for auto-start on reboot" \
    || warn "Could not register PM2 startup — run manually: $STARTUP_CMD"
fi

# ── 4. Cloudflare Tunnel ──────────────────────────────────────────────────────
step "Cloudflare Tunnel"
if [ -z "$CF_CONFIG" ]; then
  warn "cloudflared config not found. Ensure this ingress rule exists:"
  echo "    - hostname: $DOMAIN"
  echo "      service: http://localhost:$PORT"
else
  ROUTE=$(check_tunnel_route "$CF_CONFIG" "$DOMAIN" "$PORT")
  case "$ROUTE" in
    OK)
      info "$DOMAIN → localhost:$PORT already routed — no change needed"
      ensure_dns_route "$DOMAIN" "$CF_CONFIG" ;;
    CLASH*)
      error "Port $PORT is already routed to ${ROUTE#CLASH } in $CF_CONFIG.
  Adding $DOMAIN on the same port would give two hostnames one app.
  Pick a free port:  PORT=<free-port> bash deploy.sh" ;;
    WRONGPORT*)
      error "$DOMAIN is routed to ${ROUTE#WRONGPORT } in $CF_CONFIG, not port $PORT.
  This deploy would look successful while the tunnel kept serving the old app.
  Fix the rule by hand, or deploy on that port:  PORT=<that-port> bash deploy.sh" ;;
    MISSING)
      sudo cp "$CF_CONFIG" "${CF_CONFIG}.bak"
      sudo python3 - "$CF_CONFIG" "$DOMAIN" "$PORT" <<'PYEOF'
import sys, re
config_path, domain, port = sys.argv[1], sys.argv[2], sys.argv[3]
new_rule = f"  - hostname: {domain}\n    service: http://localhost:{port}\n"
content = open(config_path).read()
m = re.search(r'^(\s*- service:\s*http_status:\d+\s*)$', content, re.MULTILINE)
content = (content[:m.start()] + new_rule + content[m.start():]) if m else (content.rstrip() + "\n" + new_rule)
open(config_path, 'w').write(content)
print("Config updated.")
PYEOF
      info "Added $DOMAIN → localhost:$PORT (existing rules untouched; backup at ${CF_CONFIG}.bak)"
      ensure_dns_route "$DOMAIN" "$CF_CONFIG"
      systemctl is-active --quiet cloudflared 2>/dev/null && sudo systemctl restart cloudflared && info "cloudflared restarted" \
        || warn "Restart cloudflared manually: sudo systemctl restart cloudflared" ;;
  esac
fi

# ── 4b. Cloudflare rate limiting (edge) ──────────────────────────────────────
step "Cloudflare Rate Limiting"
if [ -z "${CF_API_TOKEN:-}" ] || [ -z "${CF_ZONE_ID:-}" ]; then
  warn "Set CF_API_TOKEN + CF_ZONE_ID to manage the rate limits via API.
  Skipping — rules can be added manually in the dashboard (see README)."
else
  if python3 "$APP_DIR/cloudflare/rate-limit.py" apply \
      --token "$CF_API_TOKEN" --zone-id "$CF_ZONE_ID" --host "$DOMAIN"; then
    info "Edge rate limiting: /api/save and /api/load covered (per-IP, per zone)"
  else
    warn "Cloudflare rate-limit step failed — deploy continues, check the error above."
  fi
fi

# ── 5. Verify it actually came up ─────────────────────────────────────────────
step "Health"
sleep 2
if curl -fsS -o /dev/null "http://127.0.0.1:$PORT/health" 2>/dev/null; then
  info "Responding on 127.0.0.1:$PORT"
else
  warn "No response yet on 127.0.0.1:$PORT — check: pm2 logs $APP_NAME --lines 50"
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
print_routes "$CF_CONFIG" "$DOMAIN"

echo ""
echo "  ─────────────────────────────────────────"
info "Done!"
echo ""
echo "  Go server on 127.0.0.1:$PORT"
echo "  Tunnel:  https://$DOMAIN"
echo ""
echo "  Useful commands:"
echo "    pm2 logs $APP_NAME        — live logs"
echo "    pm2 restart $APP_NAME     — restart"
echo "    pm2 status                — process status"
echo ""
echo "  To update: git pull && bash deploy.sh"
echo ""
