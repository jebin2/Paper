#!/usr/bin/env python3
"""Manage Cloudflare edge rate limiting for Paper (zone http_ratelimit phase).

Built for the Cloudflare Free plan, which allows exactly:
  - 1 rate limiting rule per zone
  - rule expression on the URI path only (no hostname, no method)
  - counting by IP, a 10 s counting period and a 10 s mitigation timeout

So Paper uses one rule covering both API paths, counted per IP (plus
cf.colo.id, which the API requires). Paid plans accept the same rule.

Usage:
  python3 cloudflare/rate-limit.py apply  --token <CF_API_TOKEN> --zone-id <ZONE> [options]
  python3 cloudflare/rate-limit.py list   --token <CF_API_TOKEN> --zone-id <ZONE>
  python3 cloudflare/rate-limit.py remove --token <CF_API_TOKEN> --zone-id <ZONE>
  python3 cloudflare/rate-limit.py show   [options]

`apply` is idempotent. The Paper rule carries a stable `ref` (paper_api):
  - missing       -> POST (create)
  - same config   -> leave untouched
  - changed config -> PUT (update in place)
Rules from older versions of this script (paper_save, paper_load) are removed.
Rules not owned by Paper are never modified; on the Free plan an existing
non-Paper rate limiting rule uses up the single slot, and apply says so.
Needs only stdlib urllib; the API token needs `Zone.WAF` (Edit) on the zone.
"""
import argparse
import json
import os
import sys
import urllib.error
import urllib.request

API = "https://api.cloudflare.com/client/v4"
PHASE = "http_ratelimit"
REF = "paper_api"
LEGACY_REFS = ("paper_save", "paper_load")
PAPER_REFS = (REF,) + LEGACY_REFS
API_PATHS = ("/api/save", "/api/load")

FREE_PERIOD = 10
FREE_MITIGATION = 10


def api(base_url, token, method, path, body=None):
    req = urllib.request.Request(base_url + path, method=method)
    req.add_header("Authorization", "Bearer " + token)
    data = None
    if body is not None:
        req.add_header("Content-Type", "application/json")
        data = json.dumps(body).encode("utf-8")
    try:
        with urllib.request.urlopen(req, data=data, timeout=30) as resp:
            return resp.status, json.load(resp)
    except urllib.error.HTTPError as e:
        try:
            payload = json.loads(e.read().decode())
        except Exception:
            payload = {}
        return e.code, payload
    except Exception as e:
        sys.exit(f"error: cannot reach Cloudflare API: {e}")


def api_errors(payload):
    return "; ".join(f"{e.get('code')} {e.get('message')}" for e in payload.get("errors", [])) or str(payload)


def check(payload, status, hint=""):
    if status == 404:
        return False
    if not payload.get("success"):
        sys.exit(f"error: Cloudflare API failed ({status}): {api_errors(payload)}{hint}")
    return True


def entrypoint(base_url, token, zone):
    return api(base_url, token, "GET", f"/zones/{zone}/rulesets/phases/{PHASE}/entrypoint")


def build_rule(args):
    # Free plan: the expression may only use the path. Both API endpoints share
    # one per-IP budget; the default block response is HTTP 429.
    paths = " ".join(f'"{p}"' for p in API_PATHS)
    return {
        "ref": REF,
        "description": "paper API rate limit",
        "expression": f"(http.request.uri.path in {{{paths}}})",
        "action": "block",
        "ratelimit": {
            "characteristics": ["ip.src", "cf.colo.id"],
            "period": args.period,
            "requests_per_period": args.rate,
            "mitigation_timeout": args.mitigation,
        },
        "enabled": True,
    }


def rule_config(rule):
    keys = ("description", "expression", "action", "ratelimit", "enabled")
    cfg = {k: rule.get(k) for k in keys}
    if isinstance(cfg["ratelimit"], dict):
        cfg["ratelimit"] = dict(cfg["ratelimit"], characteristics=sorted(cfg["ratelimit"].get("characteristics", [])))
    return cfg


def validate(args):
    if args.rate < 1:
        sys.exit(f"error: --rate must be >= 1 (got {args.rate})")
    if not args.paid_plan and (args.period != FREE_PERIOD or args.mitigation != FREE_MITIGATION):
        sys.exit(f"error: the Free plan only accepts --period {FREE_PERIOD} and --mitigation {FREE_MITIGATION}; "
                 "pass --paid-plan to use other values")


FREE_SLOT_HINT = ("\nhint: the Free plan allows one rate limiting rule per zone. If another rule already "
                  "exists, remove it in the dashboard (Security > WAF > Rate limiting rules) and re-run.")


def cmd_apply(args):
    validate(args)
    rule = build_rule(args)
    if args.dry_run:
        print(json.dumps(rule, indent=2))
        return

    status, payload = entrypoint(args.base_url, args.token, args.zone_id)
    if not check(payload, status):
        body = {"name": "Paper rate limiting", "kind": "zone", "phase": PHASE, "rules": [rule]}
        st, res = api(args.base_url, args.token, "POST", f"/zones/{args.zone_id}/rulesets", body)
        check(res, st, FREE_SLOT_HINT) or sys.exit(f"error: create ruleset failed ({st})")
        print(f"added: {REF}")
        print("done")
        return

    rid = payload["result"]["id"]
    rules = payload["result"].get("rules", [])

    # Free up the slot first: drop rules left by the old two-rule layout.
    for old in [r for r in rules if r.get("ref") in LEGACY_REFS]:
        st, res = api(args.base_url, args.token, "DELETE", f"/zones/{args.zone_id}/rulesets/{rid}/rules/{old['id']}")
        check(res, st) or sys.exit(f"error: DELETE rule failed ({st})")
        print(f"removed legacy: {old['ref']}")

    others = [r for r in rules if r.get("ref") not in PAPER_REFS]
    current = next((r for r in rules if r.get("ref") == REF), None)
    if current is None:
        if others and not args.paid_plan:
            names = ", ".join(r.get("description") or r.get("ref") or r.get("id", "?") for r in others)
            sys.exit(f"error: this zone already has a rate limiting rule ({names}).{FREE_SLOT_HINT}")
        st, res = api(args.base_url, args.token, "POST", f"/zones/{args.zone_id}/rulesets/{rid}/rules", rule)
        check(res, st, FREE_SLOT_HINT) or sys.exit(f"error: POST rule failed ({st})")
        print(f"added: {REF}")
    elif rule_config(current) == rule_config(rule):
        print(f"unchanged: {REF}")
    else:
        st, res = api(args.base_url, args.token, "PUT",
                      f"/zones/{args.zone_id}/rulesets/{rid}/rules/{current['id']}", rule)
        check(res, st) or sys.exit(f"error: PUT rule failed ({st})")
        print(f"updated: {REF}")
    print("done")


def cmd_list(args):
    status, payload = entrypoint(args.base_url, args.token, args.zone_id)
    if not check(payload, status):
        print("no http_ratelimit rules configured for this zone")
        return
    rules = payload["result"].get("rules", [])
    if not rules:
        print("http_ratelimit entry point exists but has no rules")
        return
    for rule in rules:
        owned = " [paper]" if rule.get("ref") in PAPER_REFS else ""
        rl = rule.get("ratelimit", {})
        print(f"- {rule.get('ref', rule.get('description', '?'))}  id={rule.get('id', '?')}{owned}")
        print(f"    {rule.get('expression', '')}")
        if rl:
            print(f"    {rl.get('requests_per_period')} req / {rl.get('period')}s per IP, "
                  f"blocked {rl.get('mitigation_timeout')}s")


def cmd_remove(args):
    status, payload = entrypoint(args.base_url, args.token, args.zone_id)
    if not check(payload, status):
        print("no http_ratelimit rules configured — nothing to remove")
        return
    rid = payload["result"]["id"]
    removed = False
    for rule in payload["result"].get("rules", []):
        if rule.get("ref") not in PAPER_REFS:
            continue
        st, res = api(args.base_url, args.token, "DELETE",
                      f"/zones/{args.zone_id}/rulesets/{rid}/rules/{rule['id']}")
        check(res, st) or sys.exit(f"error: DELETE rule failed ({st})")
        print(f"removed: {rule['ref']}")
        removed = True
    print("done" if removed else "no paper-owned rules found")


def cmd_show(args):
    validate(args)
    print(json.dumps(build_rule(args), indent=2))


def main():
    p = argparse.ArgumentParser(description="Cloudflare edge rate limiting for Paper (Free plan compatible)")
    sub = p.add_subparsers(dest="cmd", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--token", help="CF API token (or CF_API_TOKEN env)")
    common.add_argument("--zone-id", help="CF zone ID (or CF_ZONE_ID env)")
    common.add_argument("--rate", type=int, default=30,
                        help="requests to /api/save + /api/load allowed per IP per period (default 30)")
    common.add_argument("--period", type=int, default=FREE_PERIOD, help="counting window in seconds (Free: 10)")
    common.add_argument("--mitigation", type=int, default=FREE_MITIGATION,
                        help="block duration in seconds after a breach (Free: 10)")
    common.add_argument("--paid-plan", action="store_true",
                        help="allow periods/timeouts other than 10s and coexisting rules")
    common.add_argument("--base-url", default=API, help="API base URL (tests)")
    common.add_argument("--dry-run", action="store_true", help="print the rule, send nothing")

    for name, fn in (("apply", cmd_apply), ("list", cmd_list), ("remove", cmd_remove), ("show", cmd_show)):
        sub.add_parser(name, parents=[common]).set_defaults(fn=fn)

    args = p.parse_args()
    args.token = args.token or os.environ.get("CF_API_TOKEN")
    args.zone_id = args.zone_id or os.environ.get("CF_ZONE_ID")
    if args.cmd != "show" and not args.dry_run and (not args.token or not args.zone_id):
        sys.exit("error: --token/--zone-id required (or CF_API_TOKEN/CF_ZONE_ID env)")
    args.fn(args)


if __name__ == "__main__":
    main()
