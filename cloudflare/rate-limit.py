#!/usr/bin/env python3
"""Manage Cloudflare edge rate limiting for Paper (zone http_ratelimit phase).

Usage:
  python3 cloudflare/rate-limit.py apply  --token <CF_API_TOKEN> --zone-id <ZONE> [options]
  python3 cloudflare/rate-limit.py list   --token <CF_API_TOKEN> --zone-id <ZONE> [options]
  python3 cloudflare/rate-limit.py remove --token <CF_API_TOKEN> --zone-id <ZONE> [options]
  python3 cloudflare/rate-limit.py show   [options]

`apply` is idempotent and self-healing. Each Paper rule carries a stable `ref`
(paper_save, paper_load). Against an existing entry point ruleset it will:
  - missing ref  -> POST (create)
  - same config  -> leave untouched
  - changed config -> PUT (update in place)
Rules not owned by Paper are never modified. Needs only stdlib urllib; the API
token needs `Zone.WAF` (Edit) on the zone.
"""
import argparse
import json
import sys
import urllib.error
import urllib.request

API = "https://api.cloudflare.com/client/v4"
PHASE = "http_ratelimit"
LABEL = "paper"


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


def check(payload, status):
    if status == 404:
        return False
    if not payload.get("success"):
        errors = "; ".join(f"{e.get('code')} {e.get('message')}" for e in payload.get("errors", []))
        sys.exit(f"error: Cloudflare API failed ({status}): {errors or payload}")
    return True


def entrypoint(base_url, token, zone):
    return api(base_url, token, "GET", f"/zones/{zone}/rulesets/phases/{PHASE}/entrypoint")


def rule_body(ref, args, name, path, rate, mitigation):
    return {
        "ref": ref,
        "description": f"{args.label} {name} rate limit",
        "expression": f'(http.host eq "{args.host}" and http.request.method eq "POST" and http.request.uri.path eq "{path}")',
        "action": "block",
        "action_parameters": {
            "response": {
                "status_code": 429,
                "content_type": "text/plain",
                "content": "Rate limit exceeded. Slow down and try again.",
            }
        },
        "ratelimit": {
            "characteristics": ["ip.src"],
            "period": args.period,
            "requests_per_period": rate,
            "mitigation_timeout": mitigation,
        },
        "enabled": True,
    }


def build_rules(args):
    return [
        rule_body("paper_save", args, "save", "/api/save", args.save_rate, args.mitigation),
        rule_body("paper_load", args, "load", "/api/load", args.load_rate, args.mitigation_s),
    ]


def rule_config(rule):
    keys = ("description", "expression", "action", "action_parameters", "ratelimit", "enabled")
    return {k: rule.get(k) for k in keys}


def validate_rates(args):
    bad = []
    for name, v in [("--period", args.period), ("--save-rate", args.save_rate),
                    ("--load-rate", args.load_rate), ("--mitigation", args.mitigation),
                    ("--mitigation-s", args.mitigation_s)]:
        if v < 1:
            bad.append(f"{name} must be >= 1 (got {v})")
    if args.save_rate >= args.load_rate:
        # not a hard error — load legitimately gets a higher allowance than save
        pass
    if bad:
        sys.exit("error: " + "; ".join(bad))


def cmd_apply(args):
    validate_rates(args)
    rules = build_rules(args)
    if args.dry_run:
        print(json.dumps(rules, indent=2))
        return

    status, payload = entrypoint(args.base_url, args.token, args.zone_id)
    if check(payload, status):
        rid = payload["result"]["id"]
        existing = {r.get("ref"): r for r in payload["result"].get("rules", []) if r.get("ref")}
        for rule in rules:
            cur = existing.get(rule["ref"])
            if cur is None:
                st, res = api(args.base_url, args.token, "POST",
                              f"/zones/{args.zone_id}/rulesets/{rid}/rules", rule)
                check(res, st) or sys.exit(f"error: POST rule failed ({st})")
                print(f"added: {rule['ref']}")
            elif rule_config(cur) == rule_config(rule):
                print(f"unchanged: {rule['ref']}")
            else:
                st, res = api(args.base_url, args.token, "PUT",
                              f"/zones/{args.zone_id}/rulesets/{rid}/rules/{cur['id']}", rule)
                check(res, st) or sys.exit(f"error: PUT rule failed ({st})")
                print(f"updated: {rule['ref']}")
    else:
        payload = {
            "name": "Paper rate limiting",
            "kind": "root",
            "phase": PHASE,
            "rules": rules,
        }
        st, res = api(args.base_url, args.token, "POST", f"/zones/{args.zone_id}/rulesets", payload)
        check(res, st) or sys.exit(f"error: create ruleset failed ({st})")
        for rule in rules:
            print(f"added: {rule['ref']}")
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
        owned = " [paper]" if rule.get("ref") in ("paper_save", "paper_load") else ""
        print(f"- {rule.get('ref', rule.get('description', '?'))}  id={rule.get('id', '?')}{owned}")
        print(f"    {rule.get('expression', '')}")


def cmd_remove(args):
    status, payload = entrypoint(args.base_url, args.token, args.zone_id)
    if not check(payload, status):
        print("no http_ratelimit rules configured — nothing to remove")
        return
    rid = payload["result"]["id"]
    removed = False
    for rule in payload["result"].get("rules", []):
        if rule.get("ref") not in ("paper_save", "paper_load"):
            continue
        st, res = api(args.base_url, args.token, "DELETE",
                      f"/zones/{args.zone_id}/rulesets/{rid}/rules/{rule['id']}")
        check(res, st) or sys.exit(f"error: DELETE rule failed ({st})")
        print(f"removed: {rule['ref']}")
        removed = True
    if not removed:
        print("no paper-owned rules found")
    else:
        print("done")


def cmd_show(args):
    print(json.dumps(build_rules(args), indent=2))


def main():
    p = argparse.ArgumentParser(description="Cloudflare edge rate limiting for Paper")
    sub = p.add_subparsers(dest="cmd", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--token", help="CF API token (or CF_API_TOKEN env)")
    common.add_argument("--zone-id", help="CF zone ID (or CF_ZONE_ID env)")
    common.add_argument("--host", default="paper.voidall.com", help="hostname the rules apply to")
    common.add_argument("--label", default=LABEL, help="rule description prefix")
    common.add_argument("--save-rate", type=int, default=120, help="POST /api/save limit per IP per period")
    common.add_argument("--load-rate", type=int, default=600, help="POST /api/load limit per IP per period")
    common.add_argument("--period", type=int, default=60, help="counting window (seconds)")
    common.add_argument("--mitigation", type=int, default=300, help="block duration after breach (seconds)")
    common.add_argument("--mitigation-s", type=int, default=60, help="load-rule block duration (seconds)")
    common.add_argument("--base-url", default=API, help="API base URL (tests)")
    common.add_argument("--dry-run", action="store_true", help="print rules, send nothing")

    sub.add_parser("apply", parents=[common]).set_defaults(fn=cmd_apply)
    sub.add_parser("list", parents=[common]).set_defaults(fn=cmd_list)
    sub.add_parser("remove", parents=[common]).set_defaults(fn=cmd_remove)
    sub.add_parser("show", parents=[common]).set_defaults(fn=cmd_show)

    args = p.parse_args()
    args.token = args.token or __import__("os").environ.get("CF_API_TOKEN")
    args.zone_id = args.zone_id or __import__("os").environ.get("CF_ZONE_ID")
    if args.cmd != "show":
        if not args.token or not args.zone_id:
            sys.exit("error: --token/--zone-id required (or CF_API_TOKEN/CF_ZONE_ID env)")
    args.fn(args)


if __name__ == "__main__":
    main()