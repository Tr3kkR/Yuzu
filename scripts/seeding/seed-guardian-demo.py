#!/usr/bin/env python3
"""
seed-guardian-demo.py — populate a Yuzu instance with the "Demo Enforcements"
Guardian demo content: two enforce Guards (RDP disabled; Print Spooler kept
running) and the Baseline that holds them.

Quick start (against a local UAT rig):

    python dev/scripts/guardian/demo/seed-guardian-demo.py            # create as DRAFT
    python dev/scripts/guardian/demo/seed-guardian-demo.py --deploy   # create AND deploy

Config (environment variables; defaults target a local UAT rig):

    YUZU_BASE         server URL        (default http://localhost:8080)
    YUZU_ADMIN_USER   admin username    (default admin)
    YUZU_ADMIN_PASS   admin password    (default YuzuUatAdmin1!  -- the local UAT default)

Stdlib only; runs on Linux/macOS/Windows. Idempotent — safe to re-run.
"""
import argparse
import http.cookiejar
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

BASE = os.environ.get("YUZU_BASE", "http://localhost:8080").rstrip("/")
USER = os.environ.get("YUZU_ADMIN_USER", "admin")
PASS = os.environ.get("YUZU_ADMIN_PASS", "YuzuUatAdmin1!")
HERE = Path(__file__).resolve().parent
GUARDS_DIR = HERE / "guards"
BASELINES_DIR = HERE / "baselines"


def opener():
    cj = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))


def login(op):
    data = urllib.parse.urlencode({"username": USER, "password": PASS}).encode()
    op.open(BASE + "/login", data=data, timeout=15)


def _send(op, path, data, headers, method="POST"):
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        r = op.open(req, timeout=15)
        return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def post_json(op, path, obj):
    return _send(op, path, json.dumps(obj).encode("utf-8"),
                 {"Content-Type": "application/json"})


def post_form(op, path, fields):
    body = urllib.parse.urlencode(fields, encoding="utf-8").encode("utf-8")
    return _send(op, path, body,
                 {"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"})


def get(op, path):
    return op.open(BASE + path, timeout=15).read().decode("utf-8", "replace")


def rule_id_to_name(op):
    """Map every Guard's rule_id -> name from the live store (the Baseline form
    matches members by name, so we resolve ids to names here)."""
    d = json.loads(get(op, "/api/v1/guaranteed-state/rules"))
    rules = d["data"] if isinstance(d, dict) and "data" in d else d
    return {r["rule_id"]: r["name"] for r in rules if r.get("rule_id")}


def banner_text(resp):
    m = re.search(r"&#9888;\s*([^<]*)", resp)
    return m.group(1).strip() if m else "unknown error"


def seed_guards(op):
    for path in sorted(GUARDS_DIR.glob("*.json")):
        body = json.loads(path.read_text(encoding="utf-8"))
        rid = body.get("rule_id", path.stem)
        code, resp = post_json(op, "/api/v1/guaranteed-state/rules", body)
        if code in (200, 201):
            print(f"[demo-seed] OK   guard '{rid}' created")
        elif code == 409 or "exist" in resp.lower():
            print(f"[demo-seed] OK   guard '{rid}' already present")
        else:
            print(f"[demo-seed] FAIL guard '{rid}': HTTP {code} {resp[:200]}", file=sys.stderr)


def find_baseline_id(op, name):
    html = get(op, "/fragments/guardian/baselines")
    m = re.search(r'/guardian/baseline/([0-9a-f]+)"[^>]*>\s*' + re.escape(name), html)
    return m.group(1) if m else None


def seed_baselines(op, deploy):
    id2name = rule_id_to_name(op)
    for path in sorted(BASELINES_DIR.glob("*.json")):
        spec = json.loads(path.read_text(encoding="utf-8"))
        name = spec.get("name", "").strip()
        if not name:
            print(f"[demo-seed] FAIL {path.name}: missing 'name'", file=sys.stderr)
            continue
        member_ids = spec.get("member_rule_ids", [])
        members = [id2name[r] for r in member_ids if r in id2name]
        missing = [r for r in member_ids if r not in id2name]

        fields = [("name", name), ("description", spec.get("description", ""))]
        fields += [("guards", m) for m in members]
        code, resp = post_form(op, "/fragments/guardian/baselines", fields)

        if "gs-error-banner" in resp:
            b = banner_text(resp)
            if "already exists" in b.lower():
                print(f"[demo-seed] OK   baseline '{name}' already present (left as-is)")
            else:
                print(f"[demo-seed] FAIL baseline '{name}': {b}", file=sys.stderr)
                continue
        else:
            note = f"created with {len(members)} member(s)"
            if missing:
                note += f"; {len(missing)} member rule_id(s) not in store: {', '.join(missing)}"
            print(f"[demo-seed] OK   baseline '{name}' {note}")

        if deploy:
            bid = find_baseline_id(op, name)
            if not bid:
                print(f"[demo-seed] WARN baseline '{name}': could not resolve id to deploy",
                      file=sys.stderr)
                continue
            code, _ = post_form(op, f"/fragments/guardian/baseline/{bid}/deploy", [])
            ok = code in (200, 201)
            print(f"[demo-seed] {'OK  ' if ok else 'FAIL'} baseline '{name}' deploy -> HTTP {code}",
                  file=(sys.stdout if ok else sys.stderr))


def main():
    ap = argparse.ArgumentParser(
        description="Seed the 'Demo Enforcements' Guardian demo content into a Yuzu instance.")
    ap.add_argument("--deploy", action="store_true",
                    help="deploy each Baseline after creating it "
                         "(a draft Baseline is authored-but-inert; Guards only enforce on agents "
                         "once their Baseline is DEPLOYED)")
    args = ap.parse_args()

    op = opener()
    try:
        login(op)
    except Exception as e:  # noqa: BLE001 - the rig may be down; surface and bail
        print(f"[demo-seed] ERROR: cannot reach / log in to {BASE}: {e}", file=sys.stderr)
        return 1

    seed_guards(op)
    seed_baselines(op, args.deploy)
    tail = " [deployed]" if args.deploy else " [draft -- re-run with --deploy to activate]"
    print(f"[demo-seed] done against {BASE}{tail}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
