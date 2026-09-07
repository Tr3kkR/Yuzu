#!/usr/bin/env python3
"""#3990 full_sync blackout diagnostic driver (ruling-13 on #3850).

One-time rig-scoped instrument, not production tooling (see the plan's
"Sol feedback declined" section for why this stays simple rather than
production-hardened). Measures B = T1 - T0, the synchronous full_sync
apply-window proxy, on a single Windows agent under two detection backends
(legacy IGuard vs spark), triggered two ways: a baseline (re)deploy, and a
bare rule-create in no baseline (the heartbeat-reconcile trigger that is
#3990's own literal shape).

See docs/spark-rebuild-baselines/3990-fullsync-blackout-run.md for the
measurand definitions, void rules, and decision criterion this implements -
this file is the mechanism, that doc is the record of what it measured.

Environment: YUZU_BASE (default http://127.0.0.1:8130), YUZU_ADMIN_USER,
YUZU_ADMIN_PASS (defaults match generate_resgate_load.py's UAT defaults -
override for a non-default rig). YUZU_DGRHP_SSH (ssh destination for the
agent-log reads, e.g. "-S /tmp/sock -i ~/.ssh/key user@host" as a single
pre-built arg string), YUZU_AGENT_LOG (default C:\\rigA\\logs\\agent.log).

FIXED 2026-09-07 (see docs/spark-rebuild-baselines/3990-fullsync-blackout-run.md, "T1
detection: the real root cause"): the residual t0_not_found/t1_not_found false-void rate
from the 2026-09-06/07 run was NEVER a bug in this script's window/timestamp matching logic.
`agents/core/src/main.cpp` never calls `logger->flush_on(...)` on the --log-file sink, and
spdlog's own default `flush_level_` is `level::off` - confirmed against the vendored header,
not assumed - so a log line's embedded timestamp is accurate at write time, but the
underlying bytes can sit unflushed for an unpredictable period (measured live: from ~2s up to
~108s under this rig's ambient log volume) before becoming visible to ANY external reader,
this script included. See ROOT_CAUSED_T0_TIMEOUT/ROOT_CAUSED_T1_TIMEOUT below - the fix is a
timeout wide enough to outlast flush lag, not different search logic. This is a real property
of the agent's --log-file output worth flagging as its own product finding (live-tailing
--log-file for near-real-time diagnostics is unreliable without a flush policy) - not filed
as an issue by this diagnostic; left for whoever picks that up next.
"""

import argparse
import json
import os
import re
import shlex
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import generate_resgate_load as G  # noqa: E402

BASE = G.BASE
SCRATCH_DIR = os.environ.get("YUZU_BLACKOUT_SCRATCH", "/tmp/blackout-diag")
os.makedirs(SCRATCH_DIR, exist_ok=True)

DGRHP_SSH = os.environ.get("YUZU_DGRHP_SSH", "")
AGENT_LOG = os.environ.get("YUZU_AGENT_LOG", r"C:\rigA\logs\agent.log")

COHORT_PREFIX = "blackout-"
COHORT_N = 20  # 20 file + 20 registry + 20 service = 60
COHORT_BASELINE = "blackout-cohort"
TRIGGER_RULE_ID = "blackout-trigger-rule"
TRIGGER_BASELINE = "blackout-trigger"
SCRATCH_DIR_WIN = r"C:\rigA\blackout-scratch"

RIGA_ALLOWLIST_RE = re.compile(r"^riga-")
PROTECTED_RULE_IDS = {"dgrhp-drift-test-file"}
PROTECTED_BASELINE_NAMES = {"DGRHP File Drift Test"}

LOG_TS_RE = re.compile(
    r"^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\] \[(\w+)\] \[(\d+)\] (.*)$"
)
T0_RE = re.compile(r"Guardian: full_sync cleared (\d+) prior rule\(s\)")
T0_FALLBACK_RE = re.compile(r"Received command: plugin=__guard__, action=push_rules")
T1_RE = re.compile(
    r"Guardian: apply_rules ok \(applied=(\d+), failed=(\d+), full_sync=(true|false), "
    r"generation=(\d+), total=(\d+)\)"
)
ARM_LEGACY_RE = re.compile(r"(?:file|service|registry) guard armed for rule '([^']+)'")
ARM_SPARK_RE = re.compile(r"SparkEngine: armed '([^']+)'")
BACKEND_RE = re.compile(r"detection backend = (\w+)")
NETWORK_CONNECTED_RE = re.compile(r"Guardian engine network-connected")


# --------------------------------------------------------------------------
# ssh / agent-log helpers
# --------------------------------------------------------------------------


def _ssh_argv():
    if not DGRHP_SSH:
        raise RuntimeError("YUZU_DGRHP_SSH not set")
    return ["ssh"] + shlex.split(DGRHP_SSH)


def ssh_ps(cmd_ps1, timeout=30):
    """Run a PowerShell command on DGRHP over the (assumed already-open,
    control-mastered) ssh connection. -EncodedCommand (base64 UTF-16LE) is
    used deliberately - a plain -Command string gets re-quoted by the hop
    through ssh's own argv-join + the remote shell, mangling pipes/parens
    (confirmed empirically: 'Measure-Object' is not recognized' from a
    perfectly valid PS pipeline). Encoding sidesteps that layer entirely."""
    import base64
    encoded = base64.b64encode(cmd_ps1.encode("utf-16-le")).decode("ascii")
    argv = _ssh_argv() + ["powershell.exe", "-NoProfile", "-EncodedCommand", encoded]
    # capture_output as bytes, not text=True: PowerShell 5.1's console output
    # to a redirected (non-tty) pipe is NOT reliably UTF-8 (observed a stray
    # non-UTF-8 byte from log content); decode leniently since only ASCII
    # patterns are matched against this output downstream.
    r = subprocess.run(argv, capture_output=True, timeout=timeout)
    stdout = r.stdout.decode("utf-8", errors="replace")
    stderr = r.stderr.decode("utf-8", errors="replace")
    if r.returncode != 0 and not stdout:
        raise RuntimeError(f"ssh_ps failed rc={r.returncode}: {stderr[:500]}")
    return stdout


_DGRHP_UTC_OFFSET = None  # timedelta, lazily computed once - see dgrhp_utc_offset()


def dgrhp_utc_offset():
    """DGRHP's local-clock UTC offset (a timedelta), e.g. +1h under BST.

    CRITICAL bug this exists to fix: spdlog's `%Y-%m-%d %H:%M:%S.%e` pattern
    logs LOCAL time (agent.log timestamps are DGRHP-local, i.e. BST/GMT, not
    UTC), but parse_log_line() tags every parsed timestamp with
    tzinfo=timezone.utc for convenience. That mislabeling is HARMLESS for any
    same-host comparison (B = T1-T0, T0-ordering, arm-event bracketing all
    cancel the constant offset in subtraction) but WRONG for any cross-host
    comparison: a python-side `datetime.now(timezone.utc)` used as a window
    start marker would sit an hour "in the past" relative to log lines that
    are actually only a few seconds old, once BOTH are naively compared as if
    they were the same clock - which is exactly what caused every Phase B
    repeat to falsely detect a "second T0" (it was really re-finding much
    older history, not a genuine second full_sync). Confirmed empirically:
    DGRHP raw `Get-Date` reads exactly 1h ahead of true UTC on 2026-09-06
    (BST). Compute the offset live rather than hardcoding +1h so this stays
    correct across a DST boundary.

    Fix strategy: any timestamp compared AGAINST agent-log timestamps must be
    expressed in the SAME (local-labeled-as-UTC) convention - see
    dgrhp_now(). Any timestamp that must be compared against a TRUE-UTC
    source (an event_id's embedded system_clock epoch ms, which IS real UTC
    regardless of display timezone) must have this offset subtracted back out
    - see cohort_events_d()."""
    global _DGRHP_UTC_OFFSET
    if _DGRHP_UTC_OFFSET is None:
        out = ssh_ps(
            "[System.TimeZoneInfo]::Local.GetUtcOffset([DateTime]::Now).TotalSeconds"
        ).strip()
        from datetime import timedelta
        _DGRHP_UTC_OFFSET = timedelta(seconds=float(out))
    return _DGRHP_UTC_OFFSET


def dgrhp_now():
    """'Now', expressed in the SAME local-labeled-as-UTC convention
    parse_log_line() uses - the correct thing to pass as a window-start
    marker for comparison against agent-log timestamps.

    SECOND bug this exists to fix, found live: the original implementation
    was `datetime.now(timezone.utc) + dgrhp_utc_offset()` - i.e. THIS host's
    (BigColin's) clock plus DGRHP's UTC offset. That's only correct if
    BigColin's and DGRHP's system clocks are perfectly synchronized, which
    they are NOT - measured ~200ms-1s of cross-host drift (BigColin running
    ahead), never zero. At N=62 a full_sync completes in well under a
    second, so that drift alone was enough for a repeat's own window_start_ts
    to land AFTER its own trigger's T0 line, in log-timestamp terms - every
    single Phase B/B2 repeat reported "t0_not_found" even though the trigger
    visibly worked (generation kept incrementing) and the T0 line was
    sitting right there in the tail. Fix: read DGRHP's OWN clock directly
    (one ssh round trip) instead of doing cross-host arithmetic - both the
    window marker and the log lines then come from the exact same clock, so
    no drift, of any size, can matter. A small backward safety margin
    absorbs the round-trip time between reading the clock and actually
    issuing the trigger (window_start_ts must precede the trigger, never
    equal or follow it)."""
    out = ssh_ps("Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'").strip()
    ts = datetime.strptime(out, "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=timezone.utc)
    from datetime import timedelta
    return ts - timedelta(seconds=2)


TAIL_LINES = 20000  # generous: observed peak ~115 lines/sec from the leftover riga-* outbox
                     # storm, so this covers several minutes even in the noisy pre-purge phase

# ROOT CAUSE (2026-09-07, found by deliberate live reproduction - see the run doc's "T1
# detection: the real root cause" section): the residual t0_not_found/t1_not_found false
# voids were NEVER a bug in this script's window/timestamp logic. `agents/core/src/main.cpp`
# never calls `logger->flush_on(...)` on the --log-file sink, and spdlog's own default
# `flush_level_` is `level::off` (spdlog/logger.h:311, confirmed against the vendored header,
# not assumed) - so a log LINE's embedded timestamp is recorded at message-construction time,
# but the underlying bytes can sit unflushed in the sink's buffered ofstream for an
# unpredictable period before becoming visible to ANY external reader, this driver included.
# Measured live: one repeat's T1 was visible within ~2s of being written; a later one took
# ~108s for a burst of ~93 lines (arm events + apply_rules ok) to appear on disk at once, all
# stamped within the same real-world second they were actually logged. The FIX is patience,
# not different search logic - these timeouts must comfortably exceed the worst observed
# flush lag, not the true (near-instant) completion time. A generous but still-bounded margin;
# if the real agent process ever hangs for genuinely longer than this, that IS a real void.
ROOT_CAUSED_T0_TIMEOUT = 240
ROOT_CAUSED_T1_TIMEOUT = 240


def agent_log_size():
    """Cheap O(1) file-length probe, used only to detect rotation - counting
    lines on a several-hundred-thousand-line file every poll (the original
    -Skip-based design) gets slower every call as the file grows; timestamp
    filtering on a fixed -Tail read (below) avoids that entirely."""
    out = ssh_ps(f"(Get-Item -LiteralPath '{AGENT_LOG}').Length")
    out = out.strip()
    return int(out) if out else 0


def agent_log_tail():
    """Fixed-size tail read. Callers filter to their own window by comparing
    each line's OWN embedded timestamp against a Python-side start marker -
    no line-count/byte-offset bookkeeping needed, and it stays O(TAIL_LINES)
    regardless of how large the file has grown."""
    out = ssh_ps(f"Get-Content -Path '{AGENT_LOG}' -Tail {TAIL_LINES}")
    return out.splitlines()


def parse_log_line(raw):
    m = LOG_TS_RE.match(raw)
    if not m:
        return None
    ts_str, level, thread, msg = m.groups()
    ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=timezone.utc)
    return {"ts": ts, "level": level, "thread": thread, "msg": msg, "raw": raw}


# --------------------------------------------------------------------------
# HTTP helpers (beyond generate_resgate_load's)
# --------------------------------------------------------------------------


def get_json(op, path):
    req = urllib.request.Request(BASE + path, method="GET")
    return json.loads(op.open(req, timeout=20).read().decode("utf-8"))


def get_metrics(op):
    req = urllib.request.Request(BASE + "/metrics", method="GET")
    text = op.open(req, timeout=20).read().decode("utf-8", "replace")
    out = {}
    for line in text.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        m = re.match(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^}]*\})?\s+([0-9eE+\-.]+)$", line)
        if m:
            name, labels, val = m.groups()
            out[name + (labels or "")] = float(val)
    return out


def metric_sum(metrics, prefix):
    return sum(v for k, v in metrics.items() if k.startswith(prefix))


def cohort_rule(kind, i):
    rid = f"{COHORT_PREFIX}{kind}-{i:02d}"
    if kind == "file":
        path = f"{SCRATCH_DIR_WIN}\\watch-{i:02d}.txt"
        return {
            "rule_id": rid, "name": rid, "enabled": True, "enforcement_mode": "audit",
            "severity": "low", "os_target": "windows", "scope": "",
            "spark": {"type": "file-change", "params": {"path": path}},
            "assertion": {"type": "file-exists", "params": {"path": path, "expected": "present"}},
            "remediation": {"type": "alert-only", "params": {}},
        }
    if kind == "reg":
        return {
            "rule_id": rid, "name": rid, "enabled": True, "enforcement_mode": "audit",
            "severity": "low", "os_target": "windows", "scope": "",
            "spark": {"type": "registry-change",
                      "params": {"hive": "HKCU", "key": f"SOFTWARE\\YuzuBlackout\\Key{i:02d}"}},
            "assertion": {"type": "registry-value-equals",
                          "params": {"hive": "HKCU", "key": f"SOFTWARE\\YuzuBlackout\\Key{i:02d}",
                                     "value_name": "Flag", "value_type": "REG_DWORD",
                                     "expected": "1"}},
            "remediation": {"type": "alert-only", "params": {}},
        }
    if kind == "svc":
        name = G.SERVICE_NAMES[i - 1]
        return {
            "rule_id": rid, "name": rid, "enabled": True, "enforcement_mode": "audit",
            "severity": "low", "os_target": "windows", "scope": "",
            "spark": {"type": "service-status-change", "params": {"service_name": name}},
            "assertion": {"type": "service-running", "params": {"service_name": name}},
            "remediation": {"type": "alert-only", "params": {}},
        }
    raise ValueError(kind)


def cohort_rules():
    rules = []
    for i in range(1, COHORT_N + 1):
        rules.append(cohort_rule("reg", i))
    for i in range(1, COHORT_N + 1):
        rules.append(cohort_rule("file", i))
    for i in range(1, COHORT_N + 1):
        rules.append(cohort_rule("svc", i))
    return rules


def trigger_rule():
    path = f"{SCRATCH_DIR_WIN}\\trigger.txt"
    return {
        "rule_id": TRIGGER_RULE_ID, "name": TRIGGER_RULE_ID, "enabled": True,
        "enforcement_mode": "audit", "severity": "low", "os_target": "windows", "scope": "",
        "spark": {"type": "file-change", "params": {"path": path}},
        "assertion": {"type": "file-exists", "params": {"path": path, "expected": "present"}},
        "remediation": {"type": "alert-only", "params": {}},
    }


def hbr_rule(n):
    rid = f"{COHORT_PREFIX}hbr-{n:02d}"
    path = f"{SCRATCH_DIR_WIN}\\hbr-{n:02d}.txt"
    return {
        "rule_id": rid, "name": rid, "enabled": True, "enforcement_mode": "audit",
        "severity": "low", "os_target": "windows", "scope": "",
        "spark": {"type": "file-change", "params": {"path": path}},
        "assertion": {"type": "file-exists", "params": {"path": path, "expected": "present"}},
        "remediation": {"type": "alert-only", "params": {}},
    }


# --------------------------------------------------------------------------
# inventory / purge
# --------------------------------------------------------------------------


def cmd_inventory(op, out_path=None):
    rules = get_json(op, "/api/v1/guaranteed-state/rules?limit=1000")["data"]
    baselines_html = G.list_baselines_html(op)
    baseline_ids = re.findall(
        r'href="/guardian/baseline/([A-Za-z0-9._\-]+)"[^>]*>([^<]+)</a>', baselines_html
    )
    riga_rules = sorted(r["rule_id"] for r in rules if RIGA_ALLOWLIST_RE.match(r["rule_id"]))
    riga_baselines = sorted(
        (bid, name) for bid, name in baseline_ids if RIGA_ALLOWLIST_RE.match(name)
    )
    protected_present = {
        rid: any(r["rule_id"] == rid for r in rules) for rid in PROTECTED_RULE_IDS
    }
    protected_baselines_present = {
        name: any(n == name for _, n in baseline_ids) for name in PROTECTED_BASELINE_NAMES
    }
    manifest = {
        "total_rules": len(rules),
        "riga_rule_ids": riga_rules,
        "riga_baseline_ids": [b for b, _ in riga_baselines],
        "riga_baseline_names": {b: n for b, n in riga_baselines},
        "protected_rules_present": protected_present,
        "protected_baselines_present": protected_baselines_present,
    }
    if out_path:
        with open(out_path, "w") as f:
            json.dump(manifest, f, indent=2)
    print(
        f"[inventory] total_rules={manifest['total_rules']} riga_rules={len(riga_rules)} "
        f"riga_baselines={len(riga_baselines)} protected_rules_present={protected_present} "
        f"protected_baselines_present={protected_baselines_present}"
    )
    return manifest


def cmd_purge(op, apply=False):
    manifest_path = os.path.join(SCRATCH_DIR, "purge_manifest.json")
    fresh = cmd_inventory(op, out_path=None)
    for rid, present in fresh["protected_rules_present"].items():
        if not present:
            print(f"[purge] ABORT: protected rule '{rid}' not found - refusing to proceed",
                  file=sys.stderr)
            return 1
    for name, present in fresh["protected_baselines_present"].items():
        if not present:
            print(f"[purge] ABORT: protected baseline '{name}' not found - refusing to proceed",
                  file=sys.stderr)
            return 1
    for rid in fresh["riga_rule_ids"]:
        if not RIGA_ALLOWLIST_RE.match(rid):
            print(f"[purge] ABORT: non-allowlisted id in purge set: {rid}", file=sys.stderr)
            return 1

    if not apply:
        with open(manifest_path, "w") as f:
            json.dump(fresh, f, indent=2)
        print(f"[purge] DRY RUN: would delete {len(fresh['riga_baseline_ids'])} baselines, "
              f"{len(fresh['riga_rule_ids'])} rules. Manifest written to {manifest_path}.")
        return 0

    if not os.path.exists(manifest_path):
        print("[purge] ABORT: no dry-run manifest found - run --dry-run first", file=sys.stderr)
        return 1
    with open(manifest_path) as f:
        dry = json.load(f)
    if set(dry["riga_rule_ids"]) != set(fresh["riga_rule_ids"]) or \
            set(dry["riga_baseline_ids"]) != set(fresh["riga_baseline_ids"]):
        print("[purge] ABORT: live catalogue has drifted from the --dry-run manifest - "
              "re-run --dry-run and re-verify before --apply", file=sys.stderr)
        return 1

    failed_baselines, failed_rules = [], []
    for i, bid in enumerate(fresh["riga_baseline_ids"], 1):
        try:
            G.delete_baseline_form(op, bid)
        except Exception as e:  # noqa: BLE001
            print(f"[purge] baseline delete FAILED {bid}: {e}", file=sys.stderr)
            failed_baselines.append(bid)
        if i % 10 == 0 or i == len(fresh["riga_baseline_ids"]):
            print(f"[purge] baselines {i}/{len(fresh['riga_baseline_ids'])}")
    for i, rid in enumerate(fresh["riga_rule_ids"], 1):
        if not G.delete_rule(op, rid):
            failed_rules.append(rid)
        if i % 500 == 0 or i == len(fresh["riga_rule_ids"]):
            print(f"[purge] rules {i}/{len(fresh['riga_rule_ids'])}")

    post = cmd_inventory(op, out_path=None)
    ok = (
        len(post["riga_rule_ids"]) == 0
        and len(post["riga_baseline_ids"]) == 0
        and all(post["protected_rules_present"].values())
        and all(post["protected_baselines_present"].values())
    )
    print(f"[purge] DONE. failed_baselines={len(failed_baselines)} "
          f"failed_rules={len(failed_rules)} post_riga_rules={len(post['riga_rule_ids'])} "
          f"post_riga_baselines={len(post['riga_baseline_ids'])} clean={ok}")
    return 0 if ok else 1


def prepare_cohort_targets():
    """Pre-create every watched target in its EXPECTED-compliant state before
    arming - without this, file/registry rules never reach `guard.compliant`
    (found live: cmd_ensure originally skipped this, unlike
    generate_resgate_load.py's own cmd_arm, so D's functional-validity check
    could never pass). Service rules need no setup - they watch real,
    near-universally-running Windows services."""
    ps = f"""
New-Item -ItemType Directory -Force -Path '{SCRATCH_DIR_WIN}' | Out-Null
for ($i=1; $i -le {COHORT_N}; $i++) {{
    $n = $i.ToString('00')
    New-Item -ItemType File -Force -Path "{SCRATCH_DIR_WIN}\\watch-$n.txt" | Out-Null
    $key = "HKCU:\\SOFTWARE\\YuzuBlackout\\Key$n"
    New-Item -Path $key -Force | Out-Null
    New-ItemProperty -Path $key -Name 'Flag' -Value 1 -PropertyType DWord -Force | Out-Null
}}
New-Item -ItemType File -Force -Path "{SCRATCH_DIR_WIN}\\trigger.txt" | Out-Null
for ($n=1; $n -le 3; $n++) {{
    New-Item -ItemType File -Force -Path ("{SCRATCH_DIR_WIN}\\hbr-{{0:00}}.txt" -f $n) | Out-Null
}}
Write-Output "prepared"
"""
    out = ssh_ps(ps, timeout=30)
    if "prepared" not in out:
        raise RuntimeError(f"prepare_cohort_targets failed: {out[:500]}")


def cmd_ensure(op):
    os.makedirs(SCRATCH_DIR, exist_ok=True)
    prepare_cohort_targets()
    rules = cohort_rules()
    failed, reused = G._post_all(op, rules)
    cohort_baseline_id = G.ensure_deployed_baseline(
        op, COHORT_BASELINE, [r["name"] for r in rules]
    )
    trig = trigger_rule()
    G.post_rule(op, trig)
    trigger_baseline_id = G.ensure_deployed_baseline(op, TRIGGER_BASELINE, [trig["name"]])
    print(f"[ensure] armed {len(rules) - failed}/{len(rules)} cohort rules ({reused} reused), "
          f"cohort baseline {COHORT_BASELINE} ({cohort_baseline_id}), "
          f"trigger baseline {TRIGGER_BASELINE} ({trigger_baseline_id})")
    return 1 if failed else 0


def cmd_teardown_cohort(op):
    G.teardown_deployed_baseline(op, TRIGGER_BASELINE)
    G.teardown_deployed_baseline(op, COHORT_BASELINE)
    for r in cohort_rules():
        G.delete_rule(op, r["rule_id"])
    G.delete_rule(op, TRIGGER_RULE_ID)
    for n in range(1, 4):
        G.delete_rule(op, f"{COHORT_PREFIX}hbr-{n:02d}")
    try:
        ssh_ps(
            f"Remove-Item -Recurse -Force -Path '{SCRATCH_DIR_WIN}' -ErrorAction SilentlyContinue; "
            f"Remove-Item -Recurse -Force -Path 'HKCU:\\SOFTWARE\\YuzuBlackout' -ErrorAction SilentlyContinue; "
            f"Write-Output done",
            timeout=30,
        )
    except Exception as e:  # noqa: BLE001
        print(f"[teardown] filesystem/registry cleanup failed (non-fatal): {e}", file=sys.stderr)
    print("[teardown] cohort/trigger baselines, rules, scratch files/registry removed")
    return 0


# --------------------------------------------------------------------------
# measurement
# --------------------------------------------------------------------------


def find_baseline_id(op, name):
    return G.find_baseline_id(G.list_baselines_html(op), name)


def _fetch_window(window_start_ts):
    """Fetch the current fixed tail, parse it, and return only lines whose OWN
    embedded timestamp is >= window_start_ts, sorted by that timestamp. A
    fresh full re-derivation each poll (not an incremental skip) - simpler and
    avoids offset bugs; O(TAIL_LINES) regardless of total file size. Also
    returns the current file size, for the caller's rotation check."""
    size = agent_log_size()
    raw_lines = agent_log_tail()
    parsed = []
    for raw in raw_lines:
        p = parse_log_line(raw)
        if p and p["ts"] >= window_start_ts:
            parsed.append(p)
    parsed.sort(key=lambda p: p["ts"])
    return parsed, size


def observe_window(window_start_ts, t0_timeout_s, t1_timeout_s, poll=2.0):
    """Poll the agent log for the first T0/T0' at or after window_start_ts,
    then the first T1 after that. Returns a dict with t0, t0_source, t1,
    arm_events, void_reason (or None)."""
    size0 = agent_log_size()
    deadline_t0 = time.time() + t0_timeout_s
    t0 = t0_source = None
    while time.time() < deadline_t0 and t0 is None:
        events, size = _fetch_window(window_start_ts)
        if size < size0:
            return {"void_reason": "log_rotated_mid_window"}
        for p in events:
            if T0_RE.search(p["msg"]):
                t0, t0_source = p, "cleared"
                break
        if t0 is None:
            for p in events:
                if T0_FALLBACK_RE.search(p["msg"]):
                    t0, t0_source = p, "fallback"
                    break
        if t0 is not None:
            break
        time.sleep(poll)
    if t0 is None:
        return {"void_reason": "t0_not_found"}

    deadline_t1 = time.time() + t1_timeout_s
    t1 = t1_groups = None
    arm_events = []
    second_t0 = False
    while time.time() < deadline_t1 and t1 is None:
        events, size = _fetch_window(window_start_ts)
        if size < size0:
            return {"void_reason": "log_rotated_mid_window"}
        after_t0 = [p for p in events if p["ts"] >= t0["ts"]]
        if any(T0_RE.search(p["msg"]) and p["ts"] > t0["ts"] for p in after_t0):
            second_t0 = True
        arm_events = [p for p in after_t0
                      if ARM_LEGACY_RE.search(p["msg"]) or ARM_SPARK_RE.search(p["msg"])]
        for p in after_t0:
            m = T1_RE.search(p["msg"])
            if m:
                t1, t1_groups = p, m.groups()
                break
        if t1 is not None:
            break
        time.sleep(poll)
    if second_t0:
        return {"void_reason": "double_full_sync"}
    if t1 is None:
        return {"void_reason": "t1_not_found"}
    # keep only arm events that precede t1 (a poll can race past t1's own instant)
    arm_events = [p for p in arm_events if p["ts"] <= t1["ts"]]

    applied, failed, full_sync, generation, total = t1_groups
    return {
        "void_reason": None,
        "t0": t0, "t0_source": t0_source, "t1": t1,
        "applied": int(applied), "failed": int(failed),
        "full_sync": full_sync, "generation": int(generation), "total": int(total),
        "arm_events": arm_events,
    }


def cohort_events_d(op, rule_ids, t0_dt, deadline_ms):
    # t0_dt is a log-native timestamp (local-labeled-as-UTC, see
    # dgrhp_utc_offset()) but event_id's embedded ms is a REAL UTC epoch
    # (std::chrono::system_clock, unaffected by display timezone) - subtract
    # the offset back out before comparing, or every lookup here silently
    # searches the wrong hour and reports "not_observed" for everything.
    t0_ms = int(t0_dt.timestamp() * 1000) - int(dgrhp_utc_offset().total_seconds() * 1000)
    by_rule = {}
    for rid in rule_ids:
        try:
            data = get_json(op, f"/api/v1/guaranteed-state/events?rule_id={rid}&limit=10")["data"]
        except Exception:  # noqa: BLE001
            by_rule[rid] = "not_observed"
            continue
        found = None
        for ev in data:
            if ev.get("event_type") != "guard.compliant":
                continue
            m = re.search(r"-(\d{13})-\d+$", ev.get("event_id", ""))
            if not m:
                continue
            ms = int(m.group(1))
            if t0_ms <= ms <= t0_ms + deadline_ms:
                if found is None or ms < found:
                    found = ms
        by_rule[rid] = (found - t0_ms) if found is not None else "not_observed"
    return by_rule


def run_repeat(op, phase, backend, trigger_kind, cohort_ids, repeat_idx, trigger_id_cache):
    m0 = get_metrics(op)
    window_start_ts = dgrhp_now()  # NOT datetime.now(timezone.utc) - see dgrhp_utc_offset()
    trig_ts = time.time()
    http_status = None
    if trigger_kind == "deploy":
        try:
            G.deploy_baseline_form(op, trigger_id_cache["trigger_baseline_id"])
            http_status = 200
        except Exception as e:  # noqa: BLE001
            return {"phase": phase, "backend": backend, "repeat": repeat_idx,
                     "void_reason": f"trigger_failed:{e}"}
        t0_timeout, t1_timeout = ROOT_CAUSED_T0_TIMEOUT, ROOT_CAUSED_T1_TIMEOUT
    else:
        n = trigger_id_cache["hbr_counter"]
        trigger_id_cache["hbr_counter"] += 1
        rule = hbr_rule(n)
        try:
            _, existed = G.post_rule(op, rule)
            http_status = 200 if existed else 201
        except Exception as e:  # noqa: BLE001
            return {"phase": phase, "backend": backend, "repeat": repeat_idx,
                     "void_reason": f"trigger_failed:{e}"}
        t0_timeout, t1_timeout = ROOT_CAUSED_T0_TIMEOUT, ROOT_CAUSED_T1_TIMEOUT

    obs = observe_window(window_start_ts, t0_timeout, t1_timeout)
    if obs.get("void_reason"):
        return {"phase": phase, "backend": backend, "repeat": repeat_idx,
                "trigger_http_status": http_status, "void_reason": obs["void_reason"]}

    t0, t1 = obs["t0"], obs["t1"]
    b_ms = (t1["ts"] - t0["ts"]).total_seconds() * 1000
    arm_events = obs["arm_events"]
    first_arm = arm_events[0] if arm_events else None
    last_arm = arm_events[-1] if arm_events else None
    pre_first_arm_ms = (first_arm["ts"] - t0["ts"]).total_seconds() * 1000 if first_arm else None
    first_to_last_arm_ms = (
        (last_arm["ts"] - first_arm["ts"]).total_seconds() * 1000
        if first_arm and last_arm and last_arm is not first_arm else 0.0
    ) if first_arm else None
    post_last_arm_ms = (
        (t1["ts"] - last_arm["ts"]).total_seconds() * 1000 if last_arm else None
    )

    m1 = get_metrics(op)
    reconcile_sent_delta = metric_sum(m1, 'yuzu_server_guardian_reconciles_total{result="sent"}') \
        - metric_sum(m0, 'yuzu_server_guardian_reconciles_total{result="sent"}')
    pushes_policy_change_delta = (
        metric_sum(m1, 'yuzu_server_guardian_pushes_dispatched_total{reason="policy_change"}')
        - metric_sum(m0, 'yuzu_server_guardian_pushes_dispatched_total{reason="policy_change"}')
    )

    phase_is_clean_verdict = phase in ("B", "B2")
    void_reason = None
    if phase_is_clean_verdict:
        if obs["failed"] > 0:
            void_reason = "failed_gt_0"
        elif obs["applied"] != obs["total"]:
            void_reason = "applied_ne_total"
        elif not arm_events:
            void_reason = "zero_arm_lines"
        elif phase == "B" and (reconcile_sent_delta != 0 or pushes_policy_change_delta != 1):
            void_reason = (f"push_counter_mismatch(reconcile_sent_delta="
                            f"{reconcile_sent_delta},pushes_delta={pushes_policy_change_delta})")
        elif phase == "B2" and (reconcile_sent_delta != 1 or pushes_policy_change_delta != 0):
            void_reason = (f"push_counter_mismatch(reconcile_sent_delta="
                            f"{reconcile_sent_delta},pushes_delta={pushes_policy_change_delta})")

    deadline_ms = max(2 * b_ms, 30000)
    d_by_rule = cohort_events_d(op, cohort_ids, t0["ts"], deadline_ms)
    functional_valid = all(v != "not_observed" for v in d_by_rule.values())
    d_ms = max((v for v in d_by_rule.values() if isinstance(v, (int, float))), default=None)

    # t0["ts"] is log-native (local-labeled-as-UTC); trig_ts is a true
    # time.time() epoch from this (BigColin) host - convert t0 back to true
    # UTC before diffing, same correction as cohort_events_d. Still an
    # uncalibrated cross-host interval (informational only, not
    # verdict-bearing) - two different machines' clocks, not two
    # differently-labeled reads of the same one.
    t0_true_epoch = t0["ts"].timestamp() - dgrhp_utc_offset().total_seconds()
    create_to_t0_lag_ms = ((t0_true_epoch - trig_ts) * 1000) if trigger_kind == "rule-create" else None

    return {
        "phase": phase, "backend": backend, "repeat": repeat_idx,
        "t0_source": obs["t0_source"], "t0": t0["ts"].isoformat(), "t1": t1["ts"].isoformat(),
        "generation": obs["generation"], "cleared": None, "applied": obs["applied"],
        "failed": obs["failed"], "total": obs["total"], "b_ms": b_ms,
        "pre_first_arm_ms": pre_first_arm_ms, "first_to_last_arm_ms": first_to_last_arm_ms,
        "post_last_arm_ms": post_last_arm_ms, "n_arm_lines": len(arm_events),
        "compliant_restored_ms_by_rule": d_by_rule, "d_ms_max": d_ms,
        "functional_valid": functional_valid,
        "reconcile_sent_delta": reconcile_sent_delta,
        "pushes_policy_change_delta": pushes_policy_change_delta,
        "trigger_http_status": http_status,
        "create_to_t0_lag_ms": create_to_t0_lag_ms,
        "void_reason": void_reason,
    }


def observe_phase_a_window(window_start_ts):
    """Phase A: no trigger, no clean-cohort void rules - observe ONE naturally
    occurring T0->T1 window from the leftover riga-* storm. failed>0 and
    applied!=total are EXPECTED data here, never a void."""
    size0 = agent_log_size()
    deadline_t0 = time.time() + 1200  # 20 min hard cap handled by the caller's own loop budget
    t0 = t0_source = None
    while time.time() < deadline_t0 and t0 is None:
        events, size = _fetch_window(window_start_ts)
        if size < size0:
            return {"void_reason": "log_rotated_mid_window"}
        for p in events:
            if T0_RE.search(p["msg"]):
                t0, t0_source = p, "cleared"
                break
        if t0 is None:
            for p in events:
                if T0_FALLBACK_RE.search(p["msg"]):
                    t0, t0_source = p, "fallback"
                    break
        if t0 is not None:
            break
        time.sleep(2)
    if t0 is None:
        return {"void_reason": "t0_not_found_in_cap"}

    deadline_t1 = time.time() + 120
    t1 = t1_groups = None
    arm_events = []
    while time.time() < deadline_t1 and t1 is None:
        events, size = _fetch_window(window_start_ts)
        if size < size0:
            return {"void_reason": "log_rotated_mid_window"}
        after_t0 = [p for p in events if p["ts"] >= t0["ts"]]
        arm_events = [p for p in after_t0
                      if ARM_LEGACY_RE.search(p["msg"]) or ARM_SPARK_RE.search(p["msg"])]
        for p in after_t0:
            m = T1_RE.search(p["msg"])
            if m:
                t1, t1_groups = p, m.groups()
                break
        if t1 is not None:
            break
        time.sleep(2)
    if t1 is None:
        return {"void_reason": "t1_not_found_within_120s_of_t0"}
    arm_events = [p for p in arm_events if p["ts"] <= t1["ts"]]

    applied, failed, full_sync, generation, total = t1_groups
    b_ms = (t1["ts"] - t0["ts"]).total_seconds() * 1000
    return {
        "void_reason": None, "t0_source": t0_source, "t0": t0["ts"].isoformat(),
        "t1": t1["ts"].isoformat(), "generation": int(generation), "applied": int(applied),
        "failed": int(failed), "total": int(total), "b_ms": b_ms, "n_arm_lines": len(arm_events),
        "next_window_start": t1["ts"],
    }


def cmd_run_phase_a(op, backend, label, out_path, cap_seconds=1200, target_windows=3):
    """Storm-observed windows on the leftover uncontrolled catalogue - no
    deploy trigger (would never settle: failed riga-* rules hold the
    generation, so the server reconcile-pushes on its own ~every 25s)."""
    start = time.time()
    results = []
    window_start_ts = dgrhp_now()  # NOT datetime.now(timezone.utc) - see dgrhp_utc_offset()
    while len(results) < target_windows and (time.time() - start) < cap_seconds:
        obs = observe_phase_a_window(window_start_ts)
        window_start_ts = obs.get("next_window_start") or dgrhp_now()
        obs.pop("next_window_start", None)
        obs.update({"phase": "A", "backend": backend, "label": label,
                     "repeat": len(results) + 1})
        results.append(obs)
        status = "VOID:" + obs["void_reason"] if obs.get("void_reason") else \
            f"b_ms={obs['b_ms']:.1f} applied={obs['applied']} failed={obs['failed']} total={obs['total']}"
        print(f"[run-a] {label} {backend} window={len(results)} {status}")
        if obs.get("void_reason") in ("log_rotated_mid_window",):
            break
    elapsed = time.time() - start
    with open(out_path, "a") as f:
        for r in results:
            f.write(json.dumps(r) + "\n")
    print(f"[run-a] {label} {backend} DONE windows={len(results)} elapsed_s={elapsed:.0f} "
          f"cap_hit={elapsed >= cap_seconds}")
    return 0


def cmd_run(op, phase, backend, trigger_kind, repeats, gap, label, out_path):
    trigger_id_cache = {"hbr_counter": 1}
    if trigger_kind == "deploy":
        tb = find_baseline_id(op, TRIGGER_BASELINE)
        if not tb:
            raise RuntimeError(f"trigger baseline '{TRIGGER_BASELINE}' not found - run 'ensure' first")
        trigger_id_cache["trigger_baseline_id"] = tb
    cohort_ids = [r["rule_id"] for r in cohort_rules()]

    results = []
    valid = 0
    attempts = 0
    max_attempts = repeats * 2  # cap: 10 for K=5, 6 for K=3 - "up to a cap of 10 attempts" for K=5
    while valid < repeats and attempts < max(max_attempts, 10):
        attempts += 1
        r = run_repeat(op, phase, backend, trigger_kind, cohort_ids, attempts, trigger_id_cache)
        results.append(r)
        status = "VOID:" + r["void_reason"] if r.get("void_reason") else \
            f"b_ms={r['b_ms']:.1f}"
        print(f"[run] {label} {backend} {phase} attempt={attempts} {status}")
        if not r.get("void_reason"):
            valid += 1
        if valid < repeats:
            time.sleep(gap)

    inconclusive = valid < repeats
    with open(out_path, "a") as f:
        for r in results:
            f.write(json.dumps({**r, "label": label}) + "\n")
    print(f"[run] {label} {backend} {phase} DONE valid={valid}/{repeats} "
          f"attempts={attempts} inconclusive={inconclusive}")
    return 0


def cmd_report(in_path, out_md_path):
    rows = []
    with open(in_path) as f:
        for line in f:
            rows.append(json.loads(line))
    groups = {}
    for r in rows:
        if r.get("void_reason"):
            continue
        key = (r["label"], r["backend"], r["phase"])
        groups.setdefault(key, []).append(r["b_ms"])
    lines = ["| Label | Backend | Phase | valid N | B min (ms) | B median (ms) | B max (ms) |",
             "|---|---|---|---|---|---|---|"]
    for (label, backend, phase), vals in sorted(groups.items()):
        lines.append(
            f"| {label} | {backend} | {phase} | {len(vals)} | {min(vals):.1f} | "
            f"{statistics.median(vals):.1f} | {max(vals):.1f} |"
        )
    with open(out_md_path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print("\n".join(lines))
    return 0


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("inventory")

    p = sub.add_parser("purge")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--apply", action="store_true")

    sub.add_parser("ensure")
    sub.add_parser("teardown-cohort")

    p = sub.add_parser("run")
    p.add_argument("--backend", required=True, choices=["legacy", "spark"])
    p.add_argument("--phase", required=True, choices=["A", "B", "B2"])
    p.add_argument("--trigger", required=True, choices=["deploy", "rule-create", "none"])
    p.add_argument("--repeats", type=int, default=5)
    p.add_argument("--gap", type=int, default=45)
    p.add_argument("--label", required=True)
    p.add_argument("--out", default=os.path.join(SCRATCH_DIR, "results.jsonl"))

    p = sub.add_parser("report")
    p.add_argument("--in", dest="in_path", default=os.path.join(SCRATCH_DIR, "results.jsonl"))
    p.add_argument("--out", default=os.path.join(SCRATCH_DIR, "report.md"))

    args = ap.parse_args()
    op = G.make_opener()
    G.login(op)

    if args.cmd == "inventory":
        cmd_inventory(op, out_path=os.path.join(SCRATCH_DIR, "inventory.json"))
        return 0
    if args.cmd == "purge":
        return cmd_purge(op, apply=args.apply)
    if args.cmd == "ensure":
        return cmd_ensure(op)
    if args.cmd == "teardown-cohort":
        return cmd_teardown_cohort(op)
    if args.cmd == "run":
        if args.phase == "A":
            return cmd_run_phase_a(op, args.backend, args.label, args.out)
        return cmd_run(op, args.phase, args.backend, args.trigger, args.repeats, args.gap,
                        args.label, args.out)
    if args.cmd == "report":
        return cmd_report(args.in_path, args.out)
    return 1


if __name__ == "__main__":
    sys.exit(main())
