#!/usr/bin/env python3
"""#3990 full_sync blackout diagnostic driver (ruling-13 on #3850).

One-time rig-scoped instrument, not production tooling (see the plan's
"Sol feedback declined" section for why this stays simple rather than
production-hardened). Measures B = T1 - T0 (log interval, continuity only)
and C = T2_last - T0 (primary measurand, R5.7) on a single Windows agent
under two detection backends (legacy IGuard vs spark), triggered two ways:
a baseline (re)deploy, and a bare rule-create in no baseline (the
heartbeat-reconcile trigger that is #3990's own literal shape).

See docs/spark-rebuild-baselines/3990-fullsync-blackout-run.md for the
measurand definitions, void rules, and decision criterion this implements -
this file is the mechanism, that doc is the record of what it measured.

Environment: YUZU_BASE (default http://127.0.0.1:8130), YUZU_ADMIN_USER,
YUZU_ADMIN_PASS (defaults match generate_resgate_load.py's UAT defaults -
override for a non-default rig). YUZU_DGRHP_SSH (ssh destination for the
agent-log reads, e.g. "-S /tmp/sock -i ~/.ssh/key user@host" as a single
pre-built arg string), YUZU_AGENT_LOG (default C:\\rigA\\logs\\agent.log).

PARTIALLY FIXED 2026-09-07 (see docs/spark-rebuild-baselines/3990-fullsync-blackout-run.md,
"T1 detection: the real root cause"): much of the t0_not_found/t1_not_found false-void rate
from the 2026-09-06/07 run is explained by a flush-lag gap, not this script's window/timestamp
matching logic. `agents/core/src/main.cpp` never calls `logger->flush_on(...)` on the
--log-file sink, and spdlog's own default `flush_level_` is `level::off` - confirmed against
the vendored header, not assumed - so a log line's embedded timestamp is accurate at write
time, but the underlying bytes can sit unflushed for an unpredictable period (measured live:
from ~2s up to ~108s) before becoming visible to ANY external reader, this script included.
Widened ROOT_CAUSED_T0_TIMEOUT/ROOT_CAUSED_T1_TIMEOUT to compensate - a bounded workaround for
this one-time measurement, NOT a proven-reliable fix.

FIXED 2026-09-07: `run_repeat()` folds `functional_valid` into `void_reason` itself for the
clean-verdict phases (B/B2). Cohort service-watch targets use `BLACKOUT_SVC_OVERRIDE` (5
services confirmed live, replacing 5 confirmed Stopped on DGRHP).

R5.7 T2 RE-MEASUREMENT (2026-09-19, rung 9c PR-6 item 2 - see
docs/spark-stage2-guardian-consumer-design.md "R5.7 - Re-measurement methodology"):
Window B alone is no longer a valid proxy for spark's real arm-completion latency on current
`origin/dev` - rung 9c PR-2 added `pending=` to the `apply_rules ok` line and moved
`reconcile_rule_locked()` to a NonWaiting attach model, so T1 no longer waits for every rule's
arm to commit. This round adds:
  - dev-shape T1_RE (six groups, `pending=` included).
  - T0D_RE: a new runtime log line, `Guardian spark: detach_all complete (epoch=,
    incarnation_floor=, detached_rules=, withdrawn_claims=)`, emitted as the LAST statement of
    `GuardianSparkRuntime::detach_all()`'s locked block. `epoch` is a monotonic per-application
    counter (`detach_epoch_`), `incarnation_floor` is `gen_counter_` at teardown time.
  - T2_RE: a new runtime log line, `Guardian spark: arm committed for rule '<id>' (epoch=,
    incarnation=, type=, via=, attach_to_commit_ms=)`, the LAST statement of
    `GuardianSparkRuntime::commit_new_generation_locked()` - the only valid log-side proxy for
    "this rule is armed" under spark. `epoch` names which application (full_sync teardown) the
    commit belongs to; membership is decided by EPOCH IDENTITY, never by timestamp order (a
    previous application's stale in-flight callback can otherwise land between the new
    `full_sync cleared` line and `detach_all()` and get miscounted - found by an Astra
    adversarial review of this round's design, independently confirmed against source before
    being folded in).
  - C = T2_last - T0 is now the HEADLINE measurand; B is reported for continuity only and no
    longer brackets synchronous arm completion under the NonWaiting model - a drop in B versus
    the historical clean-v2 numbers is a MODEL CHANGE, not an improvement, and must not be
    reported as one.
  - Two-class void taxonomy (instrument-invalid vs genuine failure), `run_id`-scoped Phase B2
    trigger ids (closes a real trigger-ID-reuse trap the existing run doc already documented),
    bounded functional-validity polling, and an offline `selftest` subcommand (run BEFORE any
    server login) covering the fence logic end to end.

KNOWN BUG, FIXED THIS ROUND: `cmd_report`'s grouping previously could not distinguish rows from
two different `run` invocations sharing the same label. Every row now carries `run_id` and
`comparison_id`; grouping and the printed report key on both.

This is a real property of the agent's --log-file output worth flagging as its own product
finding (live-tailing --log-file for near-real-time diagnostics is unreliable without a flush
policy) - not filed as an issue by this diagnostic; left for whoever picks that up next.
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
from datetime import datetime, timedelta, timezone

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

# 1-indexed override of G.SERVICE_NAMES for THIS script's cohort only - see the "FIXED
# 2026-09-07" docstring note above for why (Spooler/Themes/BITS/wuauserv/W32Time confirmed
# Stopped on DGRHP, live-checked before picking these replacements).
BLACKOUT_SVC_OVERRIDE = {1: "LSM", 2: "DcomLaunch", 4: "RpcEptMapper", 5: "nsi", 15: "SamSs"}

RIGA_ALLOWLIST_RE = re.compile(r"^riga-")
PROTECTED_RULE_IDS = {"dgrhp-drift-test-file"}
PROTECTED_BASELINE_NAMES = {"DGRHP File Drift Test"}

LOG_TS_RE = re.compile(
    r"^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\] \[(\w+)\] \[(\d+)\] (.*)$"
)
T0_RE = re.compile(r"Guardian: full_sync cleared (\d+) prior rule\(s\)")
T0_FALLBACK_RE = re.compile(r"Received command: plugin=__guard__, action=push_rules")
PUSH_CMD_RE = T0_FALLBACK_RE  # same line; R5.7 role: an OBSERVED push command, not a T0
T1_RE = re.compile(
    r"Guardian: apply_rules ok \(applied=(\d+), failed=(\d+), pending=(\d+), "
    r"full_sync=(true|false), generation=(\d+), total=(\d+)\)"
)
T0D_RE = re.compile(
    r"Guardian spark: detach_all complete \(epoch=(\d+), incarnation_floor=(\d+), "
    r"detached_rules=(\d+), withdrawn_claims=(\d+)\)"
)
T2_RE = re.compile(
    r"Guardian spark: arm committed for rule '([^']+)' \(epoch=(\d+), "
    r"incarnation=(\d+), type=([\w-]+), via=([\w-]+), attach_to_commit_ms=(\d+)\)"
)
ARM_LEGACY_RE = re.compile(r"(?:file|service|registry) guard armed for rule '([^']+)'")
ARM_SPARK_RE = re.compile(r"SparkEngine: armed '([^']+)'")
BACKEND_RE = re.compile(r"detection backend = (\w+)")
NETWORK_CONNECTED_RE = re.compile(r"Guardian engine network-connected")

# Void taxonomy (R5.7 round 2, §2.2 item 3). Instrument-invalid: the instrument, not the
# system, failed - reported, never counted, never held against reliability. Genuine failure:
# the system did not do what the push asked - counts against the phase's reliability gate AND
# is a product finding. `trigger_failed:*` is matched by prefix, not listed here.
INSTRUMENT_INVALID_REASONS = frozenset({
    "t0_not_found", "t0d_not_found", "t1_not_found", "t2_incomplete", "t2_late",
    "log_rotated_mid_window", "trigger_not_created", "repush_confound",
    "applied_ne_total", "double_full_sync", "cohort_composition", "teardown_size_mismatch",
})
GENUINE_FAILURE_REASONS = frozenset({
    "failed_gt_0", "arm_never_confirmed", "functional_invalid", "fence_violation",
})


def void_class_for(reason):
    if reason is None:
        return None
    if reason in GENUINE_FAILURE_REASONS:
        return "genuine"
    return "instrument"


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
    r = subprocess.run(argv, capture_output=True, timeout=timeout)
    stdout = r.stdout.decode("utf-8", errors="replace")
    stderr = r.stderr.decode("utf-8", errors="replace")
    if r.returncode != 0 and not stdout:
        raise RuntimeError(f"ssh_ps failed rc={r.returncode}: {stderr[:500]}")
    return stdout


_DGRHP_UTC_OFFSET = None  # timedelta, lazily computed once - see dgrhp_utc_offset()


def dgrhp_utc_offset():
    """DGRHP's local-clock UTC offset (a timedelta), e.g. +1h under BST. See the
    original docstring history in git blame for why this is computed live rather
    than hardcoded - unchanged this round."""
    global _DGRHP_UTC_OFFSET
    if _DGRHP_UTC_OFFSET is None:
        out = ssh_ps(
            "[System.TimeZoneInfo]::Local.GetUtcOffset([DateTime]::Now).TotalSeconds"
        ).strip()
        _DGRHP_UTC_OFFSET = timedelta(seconds=float(out))
    return _DGRHP_UTC_OFFSET


def dgrhp_now():
    """'Now', expressed in the SAME local-labeled-as-UTC convention
    parse_log_line() uses - read DGRHP's own clock directly (one ssh round
    trip) rather than doing cross-host arithmetic, which drifts. A small
    backward safety margin absorbs the round-trip time between reading the
    clock and actually issuing the trigger. Unchanged this round."""
    out = ssh_ps("Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'").strip()
    ts = datetime.strptime(out, "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=timezone.utc)
    return ts - timedelta(seconds=2)


TAIL_LINES = 20000  # generous: observed peak ~115 lines/sec from the leftover riga-* outbox
                     # storm, so this covers several minutes even in the noisy pre-purge phase.
                     # R5.7: also ample for the clean-cohort B/B2 burst (~62 SparkEngine armed
                     # + 62 T2 + T0/T0d/T1 + evals); NOT ample at the Phase-A storm rate - see
                     # tail_saturated tracking in observe_t0().

ROOT_CAUSED_T0_TIMEOUT = 240
ROOT_CAUSED_T1_TIMEOUT = 240
ROOT_CAUSED_T0D_TIMEOUT = 240
ROOT_CAUSED_T2_VISIBILITY_TIMEOUT = 240


def agent_log_size():
    """Cheap O(1) file-length probe, used only to detect rotation."""
    out = ssh_ps(f"(Get-Item -LiteralPath '{AGENT_LOG}').Length")
    out = out.strip()
    return int(out) if out else 0


def agent_log_tail():
    """Fixed-size tail read. Callers filter to their own window by comparing
    each line's OWN embedded timestamp against a Python-side start marker."""
    out = ssh_ps(f"Get-Content -Path '{AGENT_LOG}' -Tail {TAIL_LINES}")
    return out.splitlines()


def parse_log_line(raw):
    m = LOG_TS_RE.match(raw)
    if not m:
        return None
    ts_str, level, thread, msg = m.groups()
    ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=timezone.utc)
    return {"ts": ts, "level": level, "thread": thread, "msg": msg, "raw": raw}


def _ev(ts_str, msg, raw=None):
    """Construct a parsed-event-shaped dict directly, for selftest fixtures -
    bypasses parse_log_line/LOG_TS_RE so fixtures don't need a fully-formed
    `[ts] [level] [thread] msg` line, just the two fields the classification
    logic actually reads (ts, msg), plus an optional distinct `raw` for
    identity-based tests (F9's same-ms-tie case)."""
    ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=timezone.utc)
    return {"ts": ts, "level": "info", "thread": "1", "msg": msg, "raw": raw if raw is not None else msg}


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


# --------------------------------------------------------------------------
# cohort / rule builders
# --------------------------------------------------------------------------


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
        name = BLACKOUT_SVC_OVERRIDE.get(i, G.SERVICE_NAMES[i - 1])
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


def expected_rule_ids():
    """R5.7: the closed 62-member set every full_sync in this diagnostic's
    cohort should re-arm (60 cohort + trigger + the pre-existing protected
    rule, which rides along on every full_sync regardless of what this
    diagnostic itself created)."""
    return set(r["rule_id"] for r in cohort_rules()) | {TRIGGER_RULE_ID} | set(PROTECTED_RULE_IDS)


def trigger_rule():
    path = f"{SCRATCH_DIR_WIN}\\trigger.txt"
    return {
        "rule_id": TRIGGER_RULE_ID, "name": TRIGGER_RULE_ID, "enabled": True,
        "enforcement_mode": "audit", "severity": "low", "os_target": "windows", "scope": "",
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
    arming. R5.7: no longer statically pre-creates hbr-NN.txt files here -
    hbr rule ids/paths are now run_id-scoped (hbr_rule()), unknown until
    cmd_run() mints a run_id, so their watch files are touched per-repeat in
    run_repeat() instead (_touch_win_file())."""
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
Write-Output "prepared"
"""
    out = ssh_ps(ps, timeout=30)
    if "prepared" not in out:
        raise RuntimeError(f"prepare_cohort_targets failed: {out[:500]}")


def _touch_win_file(path):
    out = ssh_ps(f"New-Item -ItemType File -Force -Path '{path}' | Out-Null; Write-Output done",
                 timeout=15)
    if "done" not in out:
        raise RuntimeError(f"_touch_win_file failed for {path}: {out[:300]}")


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
    # R5.7: sweep EVERY blackout-hbr-* rule by catalogue query, not a fixed id range -
    # run_id-scoped ids from possibly several invocations (including void attempts) can
    # otherwise be left behind (the exact class of leftover the existing run doc's
    # "hbr-01..03 -> hbr-04..06" teardown miss already documented).
    rules = get_json(op, "/api/v1/guaranteed-state/rules?limit=1000")["data"]
    hbr_ids = sorted(r["rule_id"] for r in rules if r["rule_id"].startswith(f"{COHORT_PREFIX}hbr-"))
    for rid in hbr_ids:
        G.delete_rule(op, rid)
    print(f"[teardown] deleted {len(hbr_ids)} blackout-hbr-* rule(s): {hbr_ids}")
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


def hbr_rule(run_id, n):
    """R5.7 fix: rule_id (and watched path) are now run_id-scoped
    (`blackout-hbr-<run_id>-NN`), closing a real trigger-ID-reuse trap the
    existing run doc already documented (hbr_counter resets to 1 every
    cmd_run invocation, so two invocations used to collide on the same
    rule_id and a 409 silently meant "no new rule created")."""
    rid = f"{COHORT_PREFIX}hbr-{run_id}-{n:02d}"
    path = f"{SCRATCH_DIR_WIN}\\hbr-{run_id}-{n:02d}.txt"
    return {
        "rule_id": rid, "name": rid, "enabled": True, "enforcement_mode": "audit",
        "severity": "low", "os_target": "windows", "scope": "",
        "spark": {"type": "file-change", "params": {"path": path}},
        "assertion": {"type": "file-exists", "params": {"path": path, "expected": "present"}},
        "remediation": {"type": "alert-only", "params": {}},
    }


# --------------------------------------------------------------------------
# measurement - pure functions (no SSH/HTTP; directly selftest-able)
# --------------------------------------------------------------------------


def _fetch_window(window_start_ts):
    """Fetch the current fixed tail, parse it, and return only lines whose OWN
    embedded timestamp is >= window_start_ts, sorted by that timestamp. Also
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


def _find_first(events, regex, at_or_after=None, strictly_after=None):
    for p in events:
        if at_or_after is not None and p["ts"] < at_or_after:
            continue
        if strictly_after is not None and p["ts"] <= strictly_after:
            continue
        m = regex.search(p["msg"])
        if m:
            return p, m
    return None, None


def find_own_push_cmd_raw(events, t0_ts):
    """The trigger's own `Received command: ... push_rules` line, identified
    as the LAST such line at/before T0 - excluded from repush_confound
    accounting by RAW LINE CONTENT (not timestamp value), so a genuinely
    distinct second push command landing at the identical millisecond (F9)
    is still counted."""
    candidates = [p for p in events if p["ts"] <= t0_ts and PUSH_CMD_RE.search(p["msg"])]
    return candidates[-1]["raw"] if candidates else None


def classify_t2(events, epoch, floor, expected_rule_ids, own_push_raw, backend, t0_ts, t0d_ts):
    """Pure classification over an already-fetched event list (any order -
    does not assume sorted input). Membership is decided by EPOCH IDENTITY
    for spark (never by timestamp order - the R5.7 round-2 fence, closing
    the stale-prior-application gap Astra's adversarial review found in
    round 1's timestamp-only design) and by the T0d BOUNDARY for legacy
    (which has no epoch field of its own).

    Returns: selected{rid: {...}}, rejected[{line,reason}], adopt_lines[...],
    push_lines[event,...] (excluding the trigger's own line), missing[rid,...],
    legacy_before_t0d[raw,...], next_t0d_ts (the next application's T0d
    timestamp if one appears, else None - `double_full_sync` by EVENT, never
    by a bare timestamp comparison)."""
    remaining = set(expected_rule_ids)
    selected, rejected, adopt_lines, push_lines, legacy_before_t0d = {}, [], [], [], []
    next_t0d_ts = None
    own_excluded = False
    for p in sorted(events, key=lambda p: p["ts"]):
        if p["ts"] < t0_ts:
            continue
        m0d = T0D_RE.search(p["msg"])
        if m0d:
            epoch2 = int(m0d.group(1))
            if epoch2 != epoch and p["ts"] > t0d_ts:
                if next_t0d_ts is None or p["ts"] < next_t0d_ts:
                    next_t0d_ts = p["ts"]
                continue
        if next_t0d_ts is not None and p["ts"] >= next_t0d_ts:
            continue
        mpush = PUSH_CMD_RE.search(p["msg"])
        if mpush:
            if not own_excluded and own_push_raw is not None and p["raw"] == own_push_raw:
                own_excluded = True
                continue
            push_lines.append(p)
            continue
        if backend == "spark":
            m2 = T2_RE.search(p["msg"])
            if not m2:
                continue
            rid, epoch_s, inc_s, typ, via, ms_s = m2.groups()
            epoch_v, inc_v, ms_v = int(epoch_s), int(inc_s), int(ms_s)
            if epoch_v != epoch:
                rejected.append({"line": p["raw"], "reason": "wrong_epoch"})
                continue
            if rid not in expected_rule_ids:
                rejected.append({"line": p["raw"], "reason": "unexpected_rule"})
                continue
            if via == "callback-adopt":
                adopt_lines.append({"rule_id": rid, "ts": p["ts"], "incarnation": inc_v,
                                     "type": typ, "attach_to_commit_ms": ms_v})
            if inc_v <= floor and via != "callback-adopt":
                rejected.append({"line": p["raw"], "reason": "fence_violation_below_floor"})
                continue
            if rid in selected:
                rejected.append({"line": p["raw"], "reason": "duplicate_rule"})
                continue
            selected[rid] = {"ts": p["ts"], "incarnation": inc_v, "type": typ, "via": via,
                              "attach_to_commit_ms": ms_v,
                              "reobserved_adopt": inc_v <= floor and via == "callback-adopt"}
            remaining.discard(rid)
        else:
            mL = ARM_LEGACY_RE.search(p["msg"])
            if not mL:
                continue
            rid = mL.group(1)
            if p["ts"] < t0d_ts:
                legacy_before_t0d.append(p["raw"])
                continue
            if rid not in expected_rule_ids or rid in selected:
                continue
            selected[rid] = {"ts": p["ts"]}
            remaining.discard(rid)
    return {
        "selected": selected, "rejected": rejected, "adopt_lines": adopt_lines,
        "push_lines": push_lines, "legacy_before_t0d": legacy_before_t0d,
        "missing": sorted(remaining), "next_t0d_ts": next_t0d_ts,
    }


def check_teardown_size(t0d, backend, expected_n):
    expected_detached = expected_n if backend == "spark" else 0
    return "teardown_size_mismatch" if t0d["detached_rules"] != expected_detached else None


def sweep_row_pure(events, epoch, missing_rule_ids, backend, t0d_ts):
    """Post-invocation sweep core: a second, patient look at a fuller log
    span for rule_ids a repeat's own bounded T2 collection never found.
    Same epoch-identity rule as classify_t2. Returns (found{rid:{...}},
    still_missing[rid,...])."""
    found = {}
    for p in events:
        if p["ts"] < t0d_ts:
            continue
        if backend == "spark":
            m2 = T2_RE.search(p["msg"])
            if m2:
                rid, epoch_s, inc_s, typ, via, ms_s = m2.groups()
                if (int(epoch_s) == epoch and rid in missing_rule_ids
                        and via != "callback-adopt"
                        and (rid not in found or p["ts"] < found[rid]["ts"])):
                    found[rid] = {"ts": p["ts"], "incarnation": int(inc_s), "type": typ,
                                   "via": via, "attach_to_commit_ms": int(ms_s)}
        else:
            mL = ARM_LEGACY_RE.search(p["msg"])
            if mL and mL.group(1) in missing_rule_ids:
                rid = mL.group(1)
                if rid not in found or p["ts"] < found[rid]["ts"]:
                    found[rid] = {"ts": p["ts"]}
    still_missing = sorted(set(missing_rule_ids) - set(found))
    return found, still_missing


def compute_window_math(t0_ts, t0d_ts, t1_ts, selected):
    """C/B window arithmetic from an already-classified `selected` dict.
    Pure - directly selftest-able (F6)."""
    items = sorted(selected.items(), key=lambda kv: kv[1]["ts"])
    ts_list = [v["ts"] for _, v in items]
    t2_first, t2_last = ts_list[0], ts_list[-1]
    c_ms = (t2_last - t0_ts).total_seconds() * 1000
    c_first_ms = (t2_first - t0_ts).total_seconds() * 1000
    c_from_t0d_ms = (t2_last - t0d_ts).total_seconds() * 1000
    t2_spread_ms = (t2_last - t2_first).total_seconds() * 1000
    t1_to_t2_last_ms = (t2_last - t1_ts).total_seconds() * 1000
    n_before = sum(1 for ts in ts_list if ts < t1_ts)
    n_tie = sum(1 for ts in ts_list if ts == t1_ts)
    n_after = sum(1 for ts in ts_list if ts > t1_ts)
    n_adopt = sum(1 for _, v in items if v.get("via") == "callback-adopt")
    n_shared = sum(1 for _, v in items if v.get("via") in ("inline-shared", "callback-shared"))
    attach_vals = [v["attach_to_commit_ms"] for _, v in items if "attach_to_commit_ms" in v]
    by_type = {}
    for _, v in items:
        if "type" in v:
            by_type.setdefault(v["type"], []).append((v["ts"] - t0_ts).total_seconds() * 1000)
    return {
        "c_ms": c_ms, "c_first_ms": c_first_ms, "c_from_t0d_ms": c_from_t0d_ms,
        "t2_spread_ms": t2_spread_ms, "t1_to_t2_last_ms": t1_to_t2_last_ms,
        "n_t2": len(items), "n_t2_before_t1": n_before, "n_t2_tie_t1": n_tie,
        "n_t2_after_t1": n_after, "n_adopt": n_adopt, "n_shared": n_shared,
        "attach_to_commit_ms_max": max(attach_vals) if attach_vals else None,
        "t2_by_type_max_ms": {k: max(vs) for k, vs in by_type.items()},
    }


def compute_verdict(legacy_rows, spark_rows, floor):
    """§7 two-gate verdict: reliability (ALL attempts, both cells) then
    latency (counted repeats only), margin = max(1000ms, legacy median)."""
    legacy_valid = [r for r in legacy_rows if not r.get("void_reason")]
    spark_valid = [r for r in spark_rows if not r.get("void_reason")]
    genuine = any(r.get("void_class") == "genuine" for r in legacy_rows + spark_rows)
    if genuine:
        return "FAIL-RELIABILITY"
    if len(legacy_valid) < floor or len(spark_valid) < floor:
        return "INCONCLUSIVE"
    legacy_c = statistics.median(r["c_ms"] for r in legacy_valid)
    spark_c = statistics.median(r["c_ms"] for r in spark_valid)
    margin = max(1000.0, legacy_c)
    return "PASS" if spark_c <= legacy_c + margin else "FAIL-LATENCY"


# --------------------------------------------------------------------------
# measurement - live (SSH-polling) stage wrappers around the pure functions
# --------------------------------------------------------------------------


def observe_t0(window_start_ts, allow_fallback_t0, t0_timeout_s, poll=2.0):
    size0 = agent_log_size()
    deadline = time.time() + t0_timeout_s
    while time.time() < deadline:
        events, size = _fetch_window(window_start_ts)
        if size < size0:
            return None, None, "log_rotated_mid_window", False
        tail_saturated = bool(events) and events[0]["ts"] > window_start_ts
        p, m = _find_first(events, T0_RE, at_or_after=window_start_ts)
        if p:
            return p, "cleared", None, tail_saturated
        if allow_fallback_t0:
            p, m = _find_first(events, PUSH_CMD_RE, at_or_after=window_start_ts)
            if p:
                return p, "fallback", None, tail_saturated
        time.sleep(poll)
    return None, None, "t0_not_found", False


def observe_t0d(window_start_ts, t0_ts, t0d_timeout_s, poll=2.0):
    size0 = agent_log_size()
    deadline = time.time() + t0d_timeout_s
    while time.time() < deadline:
        events, size = _fetch_window(window_start_ts)
        if size < size0:
            return None, "log_rotated_mid_window"
        p, m = _find_first(events, T0D_RE, at_or_after=t0_ts)
        if p:
            epoch, floor, detached, withdrawn = (int(x) for x in m.groups())
            return {"ts": p["ts"], "epoch": epoch, "floor": floor,
                    "detached_rules": detached, "withdrawn_claims": withdrawn}, None
        time.sleep(poll)
    return None, "t0d_not_found"


def observe_t1(window_start_ts, t0d_ts, t1_timeout_s, poll=2.0):
    size0 = agent_log_size()
    deadline = time.time() + t1_timeout_s
    while time.time() < deadline:
        events, size = _fetch_window(window_start_ts)
        if size < size0:
            return None, "log_rotated_mid_window"
        p, m = _find_first(events, T1_RE, at_or_after=t0d_ts)
        if p:
            return {"ts": p["ts"], "groups": m.groups()}, None
        time.sleep(poll)
    return None, "t1_not_found"


def collect_t2(t0_ts, t0d, window_start_ts, own_push_raw, expected_rule_ids, backend,
               visibility_timeout_s=ROOT_CAUSED_T2_VISIBILITY_TIMEOUT, poll=2.0):
    """Live S4: poll until classify_t2() reports nothing missing, a next-
    application T0d appears, or the visibility deadline expires. Returns
    (classify_t2 result dict, void_reason or None, last fetched events -
    the latter reused by the caller for the n_arm_lines continuity field)."""
    deadline = time.time() + visibility_timeout_s
    result, last_events = None, []
    while time.time() < deadline:
        events, size = _fetch_window(window_start_ts)
        last_events = events
        result = classify_t2(events, t0d["epoch"], t0d["floor"], expected_rule_ids,
                              own_push_raw, backend, t0_ts, t0d["ts"])
        if result["next_t0d_ts"] is not None:
            return result, "double_full_sync", last_events
        if not result["missing"]:
            break
        time.sleep(poll)
    if result is None:
        result = classify_t2([], t0d["epoch"], t0d["floor"], expected_rule_ids,
                              own_push_raw, backend, t0_ts, t0d["ts"])
    if result["legacy_before_t0d"] or any(
            r["reason"] == "fence_violation_below_floor" for r in result["rejected"]):
        return result, "fence_violation", last_events
    if result["missing"]:
        return result, "t2_incomplete", last_events
    if result["push_lines"]:
        return result, "repush_confound", last_events
    return result, None, last_events


def sweep_incomplete(rows, window_start_ts):
    """R5.7 §2.2 item 8: one final, patient read of the whole log span at the
    end of a cmd_run() invocation, reclassifying every t2_incomplete row
    into t2_late (found on the second look - instrument-invalid) or
    arm_never_confirmed (still missing - genuine)."""
    incomplete = [r for r in rows if r.get("void_reason") == "t2_incomplete"]
    if not incomplete:
        return rows
    events, _ = _fetch_window(window_start_ts)
    for r in incomplete:
        t0d_ts = datetime.fromisoformat(r["t0d"]["ts"])
        found, still_missing = sweep_row_pure(
            events, r["t0d"]["epoch"], set(r["missing_rule_ids"]), r["backend"], t0d_ts)
        if not still_missing:
            for rid, v in found.items():
                r["t2_selected"][rid] = {**v, "ts": v["ts"].isoformat()}
            r["missing_rule_ids"] = []
            r["void_class"], r["void_reason"] = "instrument", "t2_late"
        else:
            r["missing_rule_ids"] = still_missing
            r["void_class"], r["void_reason"] = "genuine", "arm_never_confirmed"
    return rows


def cohort_events_d(op, rule_ids, t0_dt, deadline_ms, poll=5.0):
    """Bounded functional-validity polling (R5.7 §2.2 item 6, replacing the
    prior one-shot lookup): poll every `poll` seconds until every rule has a
    `guard.compliant` event whose embedded ms falls in [t0_ms, t0_ms +
    deadline_ms], or until that event-time deadline plus a 60s ingestion
    grace has elapsed on the driver clock. t0_dt is log-native
    (local-labeled-as-UTC); event_id's embedded ms is real UTC - the offset
    is subtracted back out before comparing, same correction as before."""
    t0_ms = int(t0_dt.timestamp() * 1000) - int(dgrhp_utc_offset().total_seconds() * 1000)
    grace_deadline = time.time() + (deadline_ms / 1000.0) + 60.0
    by_rule = {rid: "not_observed" for rid in rule_ids}
    while time.time() < grace_deadline:
        pending = [rid for rid, v in by_rule.items() if v == "not_observed"]
        if not pending:
            break
        for rid in pending:
            try:
                data = get_json(op, f"/api/v1/guaranteed-state/events?rule_id={rid}&limit=100")["data"]
            except Exception:  # noqa: BLE001
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
            if found is not None:
                by_rule[rid] = found - t0_ms
        if any(v == "not_observed" for v in by_rule.values()):
            time.sleep(poll)
    return by_rule


# --------------------------------------------------------------------------
# measurement - per-repeat orchestration
# --------------------------------------------------------------------------


def run_repeat(op, phase, backend, trigger_kind, cohort_ids, exp_rule_ids, repeat_idx,
                trigger_id_cache, run_id, comparison_id):
    """One trigger-and-observe cycle. Always returns a row dict, built up
    incrementally from S0 onward, with as much evidence populated as was
    actually observed before any void - R5.7 §2.2 item 7 (evidence retained
    on every row, void or not)."""
    row = {
        "phase": phase, "backend": backend, "repeat": repeat_idx,
        "run_id": run_id, "comparison_id": comparison_id,
        "void_class": None, "void_reason": None,
    }
    m0 = get_metrics(op)
    window_start_ts = dgrhp_now()
    http_status = None
    if trigger_kind == "deploy":
        try:
            G.deploy_baseline_form(op, trigger_id_cache["trigger_baseline_id"])
            http_status = 200
        except Exception as e:  # noqa: BLE001
            row.update(trigger_http_status=None, void_class="instrument",
                       void_reason=f"trigger_failed:{e}")
            return row
    else:
        n = trigger_id_cache["hbr_counter"]
        trigger_id_cache["hbr_counter"] += 1
        rule = hbr_rule(run_id, n)
        try:
            _touch_win_file(rule["spark"]["params"]["path"])
            _, existed = G.post_rule(op, rule)
        except Exception as e:  # noqa: BLE001
            row.update(trigger_http_status=None, void_class="instrument",
                       void_reason=f"trigger_failed:{e}")
            return row
        http_status = 409 if existed else 201
        if existed:
            row.update(trigger_http_status=http_status, void_class="instrument",
                       void_reason="trigger_not_created")
            return row
    row["trigger_http_status"] = http_status

    allow_fallback_t0 = False  # R5.7: B/B2 never accept the fallback T0 (round-2 correction)
    t0, t0_source, reason, tail_saturated = observe_t0(
        window_start_ts, allow_fallback_t0, ROOT_CAUSED_T0_TIMEOUT)
    row["tail_saturated"] = tail_saturated
    if reason:
        row.update(void_class=void_class_for(reason), void_reason=reason)
        return row
    row["t0"], row["t0_source"] = t0["ts"].isoformat(), t0_source

    own_events, _ = _fetch_window(window_start_ts)
    own_push_raw = find_own_push_cmd_raw(own_events, t0["ts"])

    if backend == "spark":
        t0d, reason = observe_t0d(window_start_ts, t0["ts"], ROOT_CAUSED_T0D_TIMEOUT)
        if reason:
            row.update(void_class=void_class_for(reason), void_reason=reason)
            return row
        size_reason = check_teardown_size(t0d, backend, len(exp_rule_ids))
        if size_reason:
            row.update(void_class=void_class_for(size_reason), void_reason=size_reason)
            return row
    else:
        # R5.7 wrinkle, found live on the rig (2026-09-19): GuardianEngine::
        # wire_spark_engine() returns BEFORE constructing spark_runtime_ when
        # spark_disabled_by_config is true (the --spark-disable branch, checked
        # before the "!engine" branch) - so under legacy, spark_runtime_ stays
        # null for the agent's whole lifetime and detach_all()'s `if
        # (spark_runtime_)` guard makes it a permanent no-op: the T0d line NEVER
        # fires for a --spark-disable agent, contradicting this plan's original
        # assumption that detach_all() runs regardless of backend. Legacy never
        # needed the epoch fence in the first place - its arms are SYNCHRONOUS
        # under apply_rules()'s own mtx_, same thread as T0/T1, so there is no
        # stale-prior-application race to guard against. Synthesize t0d = t0
        # (epoch/floor/detached_rules/withdrawn_claims are meaningless for
        # legacy and recorded as 0) so collect_t2's shared membership logic
        # (legacy branch: "after t0d_ts" == "after t0_ts", a no-op restriction)
        # needs no separate code path.
        t0d = {"ts": t0["ts"], "epoch": 0, "floor": 0, "detached_rules": 0, "withdrawn_claims": 0}
    row["t0d"] = {"ts": t0d["ts"].isoformat(), "epoch": t0d["epoch"], "floor": t0d["floor"],
                  "detached_rules": t0d["detached_rules"], "withdrawn_claims": t0d["withdrawn_claims"]}

    t1, reason = observe_t1(window_start_ts, t0d["ts"], ROOT_CAUSED_T1_TIMEOUT)
    if reason:
        row.update(void_class=void_class_for(reason), void_reason=reason)
        return row
    applied, failed, pending, full_sync, generation, total = (
        int(t1["groups"][0]), int(t1["groups"][1]), int(t1["groups"][2]),
        t1["groups"][3], int(t1["groups"][4]), int(t1["groups"][5]),
    )
    row.update(t1=t1["ts"].isoformat(), applied=applied, failed=failed, pending=pending,
               total=total, generation=generation)
    b_ms = (t1["ts"] - t0["ts"]).total_seconds() * 1000
    row["b_ms"] = b_ms

    # m1: sampled on DGRHP's own clock (never local time.time() - see dgrhp_now()'s own
    # docstring for the cross-host drift this avoids), immediately after T1 becomes visible.
    m1_observed_dgrhp = dgrhp_now()
    m1 = get_metrics(op)
    row["m1_observed_wall"] = m1_observed_dgrhp.isoformat()
    row["m1_lag_ms"] = (m1_observed_dgrhp - t1["ts"]).total_seconds() * 1000

    if total != len(exp_rule_ids):
        row.update(void_class=void_class_for("cohort_composition"), void_reason="cohort_composition")
        return row

    result, reason, last_events = collect_t2(t0["ts"], t0d, window_start_ts, own_push_raw,
                                              exp_rule_ids, backend)
    row["t2_selected"] = {rid: {**v, "ts": v["ts"].isoformat()} for rid, v in result["selected"].items()}
    row["t2_rejected"] = result["rejected"]
    row["missing_rule_ids"] = result["missing"]
    row["push_cmd_lines_in_window"] = [p["raw"] for p in result["push_lines"]]
    row["legacy_lines_before_t0d"] = result["legacy_before_t0d"]
    row["n_reobserved_adopt"] = sum(1 for v in result["selected"].values() if v.get("reobserved_adopt"))
    row["n_arm_lines"] = (
        sum(1 for p in last_events if p["ts"] >= t0["ts"] and ARM_SPARK_RE.search(p["msg"]))
        if backend == "spark" else len(result["selected"])
    )
    if reason:
        row.update(void_class=void_class_for(reason), void_reason=reason)
        return row

    wm = compute_window_math(t0["ts"], t0d["ts"], t1["ts"], result["selected"])
    row.update(wm)

    reconcile_sent_delta = metric_sum(m1, 'yuzu_server_guardian_reconciles_total{result="sent"}') \
        - metric_sum(m0, 'yuzu_server_guardian_reconciles_total{result="sent"}')
    pushes_policy_change_delta = (
        metric_sum(m1, 'yuzu_server_guardian_pushes_dispatched_total{reason="policy_change"}')
        - metric_sum(m0, 'yuzu_server_guardian_pushes_dispatched_total{reason="policy_change"}')
    )
    row["reconcile_sent_delta"] = reconcile_sent_delta
    row["pushes_policy_change_delta"] = pushes_policy_change_delta

    phase_is_clean_verdict = phase in ("B", "B2")
    if phase_is_clean_verdict:
        if failed > 0:
            row.update(void_class="genuine", void_reason="failed_gt_0")
            return row
        if applied != total:
            row.update(void_class="instrument", void_reason="applied_ne_total")
            return row
        if phase == "B" and (reconcile_sent_delta != 0 or pushes_policy_change_delta != 1):
            row.update(void_class="instrument",
                       void_reason=f"push_counter_mismatch(reconcile_sent_delta="
                                   f"{reconcile_sent_delta},pushes_delta={pushes_policy_change_delta})")
            return row
        if phase == "B2" and (reconcile_sent_delta != 1 or pushes_policy_change_delta != 0):
            row.update(void_class="instrument",
                       void_reason=f"push_counter_mismatch(reconcile_sent_delta="
                                   f"{reconcile_sent_delta},pushes_delta={pushes_policy_change_delta})")
            return row

    c_ms = row["c_ms"]
    deadline_ms = max(2 * c_ms, 30000)
    d_by_rule = cohort_events_d(op, cohort_ids, t0["ts"], deadline_ms)
    functional_valid = all(v != "not_observed" for v in d_by_rule.values())
    row["compliant_restored_ms_by_rule"] = d_by_rule
    row["functional_valid"] = functional_valid
    if phase_is_clean_verdict and not functional_valid:
        row.update(void_class="genuine", void_reason="functional_invalid")
        return row

    row.update(void_class=None, void_reason=None)
    return row


def cmd_run(op, phase, backend, trigger_kind, repeats, gap, label, out_path, comparison_id):
    if phase in ("B", "B2") and not comparison_id:
        print("[run] --comparison is required for phase B/B2", file=sys.stderr)
        return 1
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    trigger_id_cache = {"hbr_counter": 1}
    if trigger_kind == "deploy":
        tb = find_baseline_id(op, TRIGGER_BASELINE)
        if not tb:
            raise RuntimeError(f"trigger baseline '{TRIGGER_BASELINE}' not found - run 'ensure' first")
        trigger_id_cache["trigger_baseline_id"] = tb
    cohort_ids = [r["rule_id"] for r in cohort_rules()]
    exp_rule_ids = expected_rule_ids()
    window_start_for_sweep = dgrhp_now()

    results = []
    valid = 0
    attempts = 0
    max_attempts = repeats * 2
    while valid < repeats and attempts < max(max_attempts, 10):
        attempts += 1
        r = run_repeat(op, phase, backend, trigger_kind, cohort_ids, exp_rule_ids, attempts,
                       trigger_id_cache, run_id, comparison_id)
        results.append(r)
        status = "VOID:" + r["void_reason"] if r.get("void_reason") else f"c_ms={r.get('c_ms', '?')}"
        print(f"[run] {label} {backend} {phase} attempt={attempts} {status}")
        if not r.get("void_reason"):
            valid += 1
        if valid < repeats:
            time.sleep(gap)

    results = sweep_incomplete(results, window_start_for_sweep)
    inconclusive = valid < repeats
    with open(out_path, "a") as f:
        for r in results:
            f.write(json.dumps({**r, "label": label}) + "\n")
    void_final = sum(1 for r in results if r.get("void_reason"))
    print(f"[run] {label} {backend} {phase} DONE valid={valid}/{repeats} "
          f"attempts={attempts} void={void_final} inconclusive={inconclusive} "
          f"run_id={run_id} comparison_id={comparison_id}")
    return 0


def find_baseline_id(op, name):
    return G.find_baseline_id(G.list_baselines_html(op), name)


def observe_phase_a_window(window_start_ts):
    """Phase A: no trigger, no clean-cohort void rules, no fence machinery -
    context-only, NOT verdict-bearing (unchanged this round except the
    dev-shape T1_RE unpack, which now needs a `pending` slot)."""
    size0 = agent_log_size()
    deadline_t0 = time.time() + 1200
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
                if PUSH_CMD_RE.search(p["msg"]):
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

    applied, failed, pending, full_sync, generation, total = t1_groups
    b_ms = (t1["ts"] - t0["ts"]).total_seconds() * 1000
    return {
        "void_reason": None, "t0_source": t0_source, "t0": t0["ts"].isoformat(),
        "t1": t1["ts"].isoformat(), "generation": int(generation), "applied": int(applied),
        "failed": int(failed), "total": int(total), "pending": int(pending), "b_ms": b_ms,
        "n_arm_lines": len(arm_events), "next_window_start": t1["ts"],
    }


def cmd_run_phase_a(op, backend, label, out_path, cap_seconds=1200, target_windows=3):
    start = time.time()
    results = []
    window_start_ts = dgrhp_now()
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


# --------------------------------------------------------------------------
# reporting
# --------------------------------------------------------------------------


def build_report_lines(rows):
    groups = {}
    for r in rows:
        key = (r.get("comparison_id"), r.get("run_id"), r["label"], r["backend"], r["phase"])
        groups.setdefault(key, []).append(r)
    lines = ["| Comparison | Run | Label | Backend | Phase | Attempted | Valid | Floor reached | "
             "B median (ms) | C median (ms) | Void breakdown |",
             "|---|---|---|---|---|---|---|---|---|---|---|"]
    for key in sorted(groups, key=lambda k: tuple(str(x) for x in k)):
        comparison_id, run_id, label, backend, phase = key
        rs = groups[key]
        valid = [r for r in rs if not r.get("void_reason")]
        floor = 5 if phase == "B" else 3
        reached = "Y" if len(valid) >= floor else "N"
        void_counts = {}
        for r in rs:
            if r.get("void_reason"):
                void_counts[r["void_reason"]] = void_counts.get(r["void_reason"], 0) + 1
        void_str = ", ".join(f"{k}={v}" for k, v in sorted(void_counts.items())) or "-"
        b_vals = [r["b_ms"] for r in valid if "b_ms" in r]
        c_vals = [r["c_ms"] for r in valid if "c_ms" in r]
        b_med = f"{statistics.median(b_vals):.1f}" if b_vals else "-"
        c_med = f"{statistics.median(c_vals):.1f}" if c_vals else "-"
        lines.append(f"| {comparison_id} | {run_id} | {label} | {backend} | {phase} | "
                      f"{len(rs)} | {len(valid)} | {reached} | {b_med} | {c_med} | {void_str} |")
    return lines


def build_verdict_lines(rows):
    # R5.7 bug fix (found live, 2026-09-19): legacy and spark are separate
    # cmd_run() invocations and therefore carry DIFFERENT run_id values by
    # construction - grouping on run_id (as an earlier version of this
    # function did) can never pair them for the SAME comparison, and every
    # verdict silently read INCONCLUSIVE (each backend saw 0 rows for the
    # other side). The pairing key is (comparison_id, label, phase) only;
    # run_id is per-backend provenance, reported per cell in
    # build_report_lines, not part of how cells are paired for a verdict.
    groups = {}
    for r in rows:
        if r["phase"] not in ("B", "B2"):
            continue
        key = (r.get("comparison_id"), r["label"], r["phase"])
        groups.setdefault(key, {}).setdefault(r["backend"], []).append(r)
    lines = ["| Comparison | Label | Phase | Verdict |", "|---|---|---|---|"]
    for key in sorted(groups, key=lambda k: tuple(str(x) for x in k)):
        comparison_id, label, phase = key
        cells = groups[key]
        floor = 5 if phase == "B" else 3
        verdict = compute_verdict(cells.get("legacy", []), cells.get("spark", []), floor)
        lines.append(f"| {comparison_id} | {label} | {phase} | {verdict} |")
    return lines


def cmd_report(in_path, out_md_path):
    rows = []
    with open(in_path) as f:
        for line in f:
            rows.append(json.loads(line))
    lines = build_report_lines(rows) + [""] + build_verdict_lines(rows)
    with open(out_md_path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print("\n".join(lines))
    return 0


# --------------------------------------------------------------------------
# selftest - offline, no rig, no server. Run BEFORE any login (see main()).
# Fixtures F1-F14 per the R5.7 round-2 plan §2.2 item 11 - this is the check
# that would have caught the dev-shape T1_RE drift before a rig round, and
# the actual correctness test for the epoch-fence design Astra's adversarial
# review found round 1's timestamp-only version unsound against.
# --------------------------------------------------------------------------


def _f1():
    dev_line = "Guardian: apply_rules ok (applied=62, failed=0, pending=3, full_sync=true, generation=5, total=62)"
    old_line = "Guardian: apply_rules ok (applied=62, failed=0, full_sync=true, generation=5, total=62)"
    ok1 = bool(T1_RE.search(dev_line))
    ok2 = not bool(T1_RE.search(old_line))
    return ok1 and ok2, f"dev_match={ok1} old_rejected={ok2}"


def _f2():
    lines = {
        "t0": "Guardian: full_sync cleared 62 prior rule(s)",
        "t0d": "Guardian spark: detach_all complete (epoch=3, incarnation_floor=100, "
               "detached_rules=62, withdrawn_claims=0)",
        "t1": "Guardian: apply_rules ok (applied=62, failed=0, pending=0, full_sync=true, "
              "generation=5, total=62)",
        "t2": "Guardian spark: arm committed for rule 'blackout-reg-01' (epoch=3, "
              "incarnation=101, type=registry, via=inline-arm, attach_to_commit_ms=12)",
        "legacy": "Guardian: file guard armed for rule 'blackout-file-01'",
        "sparkengine": r"SparkEngine: armed 'reg:HKCU\SOFTWARE\YuzuBlackout\Key01'",
    }
    regexes = {"t0": T0_RE, "t0d": T0D_RE, "t1": T1_RE, "t2": T2_RE,
               "legacy": ARM_LEGACY_RE, "sparkengine": ARM_SPARK_RE}
    ok, detail = True, []
    for name, line in lines.items():
        matched = {r for r, rx in regexes.items() if rx.search(line)}
        if matched != {name}:
            ok = False
            detail.append(f"{name}: matched={matched}")
    m = T0D_RE.search(lines["t0d"])
    if not m or [int(x) for x in m.groups()] != [3, 100, 62, 0]:
        ok = False
        detail.append("t0d field mismatch")
    m = T2_RE.search(lines["t2"])
    if not m or m.groups() != ("blackout-reg-01", "3", "101", "registry", "inline-arm", "12"):
        ok = False
        detail.append("t2 field mismatch")
    return ok, "; ".join(detail) or "all regexes pairwise-exclusive, fields parsed correctly"


def _f3():
    events = [
        _ev("2026-09-19 10:00:00.000", "Guardian: full_sync cleared 1 prior rule(s)"),
        _ev("2026-09-19 10:00:00.020",
            "Guardian spark: arm committed for rule 'blackout-reg-01' (epoch=2, incarnation=50, "
            "type=registry, via=callback-arm, attach_to_commit_ms=5)"),  # STALE, epoch E-1
        _ev("2026-09-19 10:00:00.050", "Guardian spark: detach_all complete (epoch=3, "
            "incarnation_floor=100, detached_rules=1, withdrawn_claims=0)"),
        _ev("2026-09-19 10:00:00.100", "Guardian: apply_rules ok (applied=1, failed=0, "
            "pending=0, full_sync=true, generation=5, total=1)"),
        _ev("2026-09-19 10:00:00.150",
            "Guardian spark: arm committed for rule 'blackout-reg-01' (epoch=3, incarnation=101, "
            "type=registry, via=inline-arm, attach_to_commit_ms=8)"),
    ]
    result = classify_t2(events, epoch=3, floor=100, expected_rule_ids={"blackout-reg-01"},
                          own_push_raw=None, backend="spark",
                          t0_ts=events[0]["ts"], t0d_ts=events[2]["ts"])
    stale_rejected = any(r["reason"] == "wrong_epoch" for r in result["rejected"])
    completed = not result["missing"] and "blackout-reg-01" in result["selected"]
    return stale_rejected and completed, f"stale_rejected={stale_rejected} completed={completed}"


def _f4():
    events = [
        _ev("2026-09-19 10:00:00.000", "Guardian: full_sync cleared 1 prior rule(s)"),
        _ev("2026-09-19 10:00:00.010", "Guardian spark: detach_all complete (epoch=3, "
            "incarnation_floor=100, detached_rules=1, withdrawn_claims=0)"),
        _ev("2026-09-19 10:00:00.030",
            "Guardian spark: arm committed for rule 'blackout-reg-01' (epoch=3, incarnation=42, "
            "type=registry, via=callback-adopt, attach_to_commit_ms=3)"),  # incarnation <= floor
    ]
    result = classify_t2(events, epoch=3, floor=100, expected_rule_ids={"blackout-reg-01"},
                          own_push_raw=None, backend="spark",
                          t0_ts=events[0]["ts"], t0d_ts=events[1]["ts"])
    v = result["selected"].get("blackout-reg-01")
    ok = v is not None and v["reobserved_adopt"] is True and not result["missing"]
    no_fv = not any(r["reason"] == "fence_violation_below_floor" for r in result["rejected"])
    return ok and no_fv, f"selected_reobserved={ok} no_fence_violation={no_fv}"


def _f5():
    events = [
        _ev("2026-09-19 10:00:00.000", "Guardian: full_sync cleared 1 prior rule(s)"),
        _ev("2026-09-19 10:00:00.010", "Guardian spark: detach_all complete (epoch=3, "
            "incarnation_floor=100, detached_rules=1, withdrawn_claims=0)"),
        _ev("2026-09-19 10:00:00.030",
            "Guardian spark: arm committed for rule 'blackout-reg-01' (epoch=3, incarnation=42, "
            "type=registry, via=inline-arm, attach_to_commit_ms=3)"),  # NOT adopt, below floor
    ]
    result = classify_t2(events, epoch=3, floor=100, expected_rule_ids={"blackout-reg-01"},
                          own_push_raw=None, backend="spark",
                          t0_ts=events[0]["ts"], t0d_ts=events[1]["ts"])
    flagged = any(r["reason"] == "fence_violation_below_floor" for r in result["rejected"])
    not_selected = "blackout-reg-01" not in result["selected"]
    return flagged and not_selected, f"flagged={flagged} not_selected={not_selected}"


def _f6():
    t0 = _ev("2026-09-19 10:00:00.000", "x")["ts"]
    t1 = _ev("2026-09-19 10:00:00.100", "x")["ts"]
    selected = {
        "r1": {"ts": _ev("2026-09-19 10:00:00.050", "x")["ts"], "via": "inline-arm"},
        "r2": {"ts": t1, "via": "inline-arm"},
        "r3": {"ts": _ev("2026-09-19 10:00:00.150", "x")["ts"], "via": "inline-arm"},
    }
    wm = compute_window_math(t0, t0, t1, selected)
    ok = (wm["n_t2_before_t1"] == 1 and wm["n_t2_tie_t1"] == 1 and wm["n_t2_after_t1"] == 1
          and abs(wm["c_ms"] - 150.0) < 1e-6)
    return ok, (f"before={wm['n_t2_before_t1']} tie={wm['n_t2_tie_t1']} "
                f"after={wm['n_t2_after_t1']} c_ms={wm['c_ms']}")


def _f7():
    events = [
        _ev("2026-09-19 10:00:00.030",
            "Guardian spark: arm committed for rule 'blackout-reg-02' (epoch=1, incarnation=11, "
            "type=registry, via=inline-arm, attach_to_commit_ms=3)"),
        _ev("2026-09-19 10:00:00.000", "Guardian: full_sync cleared 2 prior rule(s)"),
        _ev("2026-09-19 10:00:00.010", "Guardian spark: detach_all complete (epoch=1, "
            "incarnation_floor=5, detached_rules=2, withdrawn_claims=0)"),
        _ev("2026-09-19 10:00:00.020",
            "Guardian spark: arm committed for rule 'blackout-reg-01' (epoch=1, incarnation=10, "
            "type=registry, via=inline-arm, attach_to_commit_ms=3)"),
    ]
    t0_ts = min(e["ts"] for e in events if T0_RE.search(e["msg"]))
    t0d_ev = [e for e in events if T0D_RE.search(e["msg"])][0]
    result = classify_t2(events, epoch=1, floor=5,
                          expected_rule_ids={"blackout-reg-01", "blackout-reg-02"},
                          own_push_raw=None, backend="spark", t0_ts=t0_ts, t0d_ts=t0d_ev["ts"])
    ok = not result["missing"] and len(result["selected"]) == 2
    return ok, f"missing={result['missing']} selected={sorted(result['selected'])}"


def _f8():
    events = [
        _ev("2026-09-19 10:00:00.000", "Guardian: full_sync cleared 1 prior rule(s)"),
        _ev("2026-09-19 10:00:00.010", "Guardian spark: detach_all complete (epoch=1, "
            "incarnation_floor=5, detached_rules=1, withdrawn_claims=0)"),
        _ev("2026-09-19 10:00:00.500", "Guardian: full_sync cleared 1 prior rule(s)"),
        _ev("2026-09-19 10:00:00.510", "Guardian spark: detach_all complete (epoch=2, "
            "incarnation_floor=10, detached_rules=1, withdrawn_claims=0)"),
    ]
    result = classify_t2(events, epoch=1, floor=5, expected_rule_ids={"blackout-reg-01"},
                          own_push_raw=None, backend="spark",
                          t0_ts=events[0]["ts"], t0d_ts=events[1]["ts"])
    ok = result["next_t0d_ts"] is not None
    return ok, f"next_t0d_ts={result['next_t0d_ts']}"


def _f9():
    # "Same-ms tie" case: the trigger's OWN push-command line and a genuinely
    # DIFFERENT extra push both land at the identical millisecond, at-or-after
    # t0_ts (a line strictly before t0_ts is out of classify_t2's window
    # entirely, by construction - not what this fixture is testing). Identity
    # (raw line content), not timestamp value, is what must tell them apart.
    own_line = "Received command: plugin=__guard__, action=push_rules"
    own_raw = "OWN:" + own_line
    extra_raw = "EXTRA:" + own_line
    events = [
        _ev("2026-09-19 10:00:00.000", "Guardian: full_sync cleared 1 prior rule(s)"),
        _ev("2026-09-19 10:00:00.000", own_line, raw=own_raw),      # tie with T0
        _ev("2026-09-19 10:00:00.000", own_line, raw=extra_raw),    # same ms, DIFFERENT raw
        _ev("2026-09-19 10:00:00.010", "Guardian spark: detach_all complete (epoch=1, "
            "incarnation_floor=5, detached_rules=1, withdrawn_claims=0)"),
        _ev("2026-09-19 10:00:00.030",
            "Guardian spark: arm committed for rule 'blackout-reg-01' (epoch=1, incarnation=10, "
            "type=registry, via=inline-arm, attach_to_commit_ms=3)"),
    ]
    result = classify_t2(events, epoch=1, floor=5, expected_rule_ids={"blackout-reg-01"},
                          own_push_raw=own_raw, backend="spark",
                          t0_ts=events[0]["ts"], t0d_ts=events[3]["ts"])
    ok = len(result["push_lines"]) == 1 and result["push_lines"][0]["raw"] == extra_raw
    return ok, f"push_lines={[p['raw'] for p in result['push_lines']]}"


def _f10():
    t0 = _ev("2026-09-19 10:00:00.000", "x")["ts"]
    t0d = _ev("2026-09-19 10:00:00.010", "x")["ts"]
    base = [
        _ev("2026-09-19 10:00:00.000", "Guardian: full_sync cleared 1 prior rule(s)"),
        _ev("2026-09-19 10:00:00.010", "Guardian spark: detach_all complete (epoch=1, "
            "incarnation_floor=5, detached_rules=1, withdrawn_claims=0)"),
    ]
    late = base + [
        _ev("2026-09-19 10:00:00.090",
            "Guardian spark: arm committed for rule 'blackout-reg-01' (epoch=1, incarnation=10, "
            "type=registry, via=inline-arm, attach_to_commit_ms=3)"),
    ]
    r1 = classify_t2(base, epoch=1, floor=5, expected_rule_ids={"blackout-reg-01"},
                      own_push_raw=None, backend="spark", t0_ts=t0, t0d_ts=t0d)
    r2 = classify_t2(late, epoch=1, floor=5, expected_rule_ids={"blackout-reg-01"},
                      own_push_raw=None, backend="spark", t0_ts=t0, t0d_ts=t0d)
    ok = bool(r1["missing"]) and not r2["missing"]
    return ok, f"early_missing={r1['missing']} late_missing={r2['missing']}"


def _f11():
    t0d_ts = _ev("2026-09-19 10:00:00.010", "x")["ts"]
    events_found = [
        _ev("2026-09-19 10:00:05.000",
            "Guardian spark: arm committed for rule 'blackout-reg-01' (epoch=1, incarnation=10, "
            "type=registry, via=inline-arm, attach_to_commit_ms=3)"),
    ]
    found, still_missing = sweep_row_pure(events_found, epoch=1,
                                           missing_rule_ids={"blackout-reg-01"},
                                           backend="spark", t0d_ts=t0d_ts)
    ok1 = "blackout-reg-01" in found and not still_missing
    found2, still_missing2 = sweep_row_pure([], epoch=1, missing_rule_ids={"blackout-reg-01"},
                                             backend="spark", t0d_ts=t0d_ts)
    ok2 = not found2 and still_missing2 == ["blackout-reg-01"]
    return ok1 and ok2, f"found_case={ok1} never_found_case={ok2}"


def _f12():
    # All-void cell (both backends, one void row each) - must still print and
    # must read INCONCLUSIVE (floor not reached).
    void_rows = [
        {"comparison_id": "cmp1", "run_id": "run1", "label": "t2-v1", "backend": "legacy",
         "phase": "B", "repeat": 1, "void_class": "instrument", "void_reason": "t0_not_found"},
        {"comparison_id": "cmp1", "run_id": "run1", "label": "t2-v1", "backend": "spark",
         "phase": "B", "repeat": 1, "void_class": "instrument", "void_reason": "t1_not_found"},
    ]
    lines = build_report_lines(void_rows)
    printed = any("cmp1" in ln and "t2-v1" in ln for ln in lines)
    verdicts = build_verdict_lines(void_rows)
    inconclusive = any("INCONCLUSIVE" in ln for ln in verdicts)

    # R5.7 bug (found live, 2026-09-19): legacy and spark are SEPARATE cmd_run()
    # invocations and therefore carry DIFFERENT run_id values in real data - an
    # earlier build_verdict_lines() grouped on run_id and could never pair them,
    # so every verdict silently read INCONCLUSIVE regardless of how much valid
    # data existed. This fixture uses realistic DIFFERENT run_ids per backend
    # and enough valid repeats to clear the floor - the verdict must NOT be
    # INCONCLUSIVE (it should resolve the actual latency/reliability gates).
    def _valid(backend, run_id, n, c_ms):
        return [{"comparison_id": "cmp2", "run_id": run_id, "label": "t2-v1", "backend": backend,
                 "phase": "B", "repeat": i, "void_class": None, "void_reason": None,
                 "c_ms": c_ms, "b_ms": c_ms} for i in range(1, n + 1)]
    paired_rows = (_valid("legacy", "legacy-run-1", 5, 70.0) +
                   _valid("spark", "spark-run-1", 5, 80.0))
    paired_verdicts = build_verdict_lines(paired_rows)
    paired_not_inconclusive = (
        len(paired_verdicts) > 2 and "INCONCLUSIVE" not in paired_verdicts[2]
    )
    return (printed and inconclusive and paired_not_inconclusive,
            f"cell_printed={printed} all_void_inconclusive={inconclusive} "
            f"cross_run_id_paired={paired_not_inconclusive} "
            f"paired_verdict_line={paired_verdicts[2] if len(paired_verdicts) > 2 else None}")


def _f13():
    events_ok = [
        _ev("2026-09-19 10:00:00.000", "Guardian: full_sync cleared 1 prior rule(s)"),
        _ev("2026-09-19 10:00:00.010", "Guardian spark: detach_all complete (epoch=1, "
            "incarnation_floor=5, detached_rules=0, withdrawn_claims=0)"),
        _ev("2026-09-19 10:00:00.050", "Guardian: file guard armed for rule 'blackout-file-01'"),
    ]
    r_ok = classify_t2(events_ok, epoch=1, floor=5, expected_rule_ids={"blackout-file-01"},
                        own_push_raw=None, backend="legacy",
                        t0_ts=events_ok[0]["ts"], t0d_ts=events_ok[1]["ts"])
    ok1 = not r_ok["missing"] and not r_ok["legacy_before_t0d"]

    events_bad = [
        _ev("2026-09-19 10:00:00.000", "Guardian: full_sync cleared 1 prior rule(s)"),
        _ev("2026-09-19 10:00:00.005", "Guardian: file guard armed for rule 'blackout-file-01'"),
        _ev("2026-09-19 10:00:00.010", "Guardian spark: detach_all complete (epoch=1, "
            "incarnation_floor=5, detached_rules=0, withdrawn_claims=0)"),
    ]
    r_bad = classify_t2(events_bad, epoch=1, floor=5, expected_rule_ids={"blackout-file-01"},
                         own_push_raw=None, backend="legacy",
                         t0_ts=events_bad[0]["ts"], t0d_ts=events_bad[2]["ts"])
    ok2 = bool(r_bad["legacy_before_t0d"])
    return ok1 and ok2, f"ok_case={ok1} before_t0d_case={ok2}"


def _f14():
    t0d = {"epoch": 1, "floor": 5, "detached_rules": 60, "withdrawn_claims": 0}
    ok1 = check_teardown_size(t0d, "spark", 62) == "teardown_size_mismatch"
    t0d_ok = {"epoch": 1, "floor": 5, "detached_rules": 62, "withdrawn_claims": 0}
    ok2 = check_teardown_size(t0d_ok, "spark", 62) is None
    t0d_legacy = {"epoch": 1, "floor": 5, "detached_rules": 0, "withdrawn_claims": 0}
    ok3 = check_teardown_size(t0d_legacy, "legacy", 62) is None
    return ok1 and ok2 and ok3, f"mismatch_detected={ok1} ok_spark={ok2} ok_legacy={ok3}"


def cmd_selftest():
    fixtures = [
        ("F1", _f1), ("F2", _f2), ("F3", _f3), ("F4", _f4), ("F5", _f5), ("F6", _f6),
        ("F7", _f7), ("F8", _f8), ("F9", _f9), ("F10", _f10), ("F11", _f11), ("F12", _f12),
        ("F13", _f13), ("F14", _f14),
    ]
    failures = 0
    for name, fn in fixtures:
        try:
            ok, detail = fn()
        except Exception as e:  # noqa: BLE001
            ok, detail = False, f"EXCEPTION: {e!r}"
        status = "PASS" if ok else "FAIL"
        if not ok:
            failures += 1
        print(f"[selftest] {name}: {status} - {detail}")
    print(f"[selftest] {len(fixtures) - failures}/{len(fixtures)} passed")
    return 1 if failures else 0


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("selftest")
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
    p.add_argument("--comparison", default=None,
                   help="required for phase B/B2 - groups the 4 invocations of one "
                        "legacy/spark x B/B2 comparison together in `report`")
    p.add_argument("--out", default=os.path.join(SCRATCH_DIR, "results.jsonl"))

    p = sub.add_parser("report")
    p.add_argument("--in", dest="in_path", default=os.path.join(SCRATCH_DIR, "results.jsonl"))
    p.add_argument("--out", default=os.path.join(SCRATCH_DIR, "report.md"))

    args = ap.parse_args()

    # R5.7: selftest runs BEFORE any server login - it needs no rig, no server, no SSH.
    if args.cmd == "selftest":
        return cmd_selftest()

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
                       args.label, args.out, args.comparison)
    if args.cmd == "report":
        return cmd_report(args.in_path, args.out)
    return 1


if __name__ == "__main__":
    sys.exit(main())
