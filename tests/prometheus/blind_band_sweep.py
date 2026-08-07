#!/usr/bin/env python3
"""Measure the cadences at which YuzuAuditRetentionNotRunning cannot fire.

NOT WIRED INTO CI, AND DELIBERATELY SO. This is a measurement instrument, run
by hand, whose OUTPUT is the artifact (`docs/prometheus/blind-band-measurement.md`).
The automated version - sweep on every PR, fail on any change to the silent set -
is the acceptance gate for the rule REDESIGN, not for the branch that merely
documents the gap. Wiring it here would gate on a property nobody is changing.

WHY IT EXISTS AT ALL. Three separate reviews put the blind band at three
different places, because each sampled a few cadences and a few eval points:
  - "~165-179 min", from a sweep at 30-minute steps
  - "164-195 at 1m interval, 160-195 at 5m", from a denser sweep
  - "cadence 120 and 170 both silent", from a SINGLE eval point at 300m -
    wrong, and wrong in the dangerous direction, because the alert has a duty
    cycle and one point can land between firings.
A rule change validated against any of those three would leave real cadences
uncovered. So: sweep the space, and evaluate DENSELY within each cadence.

METHOD. For each (cadence, evaluation interval) pair, synthesise a server whose
reaper is DEAD - `..._retention_passes_total` flat forever - and whose uptime is
a sawtooth restarting every `cadence` minutes. Assert the alert NEVER fires, at
every eval point across several full cycles. promtool returning SUCCESS means
the assertion held, i.e. THE ALERT IS SILENT and the dead reaper is undetected.
A FAILED result is the good outcome.

Usage:  python3 tests/prometheus/blind_band_sweep.py [--rules <ref>] [--step N]
        --rules accepts `origin/dev` to measure the previous expression.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
RULES = "docs/prometheus/yuzu-alerts.yml"
ALERT = "YuzuAuditRetentionNotRunning"
IMAGE = ("prom/prometheus:v3.13.1@sha256:"
         "3c42b892cf723fa54d2f262c37a0e1f80aa8c8ddb1da7b9b0df9455a35a7f893")


def rules_text(ref: str | None) -> str:
    if ref is None:
        return (REPO_ROOT / RULES).read_text(encoding="utf-8")
    out = subprocess.run(["git", "show", f"{ref}:{RULES}"], cwd=REPO_ROOT,
                         capture_output=True, text=True, check=True)
    return out.stdout


def extract(text: str) -> dict:
    doc = yaml.safe_load(text)
    rules = [r for g in doc["groups"] for r in g.get("rules", [])
             if r.get("alert") == ALERT]
    if not rules:
        sys.exit(f"{ALERT} not found in the rules file")
    return {"groups": [{"name": "sweep", "rules": rules}]}


START_MIN = 3 * 60 + 20   # past the [3h] window plus the 15m `for:`


def case(cadence: int, interval_s: int) -> dict:
    """One cadence, asserted silent at EVERY eval point across several cycles.

    The eval grid is the point of this function. A sparse grid reports a firing
    rule as silent whenever the sample lands outside its duty cycle, which is
    how three reviews produced three different bands.

    `cycles` is DERIVED, never fixed. A fixed 4 made the series end at 120 min
    for a 30-minute cadence while the grid started at 200, so the assertion list
    came out EMPTY and promtool passed the case vacuously - reported as "silent"
    when nothing had been measured. That is the same vacuous-success defect this
    directory's harness exists to catch, reproduced in the instrument built to
    audit it. Hence the assertion below.
    """
    seg = f"0+60x{cadence - 1}"
    cycles = max(4, -(-(START_MIN + 3 * cadence) // cadence))
    total = cadence * cycles
    step = max(1, interval_s // 60)
    points = list(range(START_MIN, total - 2, step))
    if not points:
        sys.exit(f"internal: cadence {cadence} produced no eval points")
    return {
        "interval": "1m",
        "name": f"cadence-{cadence}",
        "input_series": [
            {"series": 'yuzu_server_audit_retention_passes_total'
                       '{job="yuzu",instance="s1"}',
             "values": f"0+0x{total - 1}"},
            {"series": 'yuzu_server_uptime_seconds{job="yuzu",instance="s1"}',
             "values": " ".join([seg] * cycles)},
        ],
        "promql_expr_test": [
            {"expr": f'ALERTS{{alertname="{ALERT}", alertstate="firing"}}',
             "eval_time": f"{t}m", "exp_samples": []}
            for t in points
        ],
    }


def silent(root: Path, rules: dict, cadence: int, interval_s: int) -> bool:
    """True if the alert NEVER fires for a dead reaper at this cadence.

    A NON-ZERO exit is not by itself evidence of firing, and conflating the two
    is how the first version of this script reported "no silent cadence
    anywhere" - the exact opposite of the truth. `tempfile.mkdtemp` creates the
    directory 0700; the container runs as uid 65534, so promtool could not stat
    the file and exited 1 on EVERY cadence, which read as "the alert fired". An
    instrument that cannot run must say so, never return a value.
    """
    for d in ("rules", "tests"):
        (root / d).mkdir(exist_ok=True)
    root.chmod(0o755)
    (root / "rules" / "r.yml").write_text(yaml.safe_dump(rules, sort_keys=False),
                                          encoding="utf-8")
    (root / "tests" / "t.yml").write_text(yaml.safe_dump({
        "rule_files": ["../rules/r.yml"],
        "evaluation_interval": f"{interval_s}s",
        "tests": [case(cadence, interval_s)],
    }, sort_keys=False), encoding="utf-8")
    for d in ("rules", "tests"):
        (root / d).chmod(0o755)
        for f in (root / d).iterdir():
            f.chmod(0o644)
    p = subprocess.run(
        ["docker", "run", "--rm", "-v", f"{root}:/w:ro", "--network", "none",
         "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
         "--entrypoint", "/bin/promtool", IMAGE,
         "test", "rules", "/w/tests/t.yml"],
        capture_output=True, text=True)
    if p.returncode == 0:
        return True                      # assertion held: never fired: SILENT
    # promtool splits this across streams depending on version - check both, or
    # a real failure is misread as an infrastructure error and the sweep aborts.
    if "FAILED" in p.stdout or "FAILED" in p.stderr:
        return False                     # a real assertion failure: it fired
    sys.exit(                            # anything else: we measured NOTHING
        f"cannot measure cadence {cadence} at {interval_s}s - promtool exited "
        f"{p.returncode} without a test failure. This is not a result.\n"
        f"stdout: {p.stdout.strip()[:400]}\nstderr: {p.stderr.strip()[:400]}"
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules", default=None,
                    help="git ref to read the rules file from (default: worktree)")
    ap.add_argument("--step", type=int, default=5)
    ap.add_argument("--low", type=int, default=30)
    ap.add_argument("--high", type=int, default=240)
    args = ap.parse_args()

    rules = extract(rules_text(args.rules))
    label = args.rules or "working tree"
    print(f"rules: {label}   cadences {args.low}-{args.high} step {args.step}")
    tmp = Path(tempfile.mkdtemp(prefix="yuzu_blind_band_"))
    try:
        for interval_s in (30, 60, 300):
            band = [c for c in range(args.low, args.high + 1, args.step)
                    if silent(tmp, rules, c, interval_s)]
            sampled = len(range(args.low, args.high + 1, args.step))
            if not band:
                print(f"  eval interval {interval_s:>3}s: no silent cadence "
                      f"in {sampled} sampled")
                continue
            contiguous = band == list(range(band[0], band[-1] + 1, args.step))
            shape = "" if contiguous else "  (NON-CONTIGUOUS)"
            print(f"  eval interval {interval_s:>3}s: SILENT at "
                  f"{','.join(str(c) for c in band)} min "
                  f"({len(band)} of {sampled} sampled){shape}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
