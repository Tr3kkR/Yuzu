#!/usr/bin/env python3
"""Measure which cadences the audit-retention alert family fails to COVER.

WIRED INTO CI as of #2854 rung B (`--check`, `prometheus-rules` job). Earlier
revisions of this script were a hand-run measurement instrument only, on the
reasoning that the rule redesign it measures had not landed yet - automating a
sweep of a property nobody was changing gates nothing. Rung A (#2854, PR #2889)
changed that: `yuzu_server_audit_retention_last_pass_unixtime` now survives a
restart, which is the precondition the redesign (rung D) needs. This script is
now the ACCEPTANCE GATE for that redesign: `blind_band_manifest.json` is the
committed baseline, `--check` fails the build the moment a rule change widens
it, and `--emit` is how a deliberate change updates it.

COVERED, not SILENT - the property inverted. The pre-#2854 version asserted the
alert never fires and called a passing case "silent" (a documented, narrow gap).
Under the redesign the property that matters is the opposite: for a genuinely
dead reaper, the alert must be FIRING AT EVERY EVAL POINT past settle, not just
eventually. A cadence where the alert fires at some points and not others is
just as undetected as one where it never fires at all - Alertmanager still
emits RESOLVED mid-fault and an auditor still reads "transient". So a cadence
is UNCOVERED if the alert fails to fire at ANY sampled point, which measures
both the historical blind band and the auto-resolve duty-cycle hole with one
instrument.

TWO SCENARIOS, because one rule cannot answer both restart-liveness questions.
`anchored` seeds the stamp series at a constant non-zero unix time (a database
that has run before, whose reaper died) and gates `YuzuAuditRetentionNotRunning`.
`fresh` seeds it flat `0` (a database that has never run one) and gates
`YuzuAuditRetentionNeverRan`. `YuzuAuditRetentionNeverRan` does not exist until
rung D lands; a scenario whose alert is absent from the rules file is reported
as `alert_present: false` with EVERY sampled cadence uncovered by definition,
not an abort - see the comment on `extract()`.

METHOD, per (scenario, cadence, evaluation interval): synthesise a server whose
reaper is DEAD (`..._passes_total` flat forever) with a sawtooth
`yuzu_server_uptime_seconds` restarting every `cadence` minutes and the stamp
series held per the scenario above, then assert the target alert is firing at
EVERY eval point across several full cycles, sampled in the eval interval's own
resolution (not rounded to a whole minute - see `case()`). `promtool test rules`
returning SUCCESS means every assertion held, i.e. the cadence is fully covered;
a `FAILED` on any single point makes the whole cadence UNCOVERED.

RUNTIME. One promtool container per (scenario, evaluation interval), not per
cadence: every cadence in range is a separately NAMED case
(`cadence-<minutes>`) in one generated test file, and `--junit=<path>` recovers
which named cases failed. MEASURED (2026-08-10, this rung): promtool 3.13.1's
plain `FAILED:` text carries no case name on either stream, so a case-name
regex over it is not a fallback, it is impossible - `--junit` is the only
sound way to attribute a failure back to a cadence. Confirmed on a real
container run under the same hardening this script uses: a passing case is an
empty `<testcase>` (no `<failure>` child) and a failing one carries its
`<failure>` body, so an exact match between the submitted case-name set and
the recovered one is possible and required (`measure()` below) - a subset
check would silently tolerate promtool dropping a case.

The junit file is written through a SECOND, writable bind mount into an
otherwise `--read-only` container - the write-side of the exact 0700-mkdtemp
trap this file has hit before on the READ side (an earlier revision made its
scratch dir unreadable to the container's uid 65534 and misread "permission
denied" as "the alert fired"). Get this directory's mode wrong and promtool
cannot create the junit file at all, which must not be misread as zero
failures - see the defensive checks in `measure()`.

EXIT CONTRACT, mirroring `run_promtool_tests.py`'s SKIP-vs-FAIL convention:
  0  --check: the measured uncovered set matches the committed manifest.
  1  --check: it does not - unexpected/stale cadences are printed per scenario
     and interval.
  2  could not measure - a docker/promtool/junit problem, OR (check mode only)
     the manifest is missing or does not parse. Never treated as a verdict.
  77 docker unusable and the opt-in (`YUZU_TEST_ENABLE_PROMTOOL_DOCKER`) unset,
     and no usable native promtool of the pinned major on PATH - the same
     SKIP posture `run_promtool_tests.py` uses, and the same env var: this
     script now gates CI the same way that one does, so it inherits the same
     "a developer without the toolchain is not blocked" posture.

Usage:
  python3 tests/prometheus/blind_band_sweep.py                 # --check (default)
  python3 tests/prometheus/blind_band_sweep.py --emit > tests/prometheus/blind_band_manifest.json
  python3 tests/prometheus/blind_band_sweep.py --rules origin/dev --emit
  python3 tests/prometheus/blind_band_sweep.py --scenario anchored --alert SomeCandidateAlert --emit
"""
from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

import yaml

# Same directory as this file - Python puts the launching script's own
# directory on sys.path[0], so this needs no path surgery whether invoked
# directly or via a meson `_python3_test` entry.
from run_promtool_tests import (
    DOCKER_HARDENING,
    DOCKER_OPT_IN,
    PINNED_MAJOR,
    PROMTOOL_IMAGE,
    SKIP,
    docker_usable,
    native_promtool,
    pull_with_retry,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
RULES = "docs/prometheus/yuzu-alerts.yml"

# The scenario -> alert mapping is explicit and lives in the manifest schema
# too (`build_manifest`), not as a single top-level "scenario" field - rung B
# ships before `YuzuAuditRetentionNeverRan` exists, so the manifest has to be
# able to say which alert each scenario measures independently of whether that
# alert is in the rules file yet.
SCENARIO_ALERTS = {
    "anchored": "YuzuAuditRetentionNotRunning",
    "fresh": "YuzuAuditRetentionNeverRan",
}

DEFAULT_INTERVALS_S = (30, 60, 300)
DEFAULT_LOW, DEFAULT_HIGH, DEFAULT_STEP = 30, 240, 5
DEFAULT_MANIFEST = REPO_ROOT / "tests" / "prometheus" / "blind_band_manifest.json"

SETTLE_MIN = 3 * 60 + 20   # past the [3h] window plus the 15m `for:`


def rules_text(ref: str | None) -> str:
    if ref is None:
        return (REPO_ROOT / RULES).read_text(encoding="utf-8")
    out = subprocess.run(["git", "show", f"{ref}:{RULES}"], cwd=REPO_ROOT,
                         capture_output=True, text=True, check=True)
    return out.stdout


def extract(text: str, alert: str) -> tuple[dict, bool]:
    """The named alert's rule(s), and whether it exists in the file at all.

    DOES NOT sys.exit on absence, unlike the pre-rung-B version. `fresh`'s
    alertname (`YuzuAuditRetentionNeverRan`) does not exist until rung D lands,
    and rung B ships first by design (Sol's land-order review: the manifest
    and gate mechanics need independent review before the redesign changes
    what they gate) - so "alert not in the rules file yet" is an ordinary,
    expected state for this scenario during rung B/C, not a script bug. A
    future reader who "fixes" this back to fail-fast breaks every `fresh`
    manifest entry the moment this rung merges.
    """
    doc = yaml.safe_load(text)
    rules = [r for g in doc["groups"] for r in g.get("rules", [])
             if r.get("alert") == alert]
    if not rules:
        return {"groups": [{"name": "sweep", "rules": []}]}, False
    return {"groups": [{"name": "sweep", "rules": rules}]}, True


def cycles_for(cadence: int) -> int:
    """See `case()` - minimum full cycles so the eval grid actually reaches
    past `SETTLE_MIN` with margin, never fewer than 4 regardless of cadence."""
    return max(4, -(-(SETTLE_MIN + 3 * cadence) // cadence))


def case(cadence: int, interval_s: int, scenario: str, alert: str) -> dict:
    """One cadence, asserted COVERED (firing) at every eval point.

    THE GRID IS IN SECONDS, not rounded to the minute. A prior version computed
    `step = max(1, interval_s // 60)`, so a 30-second interval was still
    checked once per minute - the redesigned assertion needs to prove "fires
    at EVERY point", and a duty-cycle gap shorter than a minute could hide
    below that resolution. `eval_time` accepts bare-seconds duration strings
    (`"330s"`) - confirmed against the pinned image, not assumed from the
    PromQL duration grammar.

    THE ASSERTION WRAPS IN `count(...)` rather than naming `ALERTS{}`'s full
    label set. That set is whatever the rule's own `labels:` block plus its
    expression's inherited series labels produce, and differs between today's
    rule, rung C's new rule and rung D's redesign - hardcoding it would make
    this generator brittle to a relabel that has nothing to do with coverage.
    `count(ALERTS{alertname=..., alertstate="firing"})` aggregates to a single
    anonymous sample (`exp_samples: [{"labels": "{}", "value": 1}]`) when
    firing and to NO sample (`exp_samples: []`) when not - confirmed against
    the pinned image with both a firing and a non-firing probe rule.
    """
    cycles = cycles_for(cadence)
    total_min = cadence * cycles
    settle_s = SETTLE_MIN * 60
    total_s = total_min * 60
    points = list(range(settle_s, total_s - 120, interval_s))
    if not points:
        sys.exit(f"internal: cadence {cadence} at {interval_s}s produced no eval points")
    seg = f"0+60x{cadence - 1}"
    stamp_val = "1699000000" if scenario == "anchored" else "0"
    return {
        "interval": "1m",
        "name": f"cadence-{cadence}",
        "input_series": [
            {"series": 'yuzu_server_audit_retention_passes_total'
                       '{job="yuzu",instance="s1"}',
             "values": f"0+0x{total_min - 1}"},
            {"series": 'yuzu_server_uptime_seconds{job="yuzu",instance="s1"}',
             "values": " ".join([seg] * cycles)},
            {"series": 'yuzu_server_audit_retention_last_pass_unixtime'
                       '{job="yuzu",instance="s1"}',
             "values": f"{stamp_val}+0x{total_min - 1}"},
        ],
        "promql_expr_test": [
            {"expr": f'count(ALERTS{{alertname="{alert}", alertstate="firing"}})',
             "eval_time": f"{t}s",
             "exp_samples": [{"labels": "{}", "value": 1}]}
            for t in points
        ],
    }


class CouldNotMeasure(Exception):
    """A run that produced no evidence either way. Never becomes a verdict -
    see the exit-2 arm of `main()`. Named separately from a bare sys.exit so
    `full_sweep` can attribute the reason to the (scenario, interval) that hit
    it, matching `run_promtool_tests.py:413-441`'s rule that a FAILED-shaped
    result only counts once the run itself is proven sound."""


def resolve_promtool() -> tuple[str, list[str] | None]:
    """`("native", [path])` or `("docker", None)`. Exits 77 (SKIP) or fails,
    mirroring `run_promtool_tests.py`'s DOCKER_OPT_IN contract exactly - this
    script now gates CI the same way that one does, via the same env var, so a
    developer without the toolchain gets the same "not blocked" posture."""
    opted_in = bool(os.environ.get(DOCKER_OPT_IN))
    if not opted_in:
        native = native_promtool()
        if native is not None:
            exe, major = native
            if major == PINNED_MAJOR:
                print(f"using native promtool: {exe} (major {major})", flush=True)
                return "native", [exe]
            print(
                f"SKIP: {exe} is major {major}; this sweep is validated only against "
                f"major {PINNED_MAJOR} (range-selector semantics changed at 3.0, "
                f"which is exactly what this sweep measures). Set {DOCKER_OPT_IN}=1 "
                f"to use the pinned image instead.",
                flush=True,
            )
            sys.exit(SKIP)
        print(
            f"SKIP: no usable promtool on PATH and {DOCKER_OPT_IN} is unset. Set "
            f"{DOCKER_OPT_IN}=1 to run via the pinned image, or install a "
            f"{PINNED_MAJOR}.x promtool. CI runs this via the pinned image either way.",
            flush=True,
        )
        sys.exit(SKIP)
    if not docker_usable():
        print(f"FAIL: {DOCKER_OPT_IN} is set but docker is not usable.", flush=True)
        sys.exit(2)
    if not pull_with_retry():
        print(f"FAIL: could not pull {PROMTOOL_IMAGE}.", flush=True)
        sys.exit(2)
    return "docker", None


def measure(mode: str, native_argv: list[str] | None, tmp_root: Path,
           scenario: str, alert: str, rules: dict, cadences: list[int],
           interval_s: int) -> list[int]:
    """Uncovered cadences for one (scenario, interval) pair. Raises
    `CouldNotMeasure` rather than returning a guess on anything short of full
    evidence - see the module docstring's RUNTIME section for the junit
    write-mount and the exact-name-match rationale."""
    d = tmp_root / f"{scenario}-{interval_s}"
    for sub in ("rules", "tests", "out"):
        (d / sub).mkdir(parents=True, exist_ok=True)
    d.chmod(0o755)
    (d / "rules" / "r.yml").write_text(yaml.safe_dump(rules, sort_keys=False),
                                       encoding="utf-8")
    (d / "tests" / "t.yml").write_text(yaml.safe_dump({
        "rule_files": ["../rules/r.yml"],
        "evaluation_interval": f"{interval_s}s",
        "tests": [case(c, interval_s, scenario, alert) for c in cadences],
    }, sort_keys=False), encoding="utf-8")
    for sub in ("rules", "tests"):
        (d / sub).chmod(0o755)
        for f in (d / sub).iterdir():
            f.chmod(0o644)
    # The write side of the 0700-mkdtemp trap: uid 65534 (the image's user)
    # must be able to CREATE the junit file here, not merely read the tree.
    (d / "out").chmod(0o777)

    if mode == "docker":
        base = ["docker", "run", "--rm", "-v", f"{d}:/w:ro", *DOCKER_HARDENING,
                "--entrypoint", "/bin/promtool", PROMTOOL_IMAGE]
        run_argv = ["docker", "run", "--rm", "-v", f"{d}:/w:ro",
                    "-v", f"{d / 'out'}:/out:rw", *DOCKER_HARDENING,
                    "--entrypoint", "/bin/promtool", PROMTOOL_IMAGE]
        rules_path, tests_path, junit_container = "/w/rules/r.yml", "/w/tests/t.yml", "/out/result.xml"
    else:
        exe = native_argv[0]
        base = [exe]
        run_argv = [exe]
        rules_path = str(d / "rules" / "r.yml")
        tests_path = str(d / "tests" / "t.yml")
        junit_container = str(d / "out" / "result.xml")
    junit_host = d / "out" / "result.xml"

    try:
        check_p = subprocess.run(base + ["check", "rules", rules_path],
                                 capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        raise CouldNotMeasure(f"{scenario}@{interval_s}s: `check rules` timed out")
    m = re.search(r"SUCCESS:\s*(\d+)\s+rules found", check_p.stdout + check_p.stderr)
    if check_p.returncode != 0 or not m or int(m.group(1)) == 0:
        raise CouldNotMeasure(
            f"{scenario}@{interval_s}s: `check rules` did not confirm the generated "
            f"rules file loaded (rc {check_p.returncode}, out: "
            f"{(check_p.stdout + check_p.stderr).strip()[:300]})"
        )

    try:
        test_p = subprocess.run(
            run_argv + ["test", "rules", "--junit", junit_container, tests_path],
            capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        raise CouldNotMeasure(f"{scenario}@{interval_s}s: `test rules` timed out")

    if not junit_host.exists():
        raise CouldNotMeasure(
            f"{scenario}@{interval_s}s: promtool produced no junit file (rc "
            f"{test_p.returncode}) - cannot attribute any result to a cadence.\n"
            f"stdout/stderr: {(test_p.stdout + test_p.stderr).strip()[:400]}"
        )
    try:
        root = ET.parse(junit_host).getroot()
    except ET.ParseError as ex:
        raise CouldNotMeasure(f"{scenario}@{interval_s}s: junit output did not parse ({ex})")
    suite = root.find("testsuite")
    if suite is None:
        raise CouldNotMeasure(f"{scenario}@{interval_s}s: junit has no <testsuite>")
    if suite.get("errors", "0") != "0":
        raise CouldNotMeasure(
            f"{scenario}@{interval_s}s: junit reports {suite.get('errors')} error(s) "
            f"- an infrastructure problem, not a measurement"
        )

    seen = {tc.get("name"): tc.find("failure") is not None
            for tc in suite.findall("testcase")}
    submitted = {f"cadence-{c}" for c in cadences}
    if set(seen) != submitted:
        raise CouldNotMeasure(
            f"{scenario}@{interval_s}s: junit case names do not match the submitted "
            f"set - missing {sorted(submitted - set(seen))}, "
            f"extra {sorted(set(seen) - submitted)}. The run cannot be attributed "
            f"back to cadences."
        )
    any_failed = any(seen.values())
    if test_p.returncode == 0 and any_failed:
        raise CouldNotMeasure(
            f"{scenario}@{interval_s}s: promtool exited 0 but junit reports a "
            f"failure - inconsistent, trusted neither way"
        )
    if test_p.returncode != 0 and not any_failed:
        raise CouldNotMeasure(
            f"{scenario}@{interval_s}s: promtool exited {test_p.returncode} but "
            f"junit reports zero failures - an infrastructure error, not a "
            f"measurement (the run_promtool_tests.py FAILED-token lesson)"
        )
    return sorted(int(name.removeprefix("cadence-")) for name, failed in seen.items()
                 if failed)


def full_sweep(mode: str, native_argv: list[str] | None, rules_ref: str | None,
               scenarios: list[str], alerts: dict[str, str], intervals: tuple[int, ...],
               cadences: list[int], tmp_root: Path) -> dict:
    uncovered = {}
    for scenario in scenarios:
        alert = alerts[scenario]
        rules, found = extract(rules_text(rules_ref), alert)
        by_interval = {}
        for interval_s in intervals:
            if not found:
                # Selected-but-absent: fully uncovered by definition, not an
                # abort and not a docker call - `fresh` before rung D lands.
                by_interval[str(interval_s)] = list(cadences)
            else:
                by_interval[str(interval_s)] = measure(
                    mode, native_argv, tmp_root, scenario, alert, rules,
                    cadences, interval_s)
        uncovered[scenario] = {
            "alert": alert,
            "alert_present": found,
            "by_interval": by_interval,
        }
    return uncovered


def build_manifest(uncovered: dict, low: int, high: int, step: int,
                   intervals: tuple[int, ...]) -> dict:
    return {
        "note": (
            "Reflects TODAY'S rules file, measured with the inverted "
            "must-be-firing assertion. This is expected to be much wider than "
            "the historical 164-195 blind band, because the inversion sees the "
            "auto-resolve duty-cycle hole for the first time too - a long list "
            "here is the redesign's (#2854 rung D) target, not an instrument bug."
        ),
        "promtool_image": PROMTOOL_IMAGE,
        "grid": {"settle_minutes": SETTLE_MIN, "low": low, "high": high, "step": step},
        "intervals_s": list(intervals),
        "uncovered": uncovered,
    }


def compare(committed: dict, measured: dict, scenarios: list[str],
           intervals: tuple[int, ...]) -> list[tuple[str, int, list[int], list[int]]]:
    mismatches = []
    c_uncovered = committed.get("uncovered", {})
    m_uncovered = measured["uncovered"]
    for scenario in scenarios:
        c_by = c_uncovered.get(scenario, {}).get("by_interval", {})
        m_by = m_uncovered[scenario]["by_interval"]
        for interval_s in intervals:
            key = str(interval_s)
            c_set = set(c_by.get(key, []))
            m_set = set(m_by.get(key, []))
            unexpected = sorted(m_set - c_set)
            stale = sorted(c_set - m_set)
            if unexpected or stale:
                mismatches.append((scenario, interval_s, unexpected, stale))
    return mismatches


def selftest() -> int:
    """Pure logic only - no promtool, no docker, no network. Mirrors
    `run_promtool_tests.py --selftest`'s pattern and registers the same way in
    `tests/meson.build`, so it runs on all three required build legs."""
    failures = []

    def check(name: str, got, want):
        if got != want:
            failures.append(f"{name}: got {got!r}, want {want!r}")

    # cycles_for: known values, hand-computed against the formula's own
    # definition (ceil(SETTLE_MIN/cadence + 3), floored at 4).
    check("cycles_for(30)", cycles_for(30), 10)
    check("cycles_for(60)", cycles_for(60), 7)
    check("cycles_for(240)", cycles_for(240), 4)
    check("cycles_for(200) floors at settle", cycles_for(200), 4)

    # case(): the grid is seconds-resolution and starts exactly at settle.
    c = case(165, 30, "anchored", "YuzuAuditRetentionNotRunning")
    points = [int(t["eval_time"][:-1]) for t in c["promql_expr_test"]]
    check("case() grid starts at settle", points[0], SETTLE_MIN * 60)
    if len(points) > 1:
        check("case() grid step is the interval, not rounded to a minute",
              points[1] - points[0], 30)
    check("case() name embeds the cadence", c["name"], "cadence-165")
    check("case() assertion is count()-wrapped, not a labelled ALERTS match",
          c["promql_expr_test"][0]["expr"],
          'count(ALERTS{alertname="YuzuAuditRetentionNotRunning", alertstate="firing"})')
    check("case() firing assertion expects exactly one anonymous sample",
          c["promql_expr_test"][0]["exp_samples"], [{"labels": "{}", "value": 1}])

    # The two scenarios must produce different stamp series - this is the
    # entire reason the two scenarios exist as separate cases.
    anchored = case(60, 60, "anchored", "YuzuAuditRetentionNotRunning")
    fresh = case(60, 60, "fresh", "YuzuAuditRetentionNeverRan")
    anchored_stamp = anchored["input_series"][2]["values"]
    fresh_stamp = fresh["input_series"][2]["values"]
    check("anchored scenario stamps a constant non-zero value",
          anchored_stamp.startswith("1699000000+0x"), True)
    check("fresh scenario stamps flat 0", fresh_stamp.startswith("0+0x"), True)

    # extract(): present vs absent must not raise, and absence must not be
    # mistaken for an empty-but-loaded ruleset.
    present_doc = ("groups:\n  - name: g\n    rules:\n"
                  "      - alert: A\n        expr: up\n")
    rules, found = extract(present_doc, "A")
    check("extract() finds a present alert", found, True)
    check("extract() returns its rule", len(rules["groups"][0]["rules"]), 1)
    rules, found = extract(present_doc, "DoesNotExist")
    check("extract() reports absence rather than raising", found, False)
    check("extract() returns an empty (not missing) ruleset on absence",
          rules["groups"][0]["rules"], [])

    # compare(): the set-difference logic that drives the exit-1 path.
    committed = {"uncovered": {"anchored": {"by_interval": {"30": [165, 170]}}}}
    measured = {"uncovered": {"anchored": {"by_interval": {"30": [170, 175]}}}}
    mismatches = compare(committed, measured, ["anchored"], (30,))
    check("compare() finds exactly one mismatching (scenario, interval)",
          len(mismatches), 1)
    if mismatches:
        _, interval_s, unexpected, stale = mismatches[0]
        check("compare() interval", interval_s, 30)
        check("compare() unexpected = newly uncovered, not in the manifest",
              unexpected, [175])
        check("compare() stale = manifest says uncovered, measurement disagrees",
              stale, [165])
    check("compare() reports nothing when the sets match",
          compare({"uncovered": {"anchored": {"by_interval": {"30": [1]}}}},
                  {"uncovered": {"anchored": {"by_interval": {"30": [1]}}}},
                  ["anchored"], (30,)),
          [])

    for f in failures:
        print(f"SELFTEST FAIL: {f}", flush=True)
    print(f"selftest: {'FAIL' if failures else 'ok'}", flush=True)
    return 1 if failures else 0


def main() -> int:
    if "--selftest" in sys.argv[1:]:
        return selftest()
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true",
                    help="compare against the committed manifest (default action)")
    ap.add_argument("--emit", action="store_true",
                    help="print the measured manifest to stdout; never writes the file")
    ap.add_argument("--rules", default=None,
                    help="git ref to read the rules file from (default: worktree)")
    ap.add_argument("--alert", default=None,
                    help="override the mapped alertname; requires --scenario name one")
    ap.add_argument("--scenario", choices=("anchored", "fresh", "all"), default="all")
    ap.add_argument("--intervals", default=",".join(str(i) for i in DEFAULT_INTERVALS_S),
                    help="comma-separated evaluation intervals, in seconds")
    ap.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    ap.add_argument("--low", type=int, default=DEFAULT_LOW)
    ap.add_argument("--high", type=int, default=DEFAULT_HIGH)
    ap.add_argument("--step", type=int, default=DEFAULT_STEP)
    args = ap.parse_args()

    if args.emit and args.check:
        sys.exit("--emit and --check are mutually exclusive")

    scenarios = list(SCENARIO_ALERTS) if args.scenario == "all" else [args.scenario]
    alerts = dict(SCENARIO_ALERTS)
    if args.alert:
        if len(scenarios) != 1:
            sys.exit("--alert requires --scenario to name exactly one scenario")
        alerts[scenarios[0]] = args.alert

    try:
        intervals = tuple(int(x) for x in args.intervals.split(","))
    except ValueError:
        sys.exit(f"--intervals must be a comma-separated list of integers, got {args.intervals!r}")
    cadences = list(range(args.low, args.high + 1, args.step))

    # Every progress/diagnostic print during resolution and measurement goes to
    # STDERR, not stdout - `--emit`'s whole contract is that stdout carries
    # ONLY the manifest JSON so a caller can pipe it straight to a file.
    # `resolve_promtool`/`pull_with_retry`/`docker_usable` (imported from
    # `run_promtool_tests`) print progress via plain `print()`, which defaults
    # to stdout; redirecting the whole phase is simpler and less fragile than
    # auditing every import for where its output goes. `--check` doesn't need
    # this (nothing it prints is meant to be piped), but the redirect is
    # harmless there too, so it applies uniformly rather than branching.
    tmp = Path(tempfile.mkdtemp(prefix="yuzu_blind_band_"))
    try:
        try:
            with contextlib.redirect_stdout(sys.stderr):
                mode, native_argv = resolve_promtool()
                uncovered = full_sweep(mode, native_argv, args.rules, scenarios, alerts,
                                       intervals, cadences, tmp)
        except CouldNotMeasure as ex:
            print(f"COULD NOT MEASURE: {ex}", file=sys.stderr, flush=True)
            print("This is not a verdict.", file=sys.stderr, flush=True)
            return 2

        manifest = build_manifest(uncovered, args.low, args.high, args.step, intervals)

        if args.emit:
            print(json.dumps(manifest, indent=2, sort_keys=False))
            return 0

        # --check is the default action.
        if not args.manifest.exists():
            print(f"FAIL: manifest {args.manifest} not found - nothing to compare "
                 f"against. Not a verdict.", flush=True)
            return 2
        try:
            committed = json.loads(args.manifest.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as ex:
            print(f"FAIL: manifest {args.manifest} could not be parsed ({ex}). "
                 f"Not a verdict.", flush=True)
            return 2

        mismatches = compare(committed, manifest, scenarios, intervals)
        if mismatches:
            for scenario, interval_s, unexpected, stale in mismatches:
                print(f"{scenario}@{interval_s}s: unexpected={unexpected} stale={stale}",
                     flush=True)
            print(f"FAIL: measured coverage does not match {args.manifest}. Re-run "
                 f"with --emit and commit the result if this change is intended.",
                 flush=True)
            return 1
        print("OK: measured coverage matches the committed manifest.", flush=True)
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
