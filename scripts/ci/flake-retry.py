#!/usr/bin/env python3
"""flake-retry.py — CI flake-retry wrapper around `meson test` (Yuzu).

Runs `meson test`; on a clean pass, exits 0 and does nothing else. On failure
it isolates the failed Catch2 case(s) and, for those listed in
`tests/known-flaky.json` (scoped to the current OS), retries them in isolation.

Outcome contract:
  - Any failed case NOT in the list (for this OS)  -> job FAILS (real regression).
  - A failed suite we cannot classify per-case
    (non-Catch2 e.g. gateway, crash/timeout, no junit) -> job FAILS (never mask).
  - A listed case that fails ALL retries           -> job FAILS (regression in a
                                                       flaky test still blocks).
  - Every failed case is a listed flake that recovers within --retries -> PASS.

Cross-platform entries (`"platforms": ["all"]`) are still retried but emit a
loud ::warning (and MUST carry an `issue`); OS-scoped entries emit a ::notice.

Design was grilled 2026-06-22 (mechanism "C": case-level retry + static in-repo
list). No DB — visibility is the job summary + annotations; trend is deferred to
a future `ci-ingest`-style step. Scope: ci.yml only (PR fast-path + push
matrix); nightly/sanitizer stay fail-loud. Not an ADR (reversible test tooling)
— rationale lives here and in docs/ci-architecture.md.

Effective attempts for a flaky case = original in-suite run + one enumeration
re-run (to find which cases failed) + up to --retries isolated re-runs.
"""
import argparse
import os
import platform
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from datetime import date, datetime

CATCH2_EXE = re.compile(r"yuzu_\w+_tests(\.exe)?$", re.IGNORECASE)
VALID_PLATFORMS = {"windows", "linux", "macos", "all"}


def detect_os():
    s = platform.system()
    return {"Darwin": "macos", "Windows": "windows", "Linux": "linux"}.get(s, s.lower())


def gh(kind, msg):
    """Emit a GitHub Actions annotation (::warning::/::notice::/::error::)."""
    print(f"::{kind}::{msg}", flush=True)


def summary(md):
    """Append a markdown block to the job summary, if running under Actions."""
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        try:
            with open(path, "a", encoding="utf-8") as f:
                f.write(md + "\n")
        except OSError:
            pass


# ── known-flaky.json ──────────────────────────────────────────────────────────
def load_known_flaky(path, this_os, stale_days):
    """Parse + validate the list; return {case_name: entry} applicable to this_os.

    Fail-fast (raise ValueError) on a malformed list so a structural typo can't
    silently disable protection. Emit a ::warning for entries older than
    stale_days (soft nag — never a hard failure).
    """
    if not os.path.exists(path):
        return {}
    import json

    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError(f"{path}: top level must be a JSON array")

    applicable = {}
    today = date.today()
    for i, e in enumerate(data):
        where = f"{path}[{i}]"
        if not isinstance(e, dict):
            raise ValueError(f"{where}: entry must be an object")
        case = e.get("case")
        plats = e.get("platforms")
        if not isinstance(case, str) or not case:
            raise ValueError(f"{where}: missing/empty 'case'")
        if not isinstance(plats, list) or not plats or any(p not in VALID_PLATFORMS for p in plats):
            raise ValueError(f"{where} ({case}): 'platforms' must be a non-empty subset of {sorted(VALID_PLATFORMS)}")
        if not e.get("reason"):
            raise ValueError(f"{where} ({case}): missing 'reason'")
        cross_platform = "all" in plats
        if cross_platform and not e.get("issue"):
            raise ValueError(f"{where} ({case}): cross-platform ('all') entries must carry an 'issue'")
        # Soft staleness nag (by added-date age).
        added = e.get("added")
        if isinstance(added, str):
            try:
                age = (today - datetime.strptime(added, "%Y-%m-%d").date()).days
                if age > stale_days:
                    gh("warning", f"known-flaky entry is {age}d old (>{stale_days}) — re-evaluate or fix: {case}")
            except ValueError:
                gh("warning", f"known-flaky entry has unparseable 'added' ({added!r}): {case}")
        if cross_platform or this_os in plats:
            applicable[case] = e
    return applicable


# ── junit parsing ─────────────────────────────────────────────────────────────
def _failed_testcase_names(xml_path):
    """Return the set of <testcase> names that carry a <failure>/<error> child."""
    failed = set()
    tree = ET.parse(xml_path)
    for tc in tree.iter("testcase"):
        if tc.find("failure") is not None or tc.find("error") is not None:
            failed.add(tc.get("name", ""))
    return failed


def meson_failed_suites(builddir):
    """Suite-level: which meson test()s failed (names from meson's junit)."""
    xml_path = os.path.join(builddir, "meson-logs", "testlog.junit.xml")
    if not os.path.exists(xml_path):
        return None  # no junit -> caller treats as unclassifiable
    return _failed_testcase_names(xml_path)


# ── meson introspection: suite name -> binary command ─────────────────────────
def introspect_tests(builddir):
    out = subprocess.run(
        ["meson", "introspect", builddir, "--tests"],
        capture_output=True, text=True,
    )
    if out.returncode != 0:
        return []
    import json

    return json.loads(out.stdout)


def match_suite(failed_name, tests):
    """Map a meson-junit failed-suite name to its introspected test (cmd/env)."""
    # meson junit names look like "agent - yuzu:agent unit tests"; the
    # introspect `name` ("agent unit tests") is a substring. Longest match wins.
    best = None
    for t in tests:
        n = t.get("name", "")
        if n and n in failed_name and (best is None or len(n) > len(best.get("name", ""))):
            best = t
    return best


# ── running Catch2 binaries ───────────────────────────────────────────────────
def _run(cmd, env, workdir, extra=None):
    e = dict(os.environ)
    e.update(env or {})
    return subprocess.run(
        cmd + (extra or []), env=e, cwd=workdir or None,
        capture_output=True, text=True,
    )


def catch2_failed_cases(test, this_os):
    """Re-run a failed Catch2 suite with the junit reporter; return failed case
    names, or None if it isn't a classifiable Catch2 run (non-Catch2 / crash)."""
    cmd = test.get("cmd") or []
    if not cmd or not CATCH2_EXE.search(os.path.basename(cmd[0])):
        return None  # gateway (python) or anything not a Catch2 binary
    fd, xml_path = tempfile.mkstemp(suffix=".catch2.xml")
    os.close(fd)
    try:
        _run(cmd, test.get("env"), test.get("workdir"),
             extra=["--reporter", "junit", "--out", xml_path])
        if not os.path.getsize(xml_path):
            return None  # crash/timeout before any reporter output -> unclassifiable
        return _failed_testcase_names(xml_path)
    except (ET.ParseError, OSError):
        return None
    finally:
        try:
            os.remove(xml_path)
        except OSError:
            pass


def retry_case(test, case, retries):
    """Re-run a single Catch2 case by exact name up to `retries` times; True if
    any attempt passes."""
    for _ in range(retries):
        if _run(test.get("cmd"), test.get("env"), test.get("workdir"), extra=[case]).returncode == 0:
            return True
    return False


# ── orchestration ─────────────────────────────────────────────────────────────
def main(argv=None):
    ap = argparse.ArgumentParser(description="meson test with known-flaky case retry")
    ap.add_argument("--builddir", required=True)
    ap.add_argument("--known-flaky", default="tests/known-flaky.json")
    ap.add_argument("--retries", type=int, default=2)
    ap.add_argument("--stale-days", type=int, default=90)
    ap.add_argument("--selftest", action="store_true", help="run internal logic checks and exit")
    ap.add_argument("meson_args", nargs="*", help="passthrough args after `--`")
    args = ap.parse_args(argv)

    if args.selftest:
        return _selftest()

    this_os = detect_os()
    # Validate the list up front (fail-fast on a malformed list).
    try:
        flaky = load_known_flaky(args.known_flaky, this_os, args.stale_days)
    except Exception as ex:  # noqa: BLE001 — surface any list error as a hard failure
        gh("error", f"known-flaky list invalid: {ex}")
        return 2

    # 1. Run meson test normally.
    rc = subprocess.run(["meson", "test", "-C", args.builddir] + args.meson_args).returncode
    if rc == 0:
        return 0

    gh("notice", "meson test failed — checking whether every failure is a known flake")

    failed_suites = meson_failed_suites(args.builddir)
    if not failed_suites:
        gh("error", "test failed but no per-suite junit to classify — failing (no masking)")
        return rc or 1

    tests = introspect_tests(args.builddir)
    blocked = []      # case names that must fail the job
    recovered = []    # (case, cross_platform) that recovered
    for suite_name in sorted(failed_suites):
        test = match_suite(suite_name, tests)
        if test is None:
            blocked.append(f"{suite_name} (could not map to a binary)")
            continue
        cases = catch2_failed_cases(test, this_os)
        if cases is None:
            blocked.append(f"{suite_name} (not a classifiable Catch2 run — crash/non-Catch2)")
            continue
        for case in sorted(cases):
            entry = flaky.get(case)
            if entry is None:
                blocked.append(case)
                continue
            if retry_case(test, case, args.retries):
                cross = "all" in entry.get("platforms", [])
                recovered.append((case, cross))
            else:
                blocked.append(f"{case} (listed flake but failed all {args.retries} retries)")

    # Report.
    for case, cross in recovered:
        if cross:
            gh("warning", f"CROSS-PLATFORM flake recovered on retry (needs urgent fix): {case}")
        else:
            gh("notice", f"known flake recovered on retry: {case}")
    if recovered:
        lines = ["### flake-retry", "", "Recovered known flakes (passed on retry):", ""]
        lines += [f"- {'⚠️ **cross-platform** ' if c else ''}`{n}`" for n, c in recovered]
        summary("\n".join(lines))

    if blocked:
        for b in blocked:
            gh("error", f"unrecovered test failure (blocking): {b}")
        summary("### flake-retry\n\nBlocking failures: " + ", ".join(f"`{b}`" for b in blocked))
        return 1
    return 0


# ── self-test (pure logic; runs without a build) ──────────────────────────────
def _selftest():
    import json

    failures = []

    def check(cond, label):
        if not cond:
            failures.append(label)

    # OS-scoping + cross-platform validation via a temp list file.
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "kf.json")
        with open(p, "w") as f:
            json.dump([
                {"case": "Win Only", "platforms": ["windows"], "reason": "r"},
                {"case": "Everywhere", "platforms": ["all"], "reason": "r", "issue": "#1"},
            ], f)
        win = load_known_flaky(p, "windows", 90)
        lin = load_known_flaky(p, "linux", 90)
        check("Win Only" in win and "Everywhere" in win, "windows sees both")
        check("Win Only" not in lin and "Everywhere" in lin, "linux sees only cross-platform")

        # cross-platform without issue must fail-fast.
        with open(p, "w") as f:
            json.dump([{"case": "X", "platforms": ["all"], "reason": "r"}], f)
        try:
            load_known_flaky(p, "linux", 90)
            check(False, "missing-issue cross-platform should raise")
        except ValueError:
            pass

        # malformed (missing reason) must fail-fast.
        with open(p, "w") as f:
            json.dump([{"case": "X", "platforms": ["windows"]}], f)
        try:
            load_known_flaky(p, "windows", 90)
            check(False, "missing-reason should raise")
        except ValueError:
            pass

    # junit parsing.
    with tempfile.TemporaryDirectory() as d:
        x = os.path.join(d, "t.xml")
        with open(x, "w") as f:
            f.write('<testsuites><testsuite><testcase name="A"/>'
                    '<testcase name="B"><failure>x</failure></testcase></testsuite></testsuites>')
        check(_failed_testcase_names(x) == {"B"}, "junit picks only failed cases")

    # catch2 exe detection.
    check(CATCH2_EXE.search("yuzu_agent_tests.exe") is not None, "catch2 exe matches (win)")
    check(CATCH2_EXE.search("yuzu_server_tests") is not None, "catch2 exe matches (nix)")
    check(CATCH2_EXE.search("python3") is None, "python is not a catch2 exe")

    # suite matching.
    tests = [{"name": "agent unit tests", "cmd": ["x"]}, {"name": "tar unit tests", "cmd": ["y"]}]
    check(match_suite("agent - yuzu:agent unit tests", tests)["cmd"] == ["x"], "suite match")

    if failures:
        print("SELFTEST FAILURES:", *failures, sep="\n  ")
        return 1
    print("flake-retry selftest: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
