#!/usr/bin/env python3
"""flake-retry.py — CI flake-retry wrapper around `meson test` (Yuzu).

Runs `meson test`; every run — green included — then gets the #2093 duration
watchdog (a per-suite duration/budget table in the step summary + a ::warning
for any suite past 80% of its meson timeout; reporting only, pass/fail
semantics never change). On a clean pass, exits 0 with no retry machinery.
On failure it isolates the failed Catch2 case(s) and, for those listed in
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
list). Visibility is the job summary + annotations; recovered cases are also
written to meson-logs/flake-retry.json for import into the runner-local
test-runs.db. The static list remains the allowlist; DB history never changes
pass/fail semantics. Scope: ci.yml only (PR fast-path + push matrix);
nightly/sanitizer stay fail-loud. Not an ADR (reversible test tooling) —
rationale lives here and in docs/ci-architecture.md.

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
# A positional Catch2 tag-filter spec as used by sharded meson entries (#2092).
# Grammar: one or more comma-OR'd AND-groups, each group a run of ~?[tag].
# Examples: '[pg]', '~[pg]', '[a][b]', '~[a][b]', '[pg]~[routes]~[store]'
# (a single AND-group with mid-spec negations), and '[pg][routes],[pg][store]'
# (a comma-OR of AND-groups — the auth->PG [pg] rebalance split, #2394). Bare
# case-name specs still never match (no leading '['), so a case name is never
# mistaken for a strippable spec — the invariant _cmd_without_test_specs and
# the isolated retry rely on (a recognised spec is always stripped, so it can
# never OR with the retried case name).
CATCH2_TAG_SPEC = re.compile(r"^(~?\[[^\[\]]+\])+(,(~?\[[^\[\]]+\])+)*$")
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


def _entry_durations(builddir):
    """{meson-junit testcase name: wall seconds} from testlog.junit.xml.

    Meson writes one <testcase> per test() entry with a per-entry `time`
    attribute (the <testsuite> nodes carry aggregates we ignore). Defensive
    by design — this feeds pure reporting (#2093), so a missing file, parse
    error, or absent/garbled time attr degrades to "no row", never a crash.
    Duplicate names are summed."""
    xml_path = os.path.join(builddir, "meson-logs", "testlog.junit.xml")
    if not os.path.exists(xml_path):
        return {}
    try:
        tree = ET.parse(xml_path)
    except (ET.ParseError, OSError):
        return {}
    durations = {}
    for tc in tree.iter("testcase"):
        name = tc.get("name", "")
        try:
            secs = float(tc.get("time"))
        except (TypeError, ValueError):
            continue
        durations[name] = durations.get(name, 0.0) + secs
    return durations


def budget_rows(durations, tests):
    """Pure: [(display_name, secs, budget_or_None, frac_or_None)] per junit
    entry, mapping junit names to introspected entries via match_suite. The
    budget is the entry's meson timeout; falsy (0 = meson's "no timeout")
    becomes None, as does the whole budget for an unmappable name."""
    rows = []
    for junit_name in sorted(durations):
        secs = durations[junit_name]
        entry = match_suite(junit_name, tests)
        name = entry.get("name") if entry and entry.get("name") else junit_name
        budget = (entry.get("timeout") or None) if entry else None
        rows.append((name, secs, budget, (secs / budget) if budget else None))
    return rows


def report_suite_budgets(builddir, tests, warn_frac=0.8):
    """#2093: degrade duration creep toward a suite's meson timeout into a
    visible ::warning instead of a discontinuous red wall (the server suite
    crept 448s -> 512s/600 in green runs with zero signal before the
    2026-07-12 timeouts). Runs on every invocation — green included, that is
    the entire point — and never changes pass/fail semantics."""
    rows = budget_rows(_entry_durations(builddir), tests)
    if not rows:
        return
    for name, secs, budget, frac in rows:
        if frac is not None and frac > warn_frac:
            gh("warning",
               f"{name} at {secs:.0f}/{budget}s ({frac:.0%}) of its meson timeout — "
               f"split the suite or rebalance before this flakes (#2092, #2093)")
    lines = ["### Suite durations vs meson budgets", "",
             "| test entry | wall (s) | budget (s) | used |", "|---|---:|---:|---:|"]
    for name, secs, budget, frac in rows:
        lines.append(f"| {name} | {secs:.0f} | {f'{budget:g}' if budget else '—'} | "
                     f"{f'{frac:.0%}' if frac is not None else '—'} |")
    summary("\n".join(lines))


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
def _cmd_without_test_specs(cmd):
    """cmd minus positional Catch2 tag-filter specs.

    Sharded meson entries (#2092) carry a tag spec ('~[pg]' / '[pg]') in their
    args, and Catch2 ORs positional test specs — appending a case name to the
    introspected cmd would re-run the whole shard ∪ case. The isolated retry
    must REPLACE the shard filter with the case name. argv[0] and option args
    are never touched."""
    if not cmd:
        return []
    return [cmd[0]] + [a for a in cmd[1:] if not CATCH2_TAG_SPEC.match(a)]


def _run(cmd, env, workdir, extra=None, timeout=None):
    e = dict(os.environ)
    e.update(env or {})
    return subprocess.run(
        cmd + (extra or []), env=e, cwd=workdir or None,
        capture_output=True, text=True, timeout=timeout,
    )


def catch2_failed_cases(test, this_os):
    """Re-run a failed Catch2 suite with the junit reporter; return failed case
    names, or None if it isn't a classifiable Catch2 run (non-Catch2 / crash /
    hang). `timeout` mirrors the suite's own meson-configured timeout (falsy ->
    None, meson's own "no timeout" convention) so a genuine hang degrades to a
    clean unclassifiable result instead of blocking the job indefinitely — the
    observed failure mode this guards is a fast abnormal exit, not a hang, so
    this is a robustness net rather than a fix for that specific pattern."""
    # Deliberately keeps any shard tag-filter in cmd: the enumeration re-run
    # must only surface failures from THIS shard (#2092). Only the isolated
    # retry_case() strips it.
    cmd = test.get("cmd") or []
    if not cmd or not CATCH2_EXE.search(os.path.basename(cmd[0])):
        return None  # gateway (python) or anything not a Catch2 binary
    fd, xml_path = tempfile.mkstemp(suffix=".catch2.xml")
    os.close(fd)
    try:
        _run(cmd, test.get("env"), test.get("workdir"),
             extra=["--reporter", "junit", "--out", xml_path],
             timeout=test.get("timeout") or None)
        if not os.path.getsize(xml_path):
            return None  # crash/timeout before any reporter output -> unclassifiable
        return _failed_testcase_names(xml_path)
    except (ET.ParseError, OSError, subprocess.TimeoutExpired):
        return None
    finally:
        try:
            os.remove(xml_path)
        except OSError:
            pass


def retry_case(test, case, retries):
    """Return the 1-based retry attempt that passed, or 0 if none passed."""
    for attempt in range(1, retries + 1):
        try:
            result = _run(_cmd_without_test_specs(test.get("cmd") or []),
                          test.get("env"), test.get("workdir"), extra=[case],
                          timeout=test.get("timeout") or None)
        except subprocess.TimeoutExpired:
            continue
        if result.returncode == 0:
            return attempt
    return 0


def write_retry_report(builddir, this_os, recovered, blocked):
    """Persist retry evidence without changing the test process' result."""
    import json

    logs = os.path.join(builddir, "meson-logs")
    path = os.path.join(logs, "flake-retry.json")
    tmp = path + f".{os.getpid()}.tmp"
    payload = {
        "platform": this_os,
        "recovered": [
            {
                "case": case,
                "cross_platform": cross,
                "attempts": attempts,
            }
            for case, cross, attempts in recovered
        ],
        "blocked": list(blocked),
    }
    try:
        os.makedirs(logs, exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, sort_keys=True)
            f.write("\n")
        os.replace(tmp, path)
        return True
    except (OSError, TypeError, ValueError) as ex:
        try:
            os.remove(tmp)
        except OSError:
            pass
        gh(
            "warning",
            "flake retry report write failed "
            f"(reporting only, run unaffected): {ex}",
        )
        return False


# ── orchestration ─────────────────────────────────────────────────────────────
def main(argv=None):
    ap = argparse.ArgumentParser(description="meson test with known-flaky case retry")
    ap.add_argument("--builddir")  # required unless --selftest (validated below)
    ap.add_argument("--known-flaky", default="tests/known-flaky.json")
    ap.add_argument("--retries", type=int, default=2)
    ap.add_argument("--stale-days", type=int, default=90)
    ap.add_argument("--selftest", action="store_true", help="run internal logic checks and exit")
    ap.add_argument("meson_args", nargs="*", help="passthrough args after `--`")
    args = ap.parse_args(argv)

    if args.selftest:
        return _selftest()
    if not args.builddir:
        ap.error("--builddir is required (unless --selftest)")

    this_os = detect_os()
    # Validate the list up front (fail-fast on a malformed list).
    try:
        flaky = load_known_flaky(args.known_flaky, this_os, args.stale_days)
    except Exception as ex:  # noqa: BLE001 — surface any list error as a hard failure
        gh("error", f"known-flaky list invalid: {ex}")
        return 2

    # 1. Run meson test normally.
    rc = subprocess.run(["meson", "test", "-C", args.builddir] + args.meson_args).returncode

    # 2. Duration-vs-budget watchdog (#2093) — before the green early-return,
    #    because the creep it exists to surface happens in green runs. Hard
    #    exception-guarded: reporting must never turn a green run red (e.g.
    #    introspect returning rc 0 with garbled stdout, or a non-numeric
    #    timeout reaching the frac arithmetic).
    tests = []
    try:
        tests = introspect_tests(args.builddir)
        report_suite_budgets(args.builddir, tests)
    except Exception as ex:  # noqa: BLE001 — watchdog is reporting-only by contract
        # `tests` keeps whatever introspect managed to return ([] if it was
        # introspect itself that threw) — the failure path below re-uses it.
        gh("warning", f"suite-budget watchdog failed (reporting only, run unaffected): {ex}")

    if rc == 0:
        write_retry_report(args.builddir, this_os, [], [])
        return 0

    gh("notice", "meson test failed — checking whether every failure is a known flake")

    failed_suites = meson_failed_suites(args.builddir)
    if not failed_suites:
        gh("error", "test failed but no per-suite junit to classify — failing (no masking)")
        write_retry_report(
            args.builddir,
            this_os,
            [],
            ["test failed but no per-suite junit to classify"],
        )
        return rc or 1
    blocked = []      # case names that must fail the job
    recovered = []    # (case, cross_platform, retry_attempt) that recovered
    for suite_name in sorted(failed_suites):
        test = match_suite(suite_name, tests)
        if test is None:
            blocked.append(f"{suite_name} (could not map to a binary)")
            continue
        cases = catch2_failed_cases(test, this_os)
        if cases is None:
            blocked.append(f"{suite_name} (not a classifiable Catch2 run — crash/non-Catch2)")
            continue
        if not cases:
            # The suite failed under meson but a solo enumeration re-run
            # reproduced no failing case — an order/contention-dependent
            # failure (or a stale junit from a crashed previous run). Nothing
            # can be attributed to a listed flake, so returning 0 here would
            # mask a real red. Block, per the header contract.
            blocked.append(f"{suite_name} (suite failed but enumeration re-run "
                           f"reproduced no failing case — unclassifiable, no masking)")
            continue
        for case in sorted(cases):
            entry = flaky.get(case)
            if entry is None:
                blocked.append(case)
                continue
            passed_attempt = retry_case(test, case, args.retries)
            if passed_attempt:
                cross = "all" in entry.get("platforms", [])
                recovered.append((case, cross, passed_attempt))
            else:
                blocked.append(f"{case} (listed flake but failed all {args.retries} retries)")

    # Report.
    write_retry_report(args.builddir, this_os, recovered, blocked)
    for case, cross, _attempts in recovered:
        if cross:
            gh("warning", f"CROSS-PLATFORM flake recovered on retry (needs urgent fix): {case}")
        else:
            gh("notice", f"known flake recovered on retry: {case}")
    if recovered:
        lines = ["### flake-retry", "", "Recovered known flakes (passed on retry):", ""]
        lines += [
            f"- {'⚠️ **cross-platform** ' if cross else ''}`{case}` "
            f"(retry {attempts})"
            for case, cross, attempts in recovered
        ]
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

    # duration extraction + budget rows (#2093).
    with tempfile.TemporaryDirectory() as d:
        logs = os.path.join(d, "meson-logs")
        os.makedirs(logs)
        with open(os.path.join(logs, "testlog.junit.xml"), "w") as f:
            f.write('<testsuites><testsuite>'
                    '<testcase name="agent - yuzu:agent unit tests" time="200.5"/>'
                    '<testcase name="agent - yuzu:agent unit tests" time="0.5"/>'   # dup: summed
                    '<testcase name="docs - yuzu:changelog order"/>'                # no time: skipped
                    '<testcase name="tar - yuzu:tar unit tests" time="garbled"/>'   # bad time: skipped
                    '</testsuite></testsuites>')
        durations = _entry_durations(d)
        check(durations == {"agent - yuzu:agent unit tests": 201.0},
              "durations: sums dups, skips missing/garbled time attrs")
        check(_entry_durations(os.path.join(d, "nope")) == {}, "durations: missing junit -> {}")

    bt = [{"name": "agent unit tests", "timeout": 240}, {"name": "docs check", "timeout": 0}]
    rows = budget_rows({"agent - yuzu:agent unit tests": 201.0,
                        "docs - yuzu:docs check": 5.0,
                        "mystery - yuzu:unmapped entry": 1.0}, bt)
    by_name = {r[0]: r for r in rows}
    check(by_name["agent unit tests"][2] == 240 and abs(by_name["agent unit tests"][3] - 201.0 / 240) < 1e-9,
          "budget rows: maps junit name, computes frac")
    check(by_name["docs check"][2] is None and by_name["docs check"][3] is None,
          "budget rows: timeout 0 (meson no-timeout) -> no budget/frac")
    check(by_name["mystery - yuzu:unmapped entry"][2] is None,
          "budget rows: unmappable junit name keeps its name, no budget")
    # >80% predicate: 0.81 fires, 0.79 doesn't (frac > warn_frac).
    frac_hi = budget_rows({"a - yuzu:agent unit tests": 0.81 * 240}, bt)[0][3]
    frac_lo = budget_rows({"a - yuzu:agent unit tests": 0.79 * 240}, bt)[0][3]
    check(frac_hi > 0.8, "watchdog fires above 80%")
    check(not (frac_lo > 0.8), "watchdog silent below 80%")

    # report_suite_budgets end-to-end (#2093): the ::warning line and summary
    # table must actually emit — an inverted threshold or a formatting
    # exception would otherwise ship silently, since the watchdog is
    # reporting-only and nothing else exercises it.
    import contextlib
    import io
    with tempfile.TemporaryDirectory() as d:
        logs = os.path.join(d, "meson-logs")
        os.makedirs(logs)
        with open(os.path.join(logs, "testlog.junit.xml"), "w") as f:
            f.write('<testsuites><testsuite>'
                    '<testcase name="server - yuzu:server unit tests" time="510.0"/>'
                    '<testcase name="tar - yuzu:tar unit tests" time="12.0"/>'
                    '</testsuite></testsuites>')
        entries = [{"name": "server unit tests", "timeout": 600},
                   {"name": "tar unit tests", "timeout": 90}]
        summary_path = os.path.join(d, "summary.md")
        old_summary = os.environ.get("GITHUB_STEP_SUMMARY")
        os.environ["GITHUB_STEP_SUMMARY"] = summary_path
        try:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                report_suite_budgets(d, entries)
        finally:
            if old_summary is None:
                del os.environ["GITHUB_STEP_SUMMARY"]
            else:
                os.environ["GITHUB_STEP_SUMMARY"] = old_summary
        stdout = out.getvalue()
        check("::warning::" in stdout and "server unit tests at 510/600s (85%)" in stdout,
              "watchdog warning emits for the over-budget suite")
        check("tar unit tests" not in stdout, "no warning for the under-budget suite")
        with open(summary_path, encoding="utf-8") as f:
            table = f.read()
        check("### Suite durations vs meson budgets" in table
              and "| test entry | wall (s) | budget (s) | used |" in table,
              "summary table heading and header row written")
        check("| server unit tests | 510 | 600 | 85% |" in table
              and "| tar unit tests | 12 | 90 | 13% |" in table,
              "summary table rows written on green")

    # catch2 exe detection.
    check(CATCH2_EXE.search("yuzu_agent_tests.exe") is not None, "catch2 exe matches (win)")
    check(CATCH2_EXE.search("yuzu_server_tests") is not None, "catch2 exe matches (nix)")
    check(CATCH2_EXE.search("python3") is None, "python is not a catch2 exe")

    # suite matching.
    tests = [{"name": "agent unit tests", "cmd": ["x"]}, {"name": "tar unit tests", "cmd": ["y"]}]
    check(match_suite("agent - yuzu:agent unit tests", tests)["cmd"] == ["x"], "suite match")

    # sharded server suite (#2092): the two shard names must map uniquely
    # (neither is a substring of the other; longest-match protects prefixes).
    shards = [{"name": "server unit tests", "cmd": ["s", "~[pg]"]},
              {"name": "server pg unit tests", "cmd": ["s", "[pg]"]}]
    check(match_suite("server - yuzu:server unit tests", shards)["cmd"] == ["s", "~[pg]"],
          "non-pg shard maps to itself")
    check(match_suite("server - yuzu:server pg unit tests", shards)["cmd"] == ["s", "[pg]"],
          "pg shard maps to itself")

    # tag-spec surgery for isolated retries (#2092): strip positional tag
    # filters, keep argv[0] and option args, never invent args.
    check(_cmd_without_test_specs(["x", "~[pg]"]) == ["x"], "strips ~[pg]")
    check(_cmd_without_test_specs(["x", "[pg]"]) == ["x"], "strips [pg]")
    check(_cmd_without_test_specs(["x", "--foo", "[a][b]"]) == ["x", "--foo"],
          "strips compound tag spec, keeps options")
    check(_cmd_without_test_specs(["x"]) == ["x"], "no-spec cmd unchanged")
    check(_cmd_without_test_specs([]) == [], "empty cmd stays empty")
    check(_cmd_without_test_specs(["~[pg]", "[pg]"]) == ["~[pg]"],
          "argv[0] untouched even when spec-shaped")
    check(_cmd_without_test_specs(["x", "~[a][b]"]) == ["x"], "strips tilde compound spec")
    check(_cmd_without_test_specs(["x", "[pg]~[routes]~[store]~[token]"]) == ["x"],
          "strips mid-spec-negation shard filter (#2394)")
    check(_cmd_without_test_specs(["x", "[pg][routes],[pg][store],[pg][token]"]) == ["x"],
          "strips comma-OR shard filter (#2394)")
    check(_cmd_without_test_specs(["x", "a normal, prose case name"])
          == ["x", "a normal, prose case name"],
          "prose case name with a comma is NOT a spec (kept)")
    check(_cmd_without_test_specs(["x", "[.]"]) == ["x"], "strips hidden-tag spec")
    check(_cmd_without_test_specs(["x", ""]) == ["x", ""], "empty arg kept (not a spec)")

    # Repo-hygiene guard (#2092): every positional arg on the server test()
    # entries in tests/meson.build must be a Catch2 tag-filter spec — the
    # invariant the retry surgery relies on. A future case-name or comma-list
    # spec would OR with the retried case and corrupt recovery verdicts; this
    # catches it at test time instead of in a masked flake.
    meson_build = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "..", "..", "tests", "meson.build")
    with open(meson_build, encoding="utf-8") as f:
        _src = f.read()
    # Entry-shaped parse (kwarg order and line breaks don't matter): grab
    # every test(..., server_test_exe, ...) body, then any args: [...] list
    # inside it. An args-less entry has no positional specs to strip, so it
    # is correctly exempt; both shard entries must be found and args-carrying
    # or the guard fails loudly instead of silently inspecting half the
    # surface.
    _entries = re.findall(r"test\(\s*'[^']*',\s*server_test_exe\b(.*?)\)", _src, re.S)
    check(len(_entries) >= 4, "meson.build: all four server shard entries located")
    _shard_specs = []
    for _body in _entries:
        # Quote-aware list match: a naive [(.*?)] truncates at the tag spec's
        # own inner ']' and validates nothing (found independently by two
        # governance reviewers) — the ']' inside a quoted string must be
        # consumed by the string alternative, not end the list.
        _m = re.search(r"args:\s*\[((?:\s*'[^']*'\s*,?)*)\]", _body, re.S)
        if not _m:
            continue  # an args-less entry has no positional specs to strip
        _args = re.findall(r"'([^']*)'", _m.group(1))
        check(bool(_args), "meson.build: args-carrying server entry extracted non-empty")
        for _arg in _args:
            check(CATCH2_TAG_SPEC.match(_arg) is not None,
                  f"meson.build server test arg {_arg!r} is not a tag-filter spec")
        _shard_specs.append(tuple(_args))
    # Positive pin so hollow extraction can never pass again: the shard filters
    # must come back verbatim. A shard add or rebalance updates this line
    # consciously. #2394 split the single '[pg]' entry into two balanced halves
    # (the auth->PG cutover ~doubled the [pg] population). #2395 then split the
    # non-PG '~[pg]' entry the same way, after it reached 603/600s (101%) on
    # Windows; the partition is [auth]+[mcp] vs the rest, balanced by measured
    # time rather than case count ([auth] alone is ~40% of the non-PG runtime).
    check(("~[pg][auth],~[pg][mcp]",) in _shard_specs
          and ("~[pg]~[auth]~[mcp]",) in _shard_specs
          and ("[pg][routes],[pg][store],[pg][token]",) in _shard_specs
          and ("[pg]~[routes]~[store]~[token]",) in _shard_specs,
          "meson.build: all four shard tag filters extracted verbatim")

    if failures:
        print("SELFTEST FAILURES:", *failures, sep="\n  ")
        return 1
    print("flake-retry selftest: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
