#!/usr/bin/env python3
"""Zero-executed guard for the Meson gateway test wrapper (#4800).

Imported by scripts/test_gateway.py and pinned by
tests/test_gateway_test_summary.py. Kept in its own module (not inline in
the wrapper) because the wrapper runs rebar3 at import time and so cannot
be imported by a test.

"""
import re
import sys

# rebar3 exits 0 when it discovers nothing to run, so a green exit code
# alone proves nothing. A run is only a pass if its final summary line
# reports at least one EXECUTED (passed + failed) test. Summary shapes:
#   ct:    "All 52 tests passed."
#          "Failed 6 tests. Skipped 2 (0, 2) tests. Passed 44 tests."
#   eunit: "All 311 tests passed."
#          "Failed: 2.  Skipped: 0.  Passed: 309."
#          "There were no tests to run."
# The LAST summary wins (rebar3 prints one per run; anything earlier is
# test-emitted noise). No recognisable summary on an otherwise-green run
# is ALSO a failure: we cannot confirm anything ran.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_SUMMARY_RE = re.compile(
    # ct and eunit, all green
    r"All (?P<all>\d+) tests? passed\."
    # eunit, exactly one test
    r"|(?P<one>\bTest passed\.)"
    # ct: each clause is printed only when its count is non-zero, except
    # "Passed", which is always printed
    r"|(?:Failed (?P<cf>\d+) tests?\. )?(?:Skipped \d+ \(\d+, \d+\) tests?\. )?"
    r"Passed (?P<cp>\d+) tests?\."
    # eunit, any failure/skip
    r"|Failed: (?P<ef>\d+)\.\s+Skipped: \d+\.\s+Passed: (?P<ep>\d+)\."
    r"|(?P<none>There were no tests to run)"
)


def executed_count(text):
    """Executed (passed + failed) count from the last summary, or None."""
    last = None
    for m in _SUMMARY_RE.finditer(_ANSI_RE.sub("", text)):
        last = m
    if last is None:
        return None
    g = last.group
    if g("all") is not None:
        return int(g("all"))
    if g("one") is not None:
        return 1
    if g("none") is not None:
        return 0
    if g("cp") is not None:
        return int(g("cf") or 0) + int(g("cp"))
    return int(g("ef")) + int(g("ep"))


def require_tests_executed(text, label, returncode):
    """Turn a green exit with zero executed tests into a failure."""
    if returncode != 0:
        return returncode
    executed = executed_count(text)
    if executed is None:
        print(f"\n[test_gateway.py] {label}: rebar3 exited 0 but printed no "
              "recognisable test summary -- cannot confirm any test ran. "
              "Failing (#4800).", file=sys.stderr)
        return 1
    if executed == 0:
        print(f"\n[test_gateway.py] {label}: rebar3 exited 0 but executed ZERO "
              "tests -- the suite directory or --dir is wrong. Failing so this "
              "cannot pass as a false green (#4800).", file=sys.stderr)
        return 1
    print(f"\n[test_gateway.py] {label}: {executed} tests executed.")
    return 0
