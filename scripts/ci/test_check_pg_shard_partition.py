#!/usr/bin/env python3
"""Unit test for check-pg-shard-partition.py's own detection logic.

Governance Gate 3/4 finding (#3443 Phase 1): the checker shipped with no
permanent regression test of its own — only ad-hoc, uncommitted manual
mutation testing done once during development (a gap, a duplication, a
shard silently dropping suite membership). Every comparable local
CI-tooling self-test (flake-retry.py --selftest, check-plugin-spawn-
lexical.sh --selftest, tsan-gdb-capture.py --selftest) exercises its own
parsing/decision logic against synthetic fixtures, independent of a real
build. This does the same, exercising `parse_shard_entries()` and
`check_partition()` directly against synthetic `meson introspect --tests`
JSON and synthetic Catch2 `--list-tests --reporter xml` output — no real
build, no real yuzu_server_tests binary needed, matching the pure/IO
split the script itself was refactored to have for exactly this reason.

Run: python3 scripts/ci/test_check_pg_shard_partition.py   (exit 0 = pass)
"""
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
MODULE_PATH = os.path.join(HERE, "check-pg-shard-partition.py")

_spec = importlib.util.spec_from_file_location("check_pg_shard_partition", MODULE_PATH)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

SUITE = _mod.SERVER_PG_SUITE


def _entry(name, exe="/fake/exe", spec="[pg][x]", extra_args=None):
    """One `meson introspect --tests` entry, server-pg-suite by default."""
    cmd = [exe, spec] + (extra_args or [])
    return {"name": name, "cmd": cmd, "suite": ["yuzu:server", SUITE]}


def _xml(cases):
    """Synthetic Catch2 `--list-tests --reporter xml` document for `cases`,
    a list of (name, file, line) tuples."""
    body = "".join(
        f'<TestCase><Name>{n}</Name><ClassName/><Tags/>'
        f'<SourceInfo><File>{f}</File><Line>{l}</Line></SourceInfo></TestCase>'
        for n, f, l in cases
    )
    return f'<?xml version="1.0"?><MatchingTests>{body}</MatchingTests>'


def check(cond, label, failures):
    if cond:
        print(f"  ok       {label}")
    else:
        print(f"  FAIL     {label}")
        failures.append(label)


def test_parse_shard_entries_happy_path(failures):
    tests = [
        _entry("server pg unit tests shard A", spec="[pg][a]"),
        _entry("server pg unit tests shard B", spec="[pg][b]"),
        {"name": "unrelated docs test", "cmd": ["x"], "suite": ["yuzu:docs"]},
        {"name": "non-pg server test", "cmd": ["x", "~[pg]"], "suite": ["yuzu:server"]},
    ]
    entries, errors = _mod.parse_shard_entries(tests)
    check(errors == [], "happy path: no shape errors", failures)
    check(len(entries) == 2, "happy path: only the 2 server-pg entries found", failures)
    check(entries[0] == ("server pg unit tests shard A", "/fake/exe", "[pg][a]"),
          "happy path: entry tuple shape correct", failures)


def test_parse_shard_entries_collects_all_shape_errors(failures):
    # Governance Gate 4 consistency-auditor F2: two simultaneously-malformed
    # entries must BOTH be reported, not just the first.
    tests = [
        {"name": "shard broken zero specs", "cmd": ["/fake/exe"],
         "suite": ["yuzu:server", SUITE]},
        {"name": "shard broken two specs",
         "cmd": ["/fake/exe", "[pg][a]", "[pg][b]"],
         "suite": ["yuzu:server", SUITE]},
    ]
    entries, errors = _mod.parse_shard_entries(tests)
    check(entries == [], "two malformed entries: zero well-shaped entries returned", failures)
    check(len(errors) == 2, "two malformed entries: BOTH errors collected, not just the first", failures)
    check(any("shard broken zero specs" in e for e in errors),
          "zero-spec entry's error present", failures)
    check(any("shard broken two specs" in e for e in errors),
          "two-spec entry's error present", failures)


def test_parse_shard_entries_options_are_fine(failures):
    tests = [_entry("shard with option", extra_args=["--allow-running-no-tests"])]
    entries, errors = _mod.parse_shard_entries(tests)
    check(errors == [], "a -- option alongside one spec is not a shape error", failures)
    check(len(entries) == 1, "entry with an option still extracted", failures)


def test_check_partition_clean(failures):
    entries = [("shard A", "/fake/exe", "[pg][a]"), ("shard B", "/fake/exe", "[pg][b]")]
    cases_by_spec = {
        "[pg]": {("t1", "f.cpp", "1"), ("t2", "f.cpp", "2")},
        "[pg][a]": {("t1", "f.cpp", "1")},
        "[pg][b]": {("t2", "f.cpp", "2")},
    }
    ok, fail_msgs, stats = _mod.check_partition(
        entries, lambda exe, spec: cases_by_spec[spec])
    check(ok, "clean partition: reports OK", failures)
    check(fail_msgs == [], "clean partition: no failure messages", failures)
    check(stats == {"shard_count": 2, "case_count": 2}, "clean partition: stats correct", failures)


def test_check_partition_gap(failures):
    # A case tagged [pg] that no shard's filter matches.
    entries = [("shard A", "/fake/exe", "[pg][a]")]
    cases_by_spec = {
        "[pg]": {("t1", "f.cpp", "1"), ("t2", "f.cpp", "2")},
        "[pg][a]": {("t1", "f.cpp", "1")},
    }
    ok, fail_msgs, _ = _mod.check_partition(entries, lambda exe, spec: cases_by_spec[spec])
    check(not ok, "gap: reports not-ok", failures)
    check(any("in NO shard" in m and "t2" in m for m in fail_msgs),
          "gap: failure message names the orphaned case", failures)
    check(any("(f.cpp:2)" in m for m in fail_msgs),
          "gap: failure message includes file:line (quality-engineer LOW)", failures)


def test_check_partition_duplication(failures):
    entries = [("shard A", "/fake/exe", "[pg][a]"), ("shard B", "/fake/exe", "[pg][b]")]
    cases_by_spec = {
        "[pg]": {("t1", "f.cpp", "1")},
        "[pg][a]": {("t1", "f.cpp", "1")},
        "[pg][b]": {("t1", "f.cpp", "1")},  # same case, claimed by both
    }
    ok, fail_msgs, _ = _mod.check_partition(entries, lambda exe, spec: cases_by_spec[spec])
    check(not ok, "duplication: reports not-ok", failures)
    check(any("appears in BOTH" in m and "t1" in m for m in fail_msgs),
          "duplication: failure message names the duplicated case", failures)


def test_check_partition_extra(failures):
    # A shard filter matches a case NOT tagged [pg] at all (over-broad filter).
    entries = [("shard A", "/fake/exe", "[pg][a]")]
    cases_by_spec = {
        "[pg]": {("t1", "f.cpp", "1")},
        "[pg][a]": {("t1", "f.cpp", "1"), ("stray", "f.cpp", "9")},
    }
    ok, fail_msgs, _ = _mod.check_partition(entries, lambda exe, spec: cases_by_spec[spec])
    check(not ok, "extra: reports not-ok", failures)
    check(any("not in the [pg] reference set" in m and "stray" in m for m in fail_msgs),
          "extra: failure message names the over-matched case", failures)


def test_check_partition_multiple_binaries(failures):
    entries = [("shard A", "/exe/one", "[pg][a]"), ("shard B", "/exe/two", "[pg][b]")]
    ok, fail_msgs, _ = _mod.check_partition(entries, lambda exe, spec: {("t", "f", "1")})
    check(not ok, "multiple binaries: reports not-ok", failures)
    check(any("different binaries" in m for m in fail_msgs),
          "multiple binaries: failure message names the mismatch", failures)


def test_check_partition_empty_reference(failures):
    entries = [("shard A", "/fake/exe", "[pg][a]")]
    ok, fail_msgs, _ = _mod.check_partition(entries, lambda exe, spec: set())
    check(not ok, "empty reference set: reports not-ok", failures)
    check(any("reference set itself is empty" in m for m in fail_msgs),
          "empty reference set: failure message says so", failures)


def test_check_partition_zero_case_shard(failures):
    entries = [("shard A", "/fake/exe", "[pg][a]"), ("shard B", "/fake/exe", "[pg][b]")]
    cases_by_spec = {
        "[pg]": {("t1", "f.cpp", "1")},
        "[pg][a]": {("t1", "f.cpp", "1")},
        "[pg][b]": set(),  # a shard whose filter matches nothing
    }
    ok, fail_msgs, _ = _mod.check_partition(entries, lambda exe, spec: cases_by_spec[spec])
    check(not ok, "zero-case shard: reports not-ok", failures)
    check(any("matched ZERO cases" in m and "shard B" in m for m in fail_msgs),
          "zero-case shard: failure message names the empty shard", failures)


def test_parse_list_tests_xml(failures):
    xml = _xml([("RbacStore: thing", "test_rbac_store.cpp", "42")])
    cases = _mod.parse_list_tests_xml(xml)
    check(cases == {("RbacStore: thing", "test_rbac_store.cpp", "42")},
          "parse_list_tests_xml: extracts (name, file, line) correctly", failures)


def main():
    failures = []
    test_parse_shard_entries_happy_path(failures)
    test_parse_shard_entries_collects_all_shape_errors(failures)
    test_parse_shard_entries_options_are_fine(failures)
    test_check_partition_clean(failures)
    test_check_partition_gap(failures)
    test_check_partition_duplication(failures)
    test_check_partition_extra(failures)
    test_check_partition_multiple_binaries(failures)
    test_check_partition_empty_reference(failures)
    test_check_partition_zero_case_shard(failures)
    test_parse_list_tests_xml(failures)

    if failures:
        print(f"\ncheck-pg-shard-partition selftest: {len(failures)} FAILED")
        return 1
    print("\ncheck-pg-shard-partition selftest: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
