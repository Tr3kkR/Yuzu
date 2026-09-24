#!/usr/bin/env python3
"""Unit test for assert-suite-cover.py's own detection logic — synthetic
`meson introspect --tests` fixtures, no real build needed. Same pure/IO
split precedent as test_check_pg_shard_partition.py.

Run: python3 scripts/ci/test_assert_suite_cover.py   (exit 0 = pass)
"""
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
MODULE_PATH = os.path.join(HERE, "assert-suite-cover.py")

_spec = importlib.util.spec_from_file_location("assert_suite_cover", MODULE_PATH)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)


def _entry(name, suites):
    """One `meson introspect --tests` entry with project-namespaced suites,
    e.g. suites=['agent'] -> {'suite': ['yuzu:agent']}."""
    return {"name": name, "suite": [f"yuzu:{s}" for s in suites]}


def check(cond, label, failures):
    if cond:
        print(f"  ok       {label}")
    else:
        print(f"  FAIL     {label}")
        failures.append(label)


def test_clean_coverage(failures):
    tests = [
        _entry("agent unit tests", ["agent"]),
        _entry("tar unit tests", ["tar"]),
        _entry("server pg unit tests shard C", ["server", "server-pg"]),
    ]
    ok, fail_msgs, stats = _mod.compute_coverage(
        tests, {"agent", "tar"}, {"server-pg"})
    check(ok, "clean: reports OK", failures)
    check(fail_msgs == [], "clean: no failure messages", failures)
    check(stats == {"selected": 2, "excluded": 1, "skipped": 0, "total": 3},
          "clean: stats correct", failures)


def test_missing_entry_neither_selected_nor_excluded(failures):
    # The core property: an entry in neither bucket must be caught, not
    # silently dropped (the exact Windows hazard this script exists for).
    tests = [
        _entry("agent unit tests", ["agent"]),
        _entry("orphan test", ["docs"]),  # neither --suite'd nor excluded
    ]
    ok, fail_msgs, _ = _mod.compute_coverage(tests, {"agent"}, {"server-pg"})
    check(not ok, "missing: reports not-ok", failures)
    check(any("orphan test" in m for m in fail_msgs),
          "missing: failure message names the uncovered entry", failures)


def test_project_namespace_stripped(failures):
    # meson introspection ALWAYS project-prefixes suite strings
    # ('yuzu:agent', not 'agent') — a naive bare-string comparison would
    # treat every entry as uncovered. This proves the prefix is stripped.
    tests = [_entry("agent unit tests", ["agent"])]
    ok, fail_msgs, stats = _mod.compute_coverage(tests, {"agent"}, set())
    check(ok, "namespace: prefixed suite matches the bare --suite name", failures)
    check(stats["selected"] == 1, "namespace: entry counted as selected", failures)


def test_suite_flag_matches_zero_entries(failures):
    # A real --suite typo looks EXACTLY like this — must fail loud, the
    # opposite of meson's own silent-zero-match --suite semantics.
    tests = [_entry("agent unit tests", ["agent"])]
    ok, fail_msgs, _ = _mod.compute_coverage(tests, {"agent", "aegnt"}, set())
    check(not ok, "zero-hit suite: reports not-ok", failures)
    check(any("aegnt" in m and "ZERO" in m for m in fail_msgs),
          "zero-hit suite: failure message names the unmatched suite", failures)


def test_empty_test_inventory(failures):
    ok, fail_msgs, _ = _mod.compute_coverage([], {"agent"}, set())
    check(not ok, "empty inventory: reports not-ok", failures)
    check(any("zero test entries" in m for m in fail_msgs),
          "empty inventory: failure message says so", failures)


def test_selected_and_excluded_conflict(failures):
    # A suite named in BOTH --suite and --exclude-suite is a caller error,
    # not a valid state (would otherwise let a "deliberately excluded"
    # suite quietly become covered, or vice versa).
    ok, fail_msgs, _ = _mod.compute_coverage(
        [_entry("x", ["agent"])], {"agent"}, {"agent"})
    check(not ok, "conflict: reports not-ok", failures)
    check(any("both covered" in m or "same suite" in m for m in fail_msgs),
          "conflict: failure message names the conflicting suite", failures)


def test_entry_carries_both_selected_and_excluded_suite(failures):
    # A single entry that happens to carry both a --suite'd label and an
    # --exclude-suite label (e.g. a mislabeled test() carrying suite:
    # ['server-nonpg', 'server-pg']) is a real, catchable defect distinct
    # from the CLI-flag conflict above.
    tests = [_entry("mislabeled", ["server-nonpg", "server-pg"])]
    ok, fail_msgs, _ = _mod.compute_coverage(
        tests, {"server-nonpg"}, {"server-pg"})
    check(not ok, "entry conflict: reports not-ok", failures)
    check(any("mislabeled" in m and "BOTH" in m for m in fail_msgs),
          "entry conflict: failure message names the conflicting entry", failures)


def test_skipped_suite_is_out_of_scope_and_counted(failures):
    # A PR that cannot reach the server family skips those suites; the proof
    # must still hold (every entry accounted for) and the count must be visible.
    tests = [
        _entry("agent unit tests", ["agent"]),
        _entry("server unit tests shard A", ["server", "server-nonpg"]),
        _entry("server pg shard partition invariant", ["server", "server-checks"]),
        _entry("server pg unit tests shard C", ["server", "server-pg"]),
    ]
    ok, fail_msgs, stats = _mod.compute_coverage(
        tests, {"agent"}, {"server-pg"},
        skipped_suites={"server-nonpg", "server-checks"})
    check(ok, "skipped: proof holds with skipped suites out of scope", failures)
    check(fail_msgs == [], "skipped: no failure messages", failures)
    check(stats == {"selected": 1, "excluded": 1, "skipped": 2, "total": 4},
          "skipped: counted apart from excluded", failures)


def test_skipped_suite_does_not_hide_an_uncovered_entry(failures):
    # The point of the proof: naming a suite as skipped must not swallow an
    # entry that is in a DIFFERENT suite nobody accounted for.
    tests = [
        _entry("agent unit tests", ["agent"]),
        _entry("server unit tests shard A", ["server", "server-nonpg"]),
        _entry("orphan test", ["docs"]),
    ]
    ok, fail_msgs, _ = _mod.compute_coverage(
        tests, {"agent"}, set(), skipped_suites={"server-nonpg"})
    check(not ok, "skipped+orphan: reports not-ok", failures)
    check(any("orphan test" in m for m in fail_msgs),
          "skipped+orphan: names the uncovered entry", failures)


def test_skipped_and_selected_conflict(failures):
    # Skipping a suite the same invocation selects is a wiring bug (the flag
    # arrays in ci.yml disagree), not a valid state.
    ok, fail_msgs, _ = _mod.compute_coverage(
        [_entry("x", ["agent"])], {"agent"}, set(), skipped_suites={"agent"})
    check(not ok, "skipped conflict: reports not-ok", failures)
    check(any("agent" in m and "same suite" in m for m in fail_msgs),
          "skipped conflict: names the suite", failures)


def test_entry_in_both_excluded_and_skipped_counts_once(failures):
    # server-pg is excluded in the non-pg step AND would be named by a
    # careless caller as skipped too; the entry must count once, as excluded.
    tests = [_entry("pg shard", ["server", "server-pg"]),
             _entry("agent unit tests", ["agent"])]
    ok, _, stats = _mod.compute_coverage(
        tests, {"agent"}, {"server-pg"}, skipped_suites={"server-pg"})
    # server-pg named on both sides: the same-suite check is only against
    # --suite, so this is legal and must not double-count.
    check(ok, "excluded+skipped overlap: reports ok", failures)
    check(stats["excluded"] == 1 and stats["skipped"] == 0,
          "excluded+skipped overlap: counted once, as excluded", failures)


def test_entry_selected_and_skipped_label_is_a_conflict(failures):
    # An entry carrying a selected label AND a skipped label is the same
    # mislabel defect the excluded case catches.
    tests = [_entry("mislabeled", ["agent", "server-checks"])]
    ok, fail_msgs, _ = _mod.compute_coverage(
        tests, {"agent"}, set(), skipped_suites={"server-checks"})
    check(not ok, "entry selected+skipped: reports not-ok", failures)
    check(any("mislabeled" in m and "BOTH" in m for m in fail_msgs),
          "entry selected+skipped: names the entry", failures)


def test_extra_suite_selected_but_unused_is_fine(failures):
    # Selecting a --suite that genuinely has no current entries (e.g. a
    # suite reserved for a future test category) is NOT the same failure
    # as a typo — meson itself would still no-op cleanly. This script
    # treats "matched zero" as an error regardless (see test above) by
    # design: an intentionally-unused --suite flag should be removed from
    # the invocation, not left in "just in case". Documented, not a gap.
    pass


def test_main_forwards_skipped_suites(failures):
    # main() is what the Windows leg runs; the first real --skipped-suite call is a PR that skips a
    # family, so drive it here with a stubbed introspection instead of waiting for one.
    import contextlib
    import io
    tests = [_entry("agent unit tests", ["agent"]), _entry("docs lint", ["docs"]),
             _entry("server shard A", ["server", "server-nonpg"])]
    real = _mod.introspect_tests
    _mod.introspect_tests = lambda builddir: tests
    try:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = _mod.main(["--builddir", "b", "--suite", "docs", "--suite", "agent",
                            "--skipped-suite", "server-nonpg"])
        check(rc == 0 and "1 skipped as unaffected" in out.getvalue()
              and "(server-nonpg)" in out.getvalue(),
              "main(): --skipped-suite reaches the proof and the OK line names it", failures)
        with contextlib.redirect_stdout(io.StringIO()):
            rc = _mod.main(["--builddir", "b", "--suite", "docs", "--suite", "agent"])
        check(rc == 1, "main(): a family neither selected nor skipped still fails", failures)
    finally:
        _mod.introspect_tests = real


def main():
    failures = []
    test_clean_coverage(failures)
    test_missing_entry_neither_selected_nor_excluded(failures)
    test_project_namespace_stripped(failures)
    test_suite_flag_matches_zero_entries(failures)
    test_empty_test_inventory(failures)
    test_selected_and_excluded_conflict(failures)
    test_entry_carries_both_selected_and_excluded_suite(failures)
    test_extra_suite_selected_but_unused_is_fine(failures)
    test_skipped_suite_is_out_of_scope_and_counted(failures)
    test_skipped_suite_does_not_hide_an_uncovered_entry(failures)
    test_skipped_and_selected_conflict(failures)
    test_entry_in_both_excluded_and_skipped_counts_once(failures)
    test_entry_selected_and_skipped_label_is_a_conflict(failures)
    test_main_forwards_skipped_suites(failures)

    if failures:
        print(f"\nassert-suite-cover selftest: {len(failures)} FAILED")
        return 1
    print("\nassert-suite-cover selftest: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
