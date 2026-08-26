#!/usr/bin/env python3
"""check-pg-shard-partition.py — prove the PG-tagged Catch2 case population is
exactly partitioned across this build's ``server-pg``-suite meson test()
entries: every ``[pg]`` case lands in exactly one shard, none lost, none
duplicated.

Replaces flake-retry.py's old verbatim positional-filter pin (a hardcoded
copy of every shard's tag-filter string, hand-updated on every split/
rebalance — missed 3 times in the same number of weeks, each time reddening
CI unconditionally; see tests/meson.build's shard-history comment). That pin
only ever proved the filter strings hadn't silently changed since the last
person to update it looked. This proves the actual property that matters —
exact partitioning of the real case population — against the compiled
binary, not against a remembered snapshot.

Runs as its own meson test() entry (suite: 'server'), NOT inside the cheap
flake-retry selftest (suite: 'docs'): it needs the real yuzu_server_tests
binary built, which the docs suite deliberately does not depend on. No
Postgres connection needed — --list-tests only enumerates registered
TEST_CASE macros, it never executes a test body.

Discovery is via `meson introspect <builddir> --tests`, keyed on suite
membership (yuzu:server-pg), not a hardcoded shard-name list — so a shard
add/split/rebalance needs no update here at all, only a correct suite: kwarg
on the new/changed test() entry in tests/meson.build.

Escape hatch if this checker itself is wrong: revert this file's own
test() block in tests/meson.build ('server pg shard partition invariant',
tests/meson.build's `if build_server` scope — not Linux-only). This is the
one COMPLETE single-edit de-wire: it stops the check on every leg that
builds the server, including Windows and macOS. Removing the
'server pg shard partition invariant' token from ci.yml's Linux
flake-retry.py invocation line (governance Gate 8, sre, #3443) is NOT
equivalent and covers Linux only — the Windows and macOS legs invoke
flake-retry.py with no --suite/name filter at all (it passes straight
through to `meson test`), so they would keep running this test regardless
of that edit. The separate 'check-pg-shard-partition selftest' entry
(suite: 'docs', added alongside test_check_pg_shard_partition.py) is
untouched by either revert and stays running — it exercises only synthetic
fixtures and asserts nothing about real shard state, so it is harmless to
leave in place while this checker itself is being fixed or reverted.

Pure logic (`parse_shard_entries`, `check_partition`) is separated from I/O
(`introspect_tests`, `list_cases`, `main`) specifically so it can be
exercised with synthetic fixtures, no real build or binary needed — see
test_check_pg_shard_partition.py, which follows the same in-process
synthetic-fixture precedent as flake-retry.py's own --selftest (not its
separate fake-PATH-stub subprocess tests) for the same reason: a future
regression in THIS script's own detection logic (not the shards it checks)
should fail a fast, no-build docs-suite test, not require another manual
mutation-test session.
"""
import argparse
import json
import subprocess
import sys
import xml.etree.ElementTree as ET  # stdlib, not defusedxml: this parses our
# own yuzu_server_tests --list-tests output, not external input — same trust
# model as flake-retry.py's and test_db.py's existing JUnit parsing, which
# also use stdlib ElementTree; defusedxml isn't a dependency anywhere in
# this repo's CI tooling and adding it for one script would be inconsistent
# with that precedent for no real risk reduction here.

SERVER_PG_SUITE = "yuzu:server-pg"


def gh(kind, msg):
    """Emit a GitHub Actions annotation (::warning::/::notice::/::error::).

    Mirrors flake-retry.py's own gh() helper — every failure path in this
    script routes through here now, not just some of them (governance Gate 4
    consistency-auditor F2: the partition-violation findings, this script's
    entire reason to exist, previously got a plain stderr print with no GH
    inline-annotation prefix, unlike every shape-violation exit path in the
    same file).
    """
    print(f"::{kind}::{msg}", flush=True)


def introspect_tests(builddir):
    out = subprocess.run(
        ["meson", "introspect", builddir, "--tests"],
        capture_output=True, text=True, check=True,
    )
    return json.loads(out.stdout)


def parse_shard_entries(tests):
    """Return (entries, errors) for every server-pg-suite entry in `tests`.

    entries: [(name, exe, tag_filter_spec), ...] for well-shaped entries.
    errors: human-readable strings for every malformed entry found.

    Pure function — no I/O, no sys.exit — so a synthetic `tests` list (as
    `meson introspect --tests` would emit) exercises this without a real
    build. Collects EVERY malformed entry rather than stopping at the first
    (governance Gate 4 consistency-auditor F2): two simultaneously-broken
    shard entries used to report only the first found.

    A server-pg entry must carry the exe as cmd[0] and exactly one
    positional (non-'-'-prefixed) tag-filter spec as its only other cmd
    element — this mirrors the same hygiene guard flake-retry.py's selftest
    already enforces (options are permitted, e.g. --allow-running-no-tests
    on an all-skip shard; two or more positional specs, or zero, is a shape
    violation).
    """
    entries = []
    errors = []
    for t in tests:
        if SERVER_PG_SUITE not in t.get("suite", []):
            continue
        cmd = t.get("cmd", [])
        name = t.get("name", "<unnamed>")
        if len(cmd) < 2:
            errors.append(f"{name!r} in suite {SERVER_PG_SUITE!r} has no "
                           f"positional Catch2 spec")
            continue
        exe, rest = cmd[0], cmd[1:]
        specs = [a for a in rest if not a.startswith("-")]
        opts = [a for a in rest if a.startswith("-")]
        if len(specs) != 1:
            errors.append(f"{name!r} must carry exactly one positional "
                           f"tag-filter spec, found {specs!r} (options "
                           f"{opts!r} are fine, e.g. --allow-running-no-tests)")
            continue
        entries.append((name, exe, specs[0]))
    return entries, errors


def list_cases(exe, filt):
    """Case identities (name, file, line) matched by `exe --list-tests filt`.

    XML reporter, not the plain --list-tests text output: Catch2 wraps long
    test names across multiple lines in the plain form, which is ambiguous
    to parse back into individual case names. --list-tests needs no
    Postgres DSN and never executes a test body — pure enumeration.
    """
    out = subprocess.run(
        [exe, "--list-tests", "--reporter", "xml", filt],
        capture_output=True, text=True, check=True,
    )
    return parse_list_tests_xml(out.stdout)


def parse_list_tests_xml(xml_text):
    """Case identities (name, file, line) from a Catch2 `--list-tests --reporter
    xml` document. Pure function, separated from the subprocess call so a
    synthetic XML string exercises it without a real binary."""
    root = ET.fromstring(xml_text)
    cases = set()
    for tc in root.findall(".//TestCase"):
        name = tc.findtext("Name")
        src = tc.find("SourceInfo")
        file_ = src.findtext("File") if src is not None else None
        line = src.findtext("Line") if src is not None else None
        cases.add((name, file_, line))
    return cases


def _fmt_case(c):
    """'name (file:line)' for a (name, file, line) tuple, consistent everywhere
    a case identity is shown in a failure message (governance Gate 3
    quality-engineer LOW: the missing/extra branches previously showed only
    names, unlike the duplicate branch, which already showed file:line)."""
    return f"{c[0]!r} ({c[1]}:{c[2]})"


def check_partition(entries, list_cases_fn):
    """Given well-shaped shard entries and a case-lookup callable
    (filter_spec -> set of (name, file, line)), prove: (a) every case the
    reference `[pg]` filter matches lands in exactly one shard's matched
    set, (b) no shard's filter matches a case outside that reference set.

    Pure with respect to I/O — `list_cases_fn` is injected so this can run
    against a real compiled binary (main(), below) or against a synthetic
    fixture (test_check_pg_shard_partition.py), with identical set-math
    either way. Returns (ok: bool, failures: list[str], stats: dict).
    """
    exes = {e for _, e, _ in entries}
    if len(exes) != 1:
        return False, [f"server-pg shards use {len(exes)} different binaries "
                        f"({sorted(exes)!r}) — expected exactly one"], {}
    exe = exes.pop()

    full_ref = list_cases_fn(exe, "[pg]")
    if not full_ref:
        return False, ["'[pg]' matched zero cases on this binary — the "
                        "reference set itself is empty"], {}

    seen = {}
    union = set()
    failures = []
    for name, _exe, spec in entries:
        cases = list_cases_fn(exe, spec)
        if not cases:
            failures.append(f"shard {name!r} (spec {spec!r}) matched ZERO cases")
        for c in cases:
            if c in seen:
                failures.append(f"case {_fmt_case(c)} appears in BOTH "
                                 f"{seen[c]!r} and {name!r} — not a partition")
            else:
                seen[c] = name
        union |= cases

    missing = full_ref - union
    extra = union - full_ref
    if missing:
        sample = ", ".join(_fmt_case(c) for c in sorted(missing)[:5])
        failures.append(f"{len(missing)} case(s) tagged [pg] are in NO shard: "
                         f"{sample}" + (" ..." if len(missing) > 5 else ""))
    if extra:
        sample = ", ".join(_fmt_case(c) for c in sorted(extra)[:5])
        failures.append(f"{len(extra)} case(s) matched by a shard filter but "
                         f"not in the [pg] reference set: {sample}"
                         + (" ..." if len(extra) > 5 else ""))

    stats = {"shard_count": len(entries), "case_count": len(full_ref)}
    return not failures, failures, stats


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--builddir", required=True)
    args = ap.parse_args(argv)

    tests = introspect_tests(args.builddir)
    entries, shape_errors = parse_shard_entries(tests)
    if shape_errors:
        for e in shape_errors:
            gh("error", f"check-pg-shard-partition: {e}")
        return 1

    if len(entries) < 2:
        gh("error", f"check-pg-shard-partition: found only {len(entries)} "
                     f"entries in suite {SERVER_PG_SUITE!r} — hollow "
                     f"discovery (expected the full set of pg shards)")
        return 1

    ok, failures, stats = check_partition(entries, list_cases)
    if not ok:
        for f in failures:
            gh("error", f"check-pg-shard-partition: {f}")
        return 1

    print(f"check-pg-shard-partition: OK — {stats['shard_count']} shards, "
          f"{stats['case_count']} cases, exact partition (no loss, no "
          f"duplication)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
