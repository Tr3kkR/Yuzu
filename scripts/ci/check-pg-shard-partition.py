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


def introspect_tests(builddir):
    out = subprocess.run(
        ["meson", "introspect", builddir, "--tests"],
        capture_output=True, text=True, check=True,
    )
    return json.loads(out.stdout)


def shard_entries(tests):
    """Return [(name, exe, tag_filter_spec), ...] for every server-pg-suite entry.

    Fails loud (not silently-empty) on any entry shaped wrong: a server-pg
    entry must carry the exe as cmd[0] and exactly one positional (non-'-'
    prefixed) tag-filter spec as its only other cmd element — this mirrors
    the same hygiene guard flake-retry.py's selftest already enforces
    (options are permitted, e.g. --allow-running-no-tests on an all-skip
    shard; two or more positional specs, or zero, is a shape violation).
    """
    entries = []
    for t in tests:
        if SERVER_PG_SUITE not in t.get("suite", []):
            continue
        cmd = t.get("cmd", [])
        name = t.get("name", "<unnamed>")
        if len(cmd) < 2:
            sys.exit(f"::error::check-pg-shard-partition: {name!r} in suite "
                      f"{SERVER_PG_SUITE!r} has no positional Catch2 spec")
        exe, rest = cmd[0], cmd[1:]
        specs = [a for a in rest if not a.startswith("-")]
        opts = [a for a in rest if a.startswith("-")]
        if len(specs) != 1:
            sys.exit(f"::error::check-pg-shard-partition: {name!r} must carry "
                      f"exactly one positional tag-filter spec, found {specs!r} "
                      f"(options {opts!r} are fine, e.g. --allow-running-no-tests)")
        entries.append((name, exe, specs[0]))
    return entries


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
    root = ET.fromstring(out.stdout)
    cases = set()
    for tc in root.findall(".//TestCase"):
        name = tc.findtext("Name")
        src = tc.find("SourceInfo")
        file_ = src.findtext("File") if src is not None else None
        line = src.findtext("Line") if src is not None else None
        cases.add((name, file_, line))
    return cases


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--builddir", required=True)
    args = ap.parse_args(argv)

    tests = introspect_tests(args.builddir)
    entries = shard_entries(tests)
    if len(entries) < 2:
        sys.exit(f"::error::check-pg-shard-partition: found only "
                  f"{len(entries)} entries in suite {SERVER_PG_SUITE!r} — "
                  f"hollow discovery (expected the full set of pg shards)")

    exes = {e for _, e, _ in entries}
    if len(exes) != 1:
        sys.exit(f"::error::check-pg-shard-partition: server-pg shards use "
                  f"{len(exes)} different binaries ({sorted(exes)!r}) — "
                  f"expected exactly one")
    exe = exes.pop()

    full_ref = list_cases(exe, "[pg]")
    if not full_ref:
        sys.exit("::error::check-pg-shard-partition: '[pg]' matched zero "
                  "cases on this binary — the reference set itself is empty")

    seen = {}
    union = set()
    failures = []
    for name, _exe, spec in entries:
        cases = list_cases(exe, spec)
        if not cases:
            failures.append(f"shard {name!r} (spec {spec!r}) matched ZERO cases")
        for c in cases:
            if c in seen:
                failures.append(f"case {c[0]!r} ({c[1]}:{c[2]}) appears in "
                                 f"BOTH {seen[c]!r} and {name!r} — not a partition")
            else:
                seen[c] = name
        union |= cases

    missing = full_ref - union
    extra = union - full_ref
    if missing:
        sample = ", ".join(sorted(c[0] for c in missing)[:5])
        failures.append(f"{len(missing)} case(s) tagged [pg] are in NO shard: "
                         f"{sample}" + (" ..." if len(missing) > 5 else ""))
    if extra:
        sample = ", ".join(sorted(c[0] for c in extra)[:5])
        failures.append(f"{len(extra)} case(s) matched by a shard filter but "
                         f"not in the [pg] reference set: {sample}"
                         + (" ..." if len(extra) > 5 else ""))

    if failures:
        print("PARTITION CHECK FAILURES:", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1

    print(f"check-pg-shard-partition: OK — {len(entries)} shards, "
          f"{len(full_ref)} cases, exact partition (no loss, no duplication)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
