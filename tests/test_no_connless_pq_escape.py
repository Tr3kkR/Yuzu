#!/usr/bin/env python3
"""#1611 tripwire: no first-party call to libpq's conn-less escape APIs.

tests/unit/test_runner_main.cpp compiles a TSan suppression for libpq's
static_std_strings / static_client_encoding globals (written on every
connection's ParameterStatus in fe-exec.c's pqSaveParameterStatus). That
suppression is honest ONLY while nothing in this tree reads those globals, and
libpq's only readers are the conn-less PQescapeString / PQescapeBytea. A new
caller would turn a benign write-write race into a real, now-silenced
read-write race, so this test fails on the first such reference — not just a
call with an immediately-following '(', but any bare identifier reference
(covers function pointers / aliasing too), with one deliberate exception (see
EXCLUDE_PATHS below). The Conn-suffixed variants (PQescapeStringConn,
PQescapeByteaConn, PQescapeLiteral, PQescapeIdentifier) take a PGconn and are
NOT matched. Wired into tests/meson.build (suite 'docs') and docs-lint.yml
(merge ref).
"""
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ROOTS = ["server", "common", "agents", "sdk", "gateway", "tests", "tools"]
EXTS = (".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hxx", ".mm", ".m")
PATTERN = re.compile(r"\bPQescapeString\b|\bPQescapeBytea\b")
SELF = Path(__file__).resolve()

# Deliberate, narrow exclusion (mirrors test_split_interlock_tripwire.py's
# `excluded` mechanism: a recorded rationale, never a silent skip). Keyed on
# the repo-relative path exactly as `git ls-files` reports it, so the
# exclusion holds in both the worktree and a CI checkout.
#
# tests/unit/test_runner_main.cpp is the file that DOCUMENTS this suppression
# (it quotes libpq's own comment naming PQescapeString/PQescapeBytea to
# explain what the __tsan_default_suppressions hook silences and why that's
# safe). It #includes no libpq header and calls neither function - the hits
# there are prose, not a call site. Excluding it by name, rather than
# rewording the comment to dodge this pattern or stripping comments before
# matching (which adds its own failure surface, e.g. '//' inside a string
# literal), keeps the explanatory comment intact and the check itself simple.
# A rename moves the comment's path out of this set and the wire fires again
# until the entry is updated - fail-loud in the direction that matters.
EXCLUDE_PATHS = {
    "tests/unit/test_runner_main.cpp": (
        "documents the #1611 TSan suppression by name; no libpq include, no call"
    ),
}


def _selfcheck() -> None:
    # Explicit raises, not `assert`: python3 -O strips asserts.
    must_match = [
        "x = PQescapeString(to, from, n);",
        "PQescapeBytea (b, n, &m)",
        "auto fp = &PQescapeString;",  # bare identifier, no paren adjacent
        "/* PQescapeString */ foo();",
    ]
    must_not = [
        "PQescapeStringConn(conn, to, from, n, &e)",
        "PQescapeByteaConn(conn, b, n, &m)",
        "PQescapeLiteral(conn, s, n)",
        "PQescapeIdentifier(conn, s, n)",
    ]
    for s in must_match:
        if not PATTERN.search(s):
            raise SystemExit(f"selfcheck: pattern failed to match {s!r}")
    for s in must_not:
        if PATTERN.search(s):
            raise SystemExit(f"selfcheck: pattern wrongly matched {s!r}")


def main() -> int:
    _selfcheck()
    out = subprocess.run(
        ["git", "ls-files", "--", *ROOTS],
        cwd=REPO_ROOT, capture_output=True, text=True, check=True,
    ).stdout
    hits = []
    for rel in out.splitlines():
        if not rel.endswith(EXTS):
            continue
        if rel in EXCLUDE_PATHS:
            continue
        p = REPO_ROOT / rel
        if p == SELF or not p.is_file():
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        for n, line in enumerate(text.splitlines(), 1):
            if PATTERN.search(line):
                hits.append(f"{rel}:{n}: {line.strip()}")
    if hits:
        print(
            "FAIL: conn-less PQescapeString/PQescapeBytea reference(s) found. They\n"
            "read libpq's static_std_strings/static_client_encoding, which\n"
            "tests/unit/test_runner_main.cpp suppresses under TSan (#1611).\n"
            "Use PQescapeStringConn/PQescapeByteaConn or pg::exec_params instead:"
        )
        print("\n".join(hits))
        return 1
    print("OK: no conn-less PQescapeString/PQescapeBytea references")
    return 0


if __name__ == "__main__":
    sys.exit(main())
