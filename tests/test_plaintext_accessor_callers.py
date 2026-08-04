#!/usr/bin/env python3
"""Pins WHO may read a runtime-config secret in plaintext.

WHY THIS EXISTS
---------------
`RuntimeConfigStore` has two accessor families: the plain ones redact secret-valued
keys, `*_with_secrets()` do not. Every disclosure closed on this branch was an emitter
holding the plaintext and printing it. The durable guard is therefore not "does today's
emitter redact" -- the unit tests cover that -- but "did a NEW emitter reach for the
plaintext accessor".

The two `/api/config` routes cannot be reached by `TestRouteSink`: they are registered
as inline lambdas on `web_server_` at `server/core/src/server.cpp:7816` and `:7863`,
while the sink-testable pattern is a route owner exposing a sink overload, as
`server/core/src/settings_routes.hpp:128` does. Giving them one is a route-owner
extraction, tracked separately rather than done here. This test guards the regression
that extraction would otherwise be needed to catch, at the seam that does exist.

WHAT IT ASSERTS
---------------
The SET of production call sites, not a count. A count is defeated by a net-zero swap
-- delete one caller, add another -- which is the refactor this exists to catch.

COMMENT HANDLING, and why it is per-line
----------------------------------------
An earlier version of this file stripped `/* ... */` spans across the whole text first.
MEASURED on `server/core/src/server.cpp`: that removed 518389 of 899392 characters,
because a `/*` inside ordinary prose and inside a route glob opened spans that ran for
tens of thousands of lines. The scan then covered 42% of the file and would have gone
GREEN while blind to the rest. Comments are judged per line here for that reason; a
whole-file span matcher on C++ needs a real lexer, and this is not one.
"""

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Call sites permitted to read a secret in plaintext, each with why.
EXPECTED = {
    "server/core/src/runtime_config_store.cpp": (
        "get_all() calls it internally and then redacts -- this IS the redacting wrapper"
    ),
    "server/core/src/server.cpp": (
        "apply_runtime_config_overrides(): the startup pass must apply the real secret. "
        "It logs the placeholder, never the value."
    ),
}

ACCESSORS = ("get_all_with_secrets", "get_value_with_secrets")

# Shipped source. Tests may read plaintext freely -- asserting on it is their job.
ROOTS = ("server", "agents", "sdk")

# A line whose first non-space is one of these is comment or doc-comment continuation.
_COMMENT_LEAD = re.compile(r"^\s*(///|//|\*|/\*)")


def is_call(line: str, acc: str) -> bool:
    """True if this line CALLS acc, as opposed to declaring it or writing about it."""
    if _COMMENT_LEAD.match(line):
        return False
    code = line.split("//", 1)[0]          # trailing comment on a code line
    if acc not in code:
        return False
    if not re.search(rf"(?:\.|->|(?<![\w:]))\s*{acc}\s*\(", code):
        return False
    # Declaration: a return type, then the name, then a parameter list, then `;`.
    if re.search(rf"\b\w[\w:<>,\s*&]*\s+{acc}\s*\([^)]*\)\s*(?:const\s*)?;", code):
        return False
    return True


def call_sites() -> dict[str, list[int]]:
    found: dict[str, list[int]] = {}
    for root in ROOTS:
        base = REPO / root
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            if path.suffix not in (".cpp", ".cc", ".hpp", ".h") or not path.is_file():
                continue
            try:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for n, line in enumerate(lines, 1):
                if any(is_call(line, acc) for acc in ACCESSORS):
                    found.setdefault(str(path.relative_to(REPO)), []).append(n)
    return found


def main() -> int:
    found = call_sites()
    ok = True

    # Self-check: if the scan finds nothing at all, the scanner is broken rather than
    # the tree being clean. The bug this replaced failed exactly that way.
    if not found:
        print("FAIL: no plaintext-accessor call sites found anywhere.")
        print("      The redacting wrapper in runtime_config_store.cpp always calls one,")
        print("      so zero hits means this scanner stopped working, not that the tree")
        print("      is clean. Fix the scan before trusting a green run.")
        return 1

    for rel in sorted(set(found) - set(EXPECTED)):
        ok = False
        lines = ", ".join(str(n) for n in found[rel])
        print(f"FAIL: {rel}:{lines} reads a runtime-config secret in plaintext.")
        print("      Every disclosure this guards against was an emitter holding the")
        print("      plaintext. If the read is entitled, add it to EXPECTED with the")
        print("      reason. Do not delete the test.")

    for rel in sorted(set(EXPECTED) - set(found)):
        ok = False
        print(f"FAIL: {rel} no longer calls a plaintext accessor.")
        print(f"      It was permitted one because: {EXPECTED[rel]}")
        print("      If the caller moved, move its entry with it -- a stale allowlist")
        print("      silently re-permits whatever takes its place.")

    if ok:
        sites = sum(len(v) for v in found.values())
        print(f"plaintext-accessor callers: OK ({sites} call site(s) across "
              f"{len(found)} file(s), all accounted for)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
