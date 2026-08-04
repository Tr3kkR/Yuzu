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
A MULTISET keyed on (file, normalised call text) -> how many times that exact call
appears. Not a count, which a net-zero swap defeats; and not a set of FILES, which was
the first version's defect: `server.cpp` is entitled for the startup pass, and both
`/api/config` routes live in that same file, so a second plaintext read added inside
either route handler was invisible. That was demonstrated by mutation in review, not
reasoned about -- the test reported OK with three call sites where one of the three
was an illegitimate read in the GET handler.

WHAT IT DOES NOT COVER, stated so the guarantee is not read wider than it is
-------------------------------------------------------------------------
  * A wrapper. Once a method that itself calls an accessor is entitled, every caller
    of THAT method is invisible here -- the scan matches accessor names as text.
  * Indirect reach: `&RuntimeConfigStore::get_all_with_secrets` bound through
    `std::function`/`std::bind` and invoked later. No line then contains both the name
    and a call.
  * Anything outside ROOTS, or any suffix outside the scanned set.
It is a tripwire on the direct-call surface, not a proof that plaintext is unreachable.

Comments are judged per line, never by whole-file `/* ... */` span matching, which
false-positives on a `/*` inside prose or a route glob and can blank most of a large
file. That needs a real lexer, and this is not one.
"""

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# (file, normalised call line) -> (how many times it may appear, why it is entitled).
# Keyed on the call text so an unrelated edit above does not move it, and counted so a
# duplicate cannot hide behind an already-entitled twin.
EXPECTED = {
    ("server/core/src/runtime_config_store.cpp",
     "auto entries = get_all_with_secrets();"):
        (1, "get_all() calls it and then redacts -- this IS the redacting wrapper"),
    ("server/core/src/runtime_config_store.cpp",
     "auto entry = get_with_secrets(key);"):
        (2, "get_value_with_secrets() and get() both funnel through it internally"),
    ("server/core/src/server.cpp",
     "auto entries = runtime_config_store_->get_all_with_secrets();"):
        (1, "apply_runtime_config_overrides(): the startup pass must apply the real "
            "secret. It logs the placeholder, never the value."),
}

# All three `_with_secrets` twins. runtime_config_store.hpp:40 states there are three
# plain read accessors that redact; an earlier version of this file pinned two of the
# three, so `get_with_secrets()` was an unguarded plaintext route past a test whose
# headline claimed to pin them all.
ACCESSORS = ("get_all_with_secrets", "get_value_with_secrets", "get_with_secrets")

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


def call_sites() -> dict[tuple[str, str], list[int]]:
    """(file, normalised call line) -> the line numbers where it occurs."""
    found: dict[tuple[str, str], list[int]] = {}
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
                if not any(is_call(line, acc) for acc in ACCESSORS):
                    continue
                # as_posix(), not str(): on Windows str() emits backslashes, so every
                # site would miss its forward-slash key and land in BOTH the unexpected
                # and the missing set -- bogus failures on every Windows run, and
                # ci.yml runs the docs suite there with no --suite filter.
                rel = path.relative_to(REPO).as_posix()
                found.setdefault((rel, " ".join(line.split())), []).append(n)
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

    for key in sorted(set(found) - set(EXPECTED)):
        ok = False
        rel, text = key
        lines = ", ".join(str(n) for n in found[key])
        print(f"FAIL: {rel}:{lines} reads a runtime-config secret in plaintext:")
        print(f"        {text}")
        print("      Every disclosure this guards against was an emitter holding the")
        print("      plaintext. If the read is entitled, add it to EXPECTED with the")
        print("      reason. Do not delete the test.")

    for key in sorted(set(EXPECTED) - set(found)):
        ok = False
        rel, text = key
        print(f"FAIL: {rel} no longer contains this entitled plaintext read:")
        print(f"        {text}")
        print(f"      It was permitted because: {EXPECTED[key][1]}")
        print("      If the caller moved or was reworded, update its entry -- a stale")
        print("      allowlist silently re-permits whatever takes its place.")

    for key in sorted(set(found) & set(EXPECTED)):
        want = EXPECTED[key][0]
        got = len(found[key])
        if got == want:
            continue
        ok = False
        rel, text = key
        lines = ", ".join(str(n) for n in found[key])
        print(f"FAIL: {rel} has {got} copies of an entitled plaintext read, expected {want}:")
        print(f"        {text}  (lines {lines})")
        print("      A duplicate cannot ride along on an entitled twin. This is counted")
        print("      per call site precisely because a file-level allowlist let a second")
        print("      read inside the GET /api/config handler pass green.")

    if ok:
        sites = sum(len(v) for v in found.values())
        print(f"plaintext-accessor callers: OK ({sites} call site(s), "
              f"{len(found)} distinct, all accounted for)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
