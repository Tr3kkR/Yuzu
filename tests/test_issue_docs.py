#!/usr/bin/env python3
"""Repo-hygiene checks for the issue-lifecycle standard (ADR-3001, Amendment A1).

Three invariants that must hold on every platform:

1. CLAUDE.md stays under its self-imposed 40,000-CHARACTER cap. Counted
   UTF-8-decoded in Python deliberately: the file is dense with multi-byte
   punctuation, so byte counts (`wc -c`, and `wc -m` on Windows Git Bash,
   which degrades to bytes) read ~300 higher than the character count -- the
   exact confusion Amendment A1 par.8 corrects. This check is the durable
   floor; PR-time reviews additionally hold edits to net-negative.

2. scripts/tracker/do-not-close.txt parses -- integers only (one per line,
   '#' comments allowed), no duplicates, never empty. Every automated close
   path reads this file; a malformed line silently shrinking the never-close
   set is exactly the failure a green build must catch.

3. docs/agents/issue-standard.md exists and still contains its never-close
   section (5.1), which do-not-close.txt and the automation cite as their
   authority.

Wired into tests/meson.build (suite: docs), mirroring test_changelog_order.py.
"""

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

CLAUDE_MD_CHAR_CAP = 40_000


def main() -> int:
    failures = []

    # 1. CLAUDE.md character budget
    claude = (ROOT / "CLAUDE.md").read_text(encoding="utf-8")
    n_chars = len(claude)
    if n_chars >= CLAUDE_MD_CHAR_CAP:
        failures.append(
            f"CLAUDE.md is {n_chars} characters -- at/over its self-imposed "
            f"{CLAUDE_MD_CHAR_CAP} cap (see 'CLAUDE.md updates' in the file itself). "
            f"Route detail to docs/ and keep only invariants + pointers."
        )

    # 2. do-not-close.txt parses clean
    dnc_path = ROOT / "scripts" / "tracker" / "do-not-close.txt"
    if not dnc_path.exists():
        failures.append(f"{dnc_path.relative_to(ROOT)} is missing")
    else:
        numbers = []
        for lineno, line in enumerate(
            dnc_path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            body = line.split("#", 1)[0].strip()
            if not body:
                continue
            if not body.isdigit():
                failures.append(
                    f"do-not-close.txt:{lineno}: not a bare issue number: {body!r}"
                )
            else:
                numbers.append(int(body))
        if not numbers:
            failures.append(
                "do-not-close.txt parses to an EMPTY set -- the never-close "
                "guard would be inert"
            )
        dupes = {n for n in numbers if numbers.count(n) > 1}
        if dupes:
            failures.append(f"do-not-close.txt: duplicate numbers: {sorted(dupes)}")

    # 3. the standard exists and keeps its never-close section
    std_path = ROOT / "docs" / "agents" / "issue-standard.md"
    if not std_path.exists():
        failures.append("docs/agents/issue-standard.md is missing")
    else:
        std = std_path.read_text(encoding="utf-8")
        if "What automation must never close" not in std:
            failures.append(
                "issue-standard.md no longer contains the 'What automation must "
                "never close' section that do-not-close.txt and the close "
                "automation cite as their authority"
            )

    if failures:
        print("issue-docs checks FAILED:")
        for f in failures:
            print(f"  - {f}")
        return 1

    print(f"issue-docs checks OK (CLAUDE.md {n_chars}/{CLAUDE_MD_CHAR_CAP} chars)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
