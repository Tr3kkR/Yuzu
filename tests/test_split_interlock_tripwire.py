#!/usr/bin/env python3
"""WS-0 merge-gate tripwire — enforces the ADR-0032 sequencing interlock in CI.

The interlock (docs/adr/0032-use-case-admission-protocol.md, the "Sequencing
interlock" section, Rule at the line beginning "no ballot-A5 code path ships")
is a *merge* gate: no engine-path code may merge into any binary until the
unconditional set (a)-(d)+(h) has landed. A routed-concern row routes such a PR
to human reviewers, but governance runs from the *author's working tree*, so a
branch predating the routed table silently runs the old pipeline. This test is
the hard backstop: it runs on the merge ref on every PR (wired into
.github/workflows/docs-lint.yml, exactly like tests/test_issue_docs.py), so a
stale branch cannot dodge it.

It reads the machine-readable ledger (tests/split_interlock_ledger.json — the
data half of WS-0's certification; the human narrative is
docs/security-reviews/split-ws0-interlock-certification-*.md) and enforces two
rules, plus a self-consistency guard:

  RULE 1 (the merge gate) — if any engine-path marker appears in the code tree
    while ANY cell in the unconditional gate set (a)-(d)+(h) is not `green`,
    FAIL. This is the falsifier ADR-0032 names: "a merged PR that admits runs,
    mints grants or serves results" before the substrate lands.

  RULE 2 (false-certification guard) — if a cell is marked `green` but its
    substrate marker is ABSENT from the tree, FAIL. A certification that claims
    a substrate landed when it did not is worse than none: it opens the gate on
    a lie. (The converse — a substrate marker present while its cell is still
    red — is NOT a failure: a partial landing is legitimate, and the reviewer
    flips the cell in the same PR.)

  GUARD (excluded symbols) — a symbol listed under `excluded` (e.g. plan_hash,
    which is the pre-existing dispatch-tag grammar in
    command_capability_parsers.hpp, NOT engine-path) is never treated as a
    marker, and the test asserts the recorded rationale is present so a future
    reader cannot quietly repurpose it.

Substrate markers are ledger-FLIPPERS, never blockers: use_case_run_id is the
D12 audit column (cell c) and release-log the disclosure store (cell d) — the
very things WS-A6 must land to turn the gate green. Blocking their first
occurrence would deadlock the interlock against itself. Only engine-path markers
block, and only while the gate is red.

Zero dependencies (stdlib only), like the other tests/test_*.py doc-lint gates.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LEDGER = os.path.join(REPO_ROOT, "tests", "split_interlock_ledger.json")


def _fail(msg: str) -> None:
    print(f"FAIL: {msg}", file=sys.stderr)


def _git_grep_hits(regex: str, search_paths: list[str], exclude_paths: list[str]) -> list[str]:
    """Return matching 'file:line:text' lines for regex across search_paths.

    Uses `git grep` so .gitignore/vendored/generated trees are honoured, matching
    the repo's search discipline. exclude_paths are dropped via pathspec
    exclusions so the ledger, the certification doc and this test never self-match.
    """
    cmd = ["git", "grep", "-nE", regex, "--", *search_paths]
    for ex in exclude_paths:
        cmd.append(f":(exclude){ex}")
    proc = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)
    # git grep exits 1 on "no matches" — that is not an error here.
    if proc.returncode not in (0, 1):
        raise RuntimeError(f"git grep failed ({proc.returncode}): {proc.stderr.strip()}")
    return [ln for ln in proc.stdout.splitlines() if ln.strip()]


def main() -> int:
    with open(LEDGER, encoding="utf-8") as fh:
        ledger = json.load(fh)

    gate_set: list[str] = ledger["gate_set"]
    cells: dict = ledger["cells"]
    search_paths: list[str] = ledger["search_paths"]
    exclude_paths: list[str] = ledger.get("exclude_paths", [])
    substrate: dict = ledger["substrate_markers"]
    engine_path: dict = ledger["engine_path_markers"]
    excluded: dict = ledger.get("excluded", {})

    failures = 0

    # Is the unconditional merge-gate open? Every cell in the gate set must be green.
    red_gate_cells = [c for c in gate_set if cells.get(c, {}).get("status") != "green"]
    gate_open = not red_gate_cells

    # RULE 1 — engine-path markers are blocked while the gate is red.
    if not gate_open:
        for name, spec in engine_path.items():
            hits = _git_grep_hits(spec["regex"], search_paths, exclude_paths)
            if hits:
                failures += 1
                _fail(
                    f"ENGINE-PATH MARKER '{name}' ({spec['regex']}) appears in the code "
                    f"tree while the ADR-0032 merge-gate is RED (open cells: "
                    f"{', '.join(red_gate_cells)}). No ballot-A5 code path may merge "
                    f"until (a)-(d)+(h) land. First hits:\n    "
                    + "\n    ".join(hits[:5])
                )

    # RULE 2 — false-certification guard: a green cell must have its substrate present.
    for name, spec in substrate.items():
        cell = spec["cell"]
        if cells.get(cell, {}).get("status") == "green":
            hits = _git_grep_hits(spec["regex"], search_paths, exclude_paths)
            if not hits:
                failures += 1
                _fail(
                    f"FALSE CERTIFICATION: cell ({cell}) is marked green but its "
                    f"substrate marker '{name}' ({spec['regex']}) is absent from the "
                    f"code tree. Flip the cell back to red or land the substrate."
                )

    # GUARD — excluded symbols must carry a recorded rationale and never appear as markers.
    marker_regexes = {s["regex"] for s in substrate.values()} | {
        e["regex"] for e in engine_path.values()
    }
    for name, rationale in excluded.items():
        if not rationale or not str(rationale).strip():
            failures += 1
            _fail(f"EXCLUDED symbol '{name}' has no recorded rationale.")
        if name in marker_regexes:
            failures += 1
            _fail(f"EXCLUDED symbol '{name}' is also registered as a marker.")

    if failures:
        print(
            f"\n{failures} interlock-tripwire failure(s). See "
            "docs/security-reviews/split-ws0-interlock-certification-2026-09-08.md "
            "and docs/adr/0032-use-case-admission-protocol.md.",
            file=sys.stderr,
        )
        return 1

    state = "OPEN (all of a-d+h green)" if gate_open else f"CLOSED (red: {', '.join(red_gate_cells)})"
    print(f"split interlock tripwire: OK — merge-gate {state}; no engine-path marker breached it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
