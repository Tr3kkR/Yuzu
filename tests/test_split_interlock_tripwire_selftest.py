#!/usr/bin/env python3
"""Self-test that locks the split interlock merge-gate against silent neutering.

tests/test_split_interlock_tripwire.py enforces the ADR-0032 interlock by reading
its policy out of tests/split_interlock_ledger.json — a repo file editable in the
very PR the gate polices. That makes the gate tamper-EVIDENT, not tamper-PROOF: on
its own, a PR could open the gate by editing one JSON value (drop a cell from
gate_set, widen exclude_paths past where new engine code lands, delete an
engine-path marker, or flip a markerless gate cell green) with nothing to catch it.

This self-test is the lock. It pins the ledger's LOAD-BEARING CONSTANTS against
frozen values HERE, in test code, so neutering the gate requires editing these
constants too — which fails CI loudly and is a reviewable change the routed-concern
row routes to security review. It also exercises the tripwire's own logic against
mutated ledgers, so a future edit that inverts a check (the false-green shape) is
caught rather than shipping a silently-inert gate.

Changing the interlock legitimately (e.g. WS-A6 lands a new gate prerequisite) means
editing BOTH the ledger and the matching constant below, in the same reviewed PR —
which is the intended, loud, auditable path, not a bug.

Wired into .github/workflows/docs-lint.yml alongside the tripwire. Stdlib only.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LEDGER = os.path.join(REPO_ROOT, "tests", "split_interlock_ledger.json")
TRIPWIRE = os.path.join(REPO_ROOT, "tests", "test_split_interlock_tripwire.py")

# --- FROZEN CONSTANTS (the lock). Editing the ledger to change any of these must
# --- also edit the value here — a loud, reviewed change, never a silent JSON edit.
EXPECTED_GATE_SET = ["a", "b", "c", "d", "h"]  # ADR-0032 unconditional set (a)-(d)+(h)
EXPECTED_SEARCH_PATHS = ["."]                   # whole tree; narrowing hides engine code
EXPECTED_EXCLUDE_PATHS = {
    "docs/",
    ".claude/",
    "tests/split_interlock_ledger.json",
    "tests/test_split_interlock_tripwire.py",
    "tests/test_split_interlock_tripwire_selftest.py",
}
EXPECTED_ENGINE_PATH_MARKER_KEYS = {
    "run_row_store",
    "invocation_grant",
    "result_scoped_grant",
    "finalisation_receipt",
    "served_from_run_id",
    "released_input_digest",
    "reaper_metrics",
}


def _fail(msg: str, failures: list) -> None:
    failures.append(msg)
    print(f"FAIL: {msg}", file=sys.stderr)


def _run_tripwire(ledger_path: str) -> int:
    """Invoke the tripwire against an alternate ledger; return its exit code."""
    proc = subprocess.run(
        [sys.executable, TRIPWIRE, ledger_path],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    return proc.returncode


def main() -> int:
    with open(LEDGER, encoding="utf-8") as fh:
        ledger = json.load(fh)
    failures: list[str] = []

    # 1. gate_set is pinned (UP-1) — a dropped gate cell would read the gate OPEN.
    if ledger.get("gate_set") != EXPECTED_GATE_SET:
        _fail(f"gate_set {ledger.get('gate_set')} != frozen {EXPECTED_GATE_SET}", failures)

    # 2. search_paths / exclude_paths pinned (UP-3) — a widened exclude or narrowed
    #    search hides where new engine code lands from RULE 1's grep.
    if ledger.get("search_paths") != EXPECTED_SEARCH_PATHS:
        _fail(f"search_paths {ledger.get('search_paths')} != frozen {EXPECTED_SEARCH_PATHS}", failures)
    if set(ledger.get("exclude_paths", [])) != EXPECTED_EXCLUDE_PATHS:
        _fail(f"exclude_paths {set(ledger.get('exclude_paths', []))} != frozen {EXPECTED_EXCLUDE_PATHS}", failures)

    # 3. engine-path marker key set pinned (UP-4) — deleting a marker unpins its symbol.
    if set(ledger.get("engine_path_markers", {})) != EXPECTED_ENGINE_PATH_MARKER_KEYS:
        _fail(
            f"engine_path_markers keys {set(ledger.get('engine_path_markers', {}))} "
            f"!= frozen {EXPECTED_ENGINE_PATH_MARKER_KEYS}",
            failures,
        )

    # 4. every gate-set cell has a substrate marker (UP-2 / hp-1) — a markerless gate
    #    cell can be flipped green with no RULE 2 absence check.
    marked_cells = {spec["cell"] for spec in ledger.get("substrate_markers", {}).values()}
    for cell_id in EXPECTED_GATE_SET:
        if cell_id not in marked_cells:
            _fail(f"gate cell ({cell_id}) has no substrate_marker — RULE 2 cannot guard it", failures)

    # 5. every cell status is the exact enum (UP-12) — a typo silently skips RULE 2.
    for cell_id, spec in ledger.get("cells", {}).items():
        if spec.get("status") not in ("green", "red"):
            _fail(f"cell ({cell_id}) status {spec.get('status')!r} not in ('green','red')", failures)

    # 6. the tripwire's own logic still fires (guards against a future edit inverting a
    #    check — the false-green shape). Exercise it against mutated temp ledgers; the
    #    tripwire greps the real repo tree regardless of the ledger's location.
    with tempfile.TemporaryDirectory() as td:
        clean = os.path.join(td, "clean.json")
        with open(clean, "w", encoding="utf-8") as fh:
            json.dump(ledger, fh)
        if _run_tripwire(clean) != 0:
            _fail("tripwire did not PASS on an unmodified ledger (expected exit 0)", failures)

        # False-certification: flip red gate cell (d) green with its substrate absent.
        fc = json.loads(json.dumps(ledger))
        fc["cells"]["d"]["status"] = "green"
        fc_path = os.path.join(td, "false_cert.json")
        with open(fc_path, "w", encoding="utf-8") as fh:
            json.dump(fc, fh)
        if _run_tripwire(fc_path) == 0:
            _fail("tripwire PASSED a false certification (cell d green, substrate absent)", failures)

        # Excluded-rationale guard: blank a rationale.
        br = json.loads(json.dumps(ledger))
        br["excluded"]["plan_hash"] = ""
        br_path = os.path.join(td, "blank_rationale.json")
        with open(br_path, "w", encoding="utf-8") as fh:
            json.dump(br, fh)
        if _run_tripwire(br_path) == 0:
            _fail("tripwire PASSED an excluded entry with a blank rationale", failures)

    if failures:
        print(f"\n{len(failures)} interlock self-test failure(s).", file=sys.stderr)
        return 1
    print("split interlock self-test: OK — ledger constants pinned; tripwire logic fires.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
