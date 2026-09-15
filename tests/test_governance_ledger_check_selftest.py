#!/usr/bin/env python3
"""Self-test for scripts/ci/check-governance-ledger.py - the author-side
governance-ledger linter.

The linter is ADVISORY (a pre-push self-check the /governance skill runs on the
current run's fragment, not a corpus CI gate - see the script's own docstring
and the calibration finding that ~93% of historical fragments predate its
strict rules). This self-test does NOT lint the real corpus; it feeds the
checker synthetic good/bad fragments and asserts it DISCRIMINATES - a clean
ledger yields no findings, and each seeded defect fires its own rule (and only
on the LIVE view, since the ledger is append-only / supersede-never-edit).
Without a discrimination test a checker that always returned "clean" would look
just as green on the current tree.

Imports the hyphenated script via importlib (matching
tests/test_seam_closure_selftest.py / scripts/ci/test_check_pg_shard_partition.py).
Stdlib only. Exit 0 = pass.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "ci" / "check-governance-ledger.py"


def _load():
    spec = importlib.util.spec_from_file_location("check_governance_ledger", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


M = _load()

_FAILURES: list[str] = []


def expect(cond, label):
    if not cond:
        _FAILURES.append(label)
        print(f"  FAIL: {label}")
    else:
        print(f"  ok:   {label}")


def _row(**kw):
    base = {
        "schema_version": 1, "run_id": None, "finding_id": "f1",
        "reporter": "architect", "source": "governance-agent",
        "reviewed_at_sha": "abc123 (merge-base def456)",
        "severity_native": "MEDIUM", "severity_mapped": "SHOULD",
        "impact": ["I6"], "exposure": ["E0"], "policy_floor": None,
        "classification": None, "disposition": "fixed",
        "adjudicated_by": None, "adjudication_rationale": None,
    }
    base.update(kw)
    return base


def _write(dirpath, stem, rows):
    p = Path(dirpath) / f"{stem}.jsonl"
    for r in rows:
        r["run_id"] = stem  # the fragment's run_id always matches its filename stem
    p.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    return str(p)


def _rules(findings):
    return sorted({f.rule for f in findings})


def run():
    # --- derivation unit checks ---
    expect(M.derived_band(["I9"], ["E0"]) == "INFO", "derive I9/E0 -> INFO")
    expect(M.derived_band(["I3"], ["E0"]) == "HIGH", "derive I3/E0 -> HIGH")
    expect(M.derived_band(["I6"], ["E1"]) == "HIGH", "derive I6/E1 -> HIGH (E1 raises)")
    expect(M.derived_band(["I2"], ["E6"]) == "LOW", "derive I2/E6 -> LOW (E6 caps)")
    expect(M.mapped_of("HIGH") == "BLOCKING" and M.mapped_of("INFO") == "NICE", "mapped_of bands")

    with tempfile.TemporaryDirectory() as d:
        # --- a clean, conforming fragment: zero findings ---
        good = _write(d, "1234-clean-run.AbCdEf", [
            _row(finding_id="a", impact=["I6"], exposure=["E0"], severity_mapped="SHOULD"),
            _row(finding_id="b", impact=["I9"], exposure=["E0"], severity_mapped="NICE",
                 severity_native="NICE", classification="wording"),
            _row(finding_id="c", impact=["I3"], exposure=["E0"], severity_mapped="BLOCKING",
                 severity_native="HIGH", disposition="fixed"),
            # a valid floored row: derived band stays in severity_mapped, floor tracked separately
            _row(finding_id="d", impact=["I9"], exposure=["E0"], severity_mapped="NICE",
                 severity_native="INFO",
                 policy_floor="severity-derived-not-chosen (CLAUDE.md standing rule 2)"),
            # a clean supersession of 'a' (native + reviewed_at_sha unchanged)
            _row(finding_id="a", impact=["I6"], exposure=["E0"], severity_mapped="SHOULD",
                 disposition="fixed"),
            # external-model row with a reporter_ref
            _row(finding_id="e", source="external-model", reporter="FortitudeEtc",
                 reporter_ref="https://example/pr#review-1", impact=["I5"], exposure=["E0"],
                 severity_mapped="SHOULD", severity_native="MEDIUM"),
        ])
        gf = M.check_fragment(good)
        expect(gf == [], f"clean fragment yields no findings (got {_rules(gf)})")

        # --- severity_mapped != derived band (STRICT) ---
        bad = _write(d, "9-sev.X", [
            _row(finding_id="s", impact=["I9"], exposure=["E0"], severity_mapped="BLOCKING")])
        expect("severity-not-derived" in _rules(M.check_fragment(bad)), "fires severity-not-derived")

        # --- wording carrying I7 (STRICT) ---
        bad = _write(d, "9-word.X", [
            _row(finding_id="w", classification="wording", impact=["I7"], exposure=["E0"],
                 severity_mapped="SHOULD")])
        expect("wording-carries-i7" in _rules(M.check_fragment(bad)), "fires wording-carries-i7")

        # --- severity_native mutated across supersession (STRICT) ---
        bad = _write(d, "9-native.X", [
            _row(finding_id="n", severity_native="HIGH", impact=["I3"], severity_mapped="BLOCKING"),
            _row(finding_id="n", severity_native="LOW", impact=["I3"], severity_mapped="BLOCKING")])
        expect("native-mutated" in _rules(M.check_fragment(bad)), "fires native-mutated")

        # --- reviewed_at_sha mutated across supersession (STRICT) ---
        bad = _write(d, "9-sha.X", [
            _row(finding_id="h", reviewed_at_sha="aaa"),
            _row(finding_id="h", reviewed_at_sha="bbb")])
        expect("reviewed-sha-mutated" in _rules(M.check_fragment(bad)), "fires reviewed-sha-mutated")

        # --- a defect on a SUPERSEDED row is NOT flagged (append-only history) ---
        superseded_ok = _write(d, "9-hist.X", [
            _row(finding_id="k", severity_mapped="BLOCKING", impact=["I9"], exposure=["E0"]),  # bad, but...
            _row(finding_id="k", severity_mapped="NICE", impact=["I9"], exposure=["E0"])])      # ...fixed live
        expect(M.check_fragment(superseded_ok) == [],
               "superseded-then-fixed row is clean (live-view only)")

        # --- structural: joined reporter, bad source, missing reporter_ref, adj pairing ---
        bad = _write(d, "9-struct.X", [
            _row(finding_id="j", reporter="A and B")])
        expect("joined-reporter" in _rules(M.check_fragment(bad)), "fires joined-reporter")
        bad = _write(d, "9-src.X", [_row(finding_id="j", source="robot")])
        expect("bad-source" in _rules(M.check_fragment(bad)), "fires bad-source")
        bad = _write(d, "9-ref.X", [
            _row(finding_id="j", source="external-model", reporter_ref=None)])
        expect("missing-reporter-ref" in _rules(M.check_fragment(bad)), "fires missing-reporter-ref")
        bad = _write(d, "9-adj.X", [
            _row(finding_id="j", adjudicated_by="someone", adjudication_rationale=None)])
        expect("adjudication-pairing" in _rules(M.check_fragment(bad)), "fires adjudication-pairing")

        # --- structural: missing policy_floor KEY (omission != null) ---
        p = Path(d) / "9-floorkey.X.jsonl"
        row = _row(finding_id="j")
        row.pop("policy_floor")
        row["run_id"] = "9-floorkey.X"
        p.write_text(json.dumps(row) + "\n", encoding="utf-8")
        expect(any(f.rule == "missing-field" and "policy_floor" in f.msg
                   for f in M.check_fragment(str(p))), "fires missing policy_floor key")

        # --- robustness: does not crash on odd field types / invalid json ---
        p = Path(d) / "9-weird.X.jsonl"
        p.write_text(
            json.dumps(_row(finding_id="z", impact="I5", exposure="unresolved",
                            run_id="9-weird.X")) + "\n" + "{not json}\n", encoding="utf-8")
        fr = M.check_fragment(str(p))
        expect(any(f.rule == "invalid-json" for f in fr), "flags invalid-json line without crashing")

    if _FAILURES:
        print(f"\ngovernance-ledger-check self-test: FAILED ({len(_FAILURES)} case(s))")
        return 1
    print("\ngovernance-ledger-check self-test: OK - linter discriminates on every seeded defect")
    return 0


if __name__ == "__main__":
    sys.exit(run())
