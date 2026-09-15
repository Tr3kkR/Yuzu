#!/usr/bin/env python3
"""Self-test for scripts/ci/check-governance-ledger.py - the author-side
governance-ledger linter.

The linter is ADVISORY (a pre-push self-check the /governance skill runs on the
current run's fragment, not a corpus CI gate). This self-test does NOT lint the
real corpus; it (1) PINS the linter's policy constants against literals so a
silent edit to a band or an enum fails here in reviewed test code (mirroring
tests/test_seam_closure_selftest.py), and (2) feeds the checker synthetic
good/bad fragments and asserts it DISCRIMINATES - a conforming ledger (including
the prescribed SPARSE-supersession shape) yields nothing, each seeded defect
fires its own rule, and an intermediate violation a later row restores is still
caught (the ledger is a FIELD-WISE MERGE, not last-row-wins). (3) exercises the
CLI exit-code contract via subprocess.

Imports the hyphenated script via importlib. Stdlib only. Exit 0 = pass.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
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
    print(("  ok:   " if cond else "  FAIL: ") + label)
    if not cond:
        _FAILURES.append(label)


def _full(**kw):
    """a complete, conforming governance-agent row."""
    base = {
        "schema_version": 1, "run_id": None, "finding_id": "f1",
        "reporter": "architect", "source": "governance-agent",
        "reviewed_at_sha": "abc123 (merge-base def456)",
        "recorded_at": "2026-09-15T10:00:00Z", "pass_ordinal": 0,
        "severity_native": "MEDIUM", "severity_mapped": "SHOULD",
        "impact": ["I6"], "exposure": ["E0"], "policy_floor": None,
        "classification": None, "disposition": "open", "independent_reporters": 1,
        "adjudicated_by": None, "adjudication_rationale": None,
    }
    base.update(kw)
    return base


def _write(dirpath, stem, rows):
    p = Path(dirpath) / f"{stem}.jsonl"
    for r in rows:
        if "run_id" in r:  # only stamp rows that carry the key (keep sparse rows sparse)
            r["run_id"] = stem
    p.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    return str(p)


def _rules(findings):
    return sorted({f.rule for f in findings})


def run():
    # -------- (1) constant + derivation pinning (mutation-proofing) --------
    expect(M._BASE == {"I1": "HIGH", "I2": "HIGH", "I3": "HIGH", "I4": "HIGH",
                       "I5": "MEDIUM", "I6": "MEDIUM", "I7": "MEDIUM",
                       "I8": "LOW", "I9": "INFO"}, "pin _BASE band table")
    expect(set(M.IMPACTS) == {f"I{i}" for i in range(1, 10)}, "pin IMPACTS")
    expect(set(M.EXPOSURES) == {f"E{i}" for i in range(0, 7)} | {"unresolved"}, "pin EXPOSURES")
    expect(set(M.MAPPED) == {"BLOCKING", "SHOULD", "NICE"}, "pin MAPPED")
    expect(set(M.SOURCES) == {"governance-agent", "collaborator", "external-model"}, "pin SOURCES")
    expect(set(M.ATTESTATION) == {"adjudicated_by", "adjudication_rationale", "refuted_by",
                                  "refuted_by_reporter", "waiver_rationale"}, "pin ATTESTATION set")
    expect(M.min_derived_band(["I9"], ["E0"]) == "INFO", "derive I9/E0 -> INFO")
    expect(M.min_derived_band(["I3"], ["E0"]) == "HIGH", "derive I3/E0 -> HIGH")
    expect(M.min_derived_band(["I6"], ["E1"]) == "HIGH", "derive I6/E1 -> HIGH (E1 raises)")
    expect(M.min_derived_band(["I2"], ["E6"]) == "LOW", "derive I2/E6 -> LOW (E6 caps)")
    expect(M.min_derived_band(["I4"], ["E1"]) == "HIGH", "derive I4/E1 -> HIGH (I4 cap, F9)")
    expect(M.min_derived_band([], ["E0"]) == "INFO", "derive empty -> INFO")

    with tempfile.TemporaryDirectory() as d:
        # -------- (2a) field-wise merge: a conforming SPARSE supersession is clean --------
        # row1 is the full finding; row2 restates ONLY disposition (the prescribed
        # sparse `fixed` shape). Last-row-replace would false-fire missing-field;
        # the field-wise merge keeps row1's fields.
        sparse = _write(d, "1234-sparse.AbCd", [
            _full(finding_id="a", recorded_at="2026-09-15T10:00:00Z"),
            {"finding_id": "a", "recorded_at": "2026-09-15T11:00:00Z",
             "disposition": "fixed"},
        ])
        expect(M.check_fragment(sparse) == [],
               f"conforming sparse supersession is clean (got {_rules(M.check_fragment(sparse))})")

        # -------- (2b) a fully-conforming multi-finding fragment is clean --------
        good = _write(d, "1234-clean.AbCd", [
            _full(finding_id="a", impact=["I6"], exposure=["E0"], severity_mapped="SHOULD"),
            _full(finding_id="b", impact=["I9"], exposure=["E0"], severity_mapped="NICE",
                  severity_native="NICE", classification="wording"),
            _full(finding_id="c", impact=["I3"], exposure=["E0"], severity_mapped="BLOCKING",
                  severity_native="HIGH", disposition="fixed"),
            # valid floored row: derived band in severity_mapped, floor separate
            _full(finding_id="e", impact=["I9"], exposure=["E0"], severity_mapped="NICE",
                  severity_native="INFO",
                  policy_floor="severity-derived-not-chosen (CLAUDE.md standing rule 2)"),
            # legit over-label (could be a conditional raise): I6/E0 as BLOCKING - NOT flagged
            _full(finding_id="g", impact=["I6"], exposure=["E0"], severity_mapped="BLOCKING",
                  severity_native="HIGH"),
            # external-model row with reporter_ref and independent_reporters=2 (F3: not flagged)
            _full(finding_id="h", source="external-model", reporter="FortitudeEtc",
                  reporter_ref="https://x/pr#r1", impact=["I5"], exposure=["E0"],
                  severity_mapped="SHOULD", severity_native="MEDIUM", independent_reporters=2),
        ])
        gf = M.check_fragment(good)
        expect(gf == [], f"clean multi-finding fragment yields nothing (got {_rules(gf)})")

        def fires(stem, rows, rule, label):
            f = M.check_fragment(_write(d, stem, rows))
            expect(rule in _rules(f), label + f" (got {_rules(f)})")

        def clean_of(stem, rows, rule, label):
            f = M.check_fragment(_write(d, stem, rows))
            expect(rule not in _rules(f), label + f" (got {_rules(f)})")

        # -------- (3) STRICT rules --------
        fires("9-under.X", [_full(finding_id="s", impact=["I3"], exposure=["E0"],
                                  severity_mapped="SHOULD")],
              "severity-under-derived", "under-grading fires")
        clean_of("9-over.X", [_full(finding_id="s", impact=["I6"], exposure=["E0"],
                                    severity_mapped="BLOCKING", severity_native="HIGH")],
                 "severity-under-derived", "over-label (possible conditional raise) NOT flagged (F2)")
        fires("9-empty.X", [_full(finding_id="s", impact=[], exposure=["E0"],
                                  severity_mapped="BLOCKING")],
              "severity-empty-impact", "empty impact + BLOCKING + no floor fires (F2)")
        fires("9-word.X", [_full(finding_id="w", classification="wording", impact=["I7"],
                                 exposure=["E0"], severity_mapped="SHOULD")],
              "wording-carries-i7", "wording+I7 fires")

        # native mutated across a RESTORED middle row (F5): MEDIUM -> LOW -> MEDIUM
        fires("9-native.X", [
            _full(finding_id="n", recorded_at="2026-09-15T10:00:00Z", severity_native="MEDIUM",
                  impact=["I6"], severity_mapped="SHOULD"),
            _full(finding_id="n", recorded_at="2026-09-15T11:00:00Z", severity_native="LOW",
                  impact=["I6"], severity_mapped="SHOULD"),
            _full(finding_id="n", recorded_at="2026-09-15T12:00:00Z", severity_native="MEDIUM",
                  impact=["I6"], severity_mapped="SHOULD")],
            "native-mutated", "mutated-then-restored native still fires (F5)")

        # F5 null-escape: null -> HIGH invents a band the reporter did not give
        fires("9-nativenull.X", [
            _full(finding_id="nn", recorded_at="2026-09-15T10:00:00Z", severity_native=None,
                  impact=["I6"], severity_mapped="SHOULD"),
            _full(finding_id="nn", recorded_at="2026-09-15T11:00:00Z", severity_native="HIGH",
                  impact=["I6"], severity_mapped="SHOULD")],
            "native-mutated", "null -> HIGH native invention fires (F5 null-escape)")

        # F1 ordering: a fractional-second timestamp is LATER than a bare one but
        # sorts EARLIER as a plain string. Discriminating check: the EARLIER (bare)
        # row is disposition:open, the LATER (fractional) row is disposition:fixed;
        # correct instant-order merges to 'fixed', a string sort would pick 'open'.
        frac_rows = [
            _full(finding_id="fr", recorded_at="2026-09-15T10:00:00Z", disposition="open"),
            {"finding_id": "fr", "run_id": "9-frac.X",
             "recorded_at": "2026-09-15T10:00:00.500Z", "disposition": "fixed"}]
        frac_ordered = sorted(((i, r) for i, r in enumerate(frac_rows)), key=M._order_key)
        expect(M.merged_view(frac_ordered).get("disposition") == "fixed",
               "fractional-second timestamp orders by instant, not string (merged disposition=fixed)")

        # reviewed_at_sha is NOT immutable: correcting it across a supersession
        # (e.g. an early pre-rebase SHA that no longer resolves) is legitimate.
        clean_of("9-sha.X", [
            _full(finding_id="h", recorded_at="2026-09-15T10:00:00Z", reviewed_at_sha="aaa"),
            _full(finding_id="h", recorded_at="2026-09-15T11:00:00Z", reviewed_at_sha="bbb")],
            "reviewed-sha-mutated", "reviewed_at_sha correction NOT flagged")

        # attestation pairing PER ROW (F5): a middle row with adjudicated_by only
        fires("9-adj.X", [
            _full(finding_id="p", recorded_at="2026-09-15T10:00:00Z"),
            _full(finding_id="p", recorded_at="2026-09-15T11:00:00Z",
                  adjudicated_by="someone", adjudication_rationale=None),
            _full(finding_id="p", recorded_at="2026-09-15T12:00:00Z", disposition="fixed")],
            "adjudication-pairing", "per-row attestation pairing fires on middle row (F5)")

        # park constraint (F8)
        fires("9-park.X", [_full(finding_id="k", impact=["I1"], exposure=["E0"],
                                 severity_mapped="BLOCKING", severity_native="HIGH",
                                 disposition="roadmap-#999")],
              "parked-top-severity", "parked top-severity fires")

        # -------- (4) STRUCTURAL rules --------
        fires("9-listrep.X", [_full(finding_id="j", reporter=["a", "b"])],
              "list-reporter", "list-valued reporter fires (F6)")
        fires("9-plusrep.X", [_full(finding_id="j", reporter="a+b")],
              "joined-reporter", "unspaced + reporter fires (F6)")
        norep = _full(finding_id="j"); norep.pop("reporter")
        fires("9-norep.X", [norep], "missing-reporter", "absent reporter fires (F6)")
        fires("9-src.X", [_full(finding_id="j", source="robot")], "bad-source", "bad source fires")
        badref = _full(finding_id="j", source="external-model"); badref.pop("reporter_ref", None)
        badref["reporter_ref"] = None
        fires("9-ref.X", [badref], "missing-reporter-ref", "external-model without ref fires")
        fires("9-scalar.X", [_full(finding_id="j", impact="I5")],
              "scalar-list-field", "scalar impact fires (F8)")
        nofloor = _full(finding_id="j"); nofloor.pop("policy_floor")
        fires("9-floorkey.X", [nofloor], "missing-field", "missing policy_floor key fires")

        # -------- (5) F11: legacy row (no schema_version) is NOT flagged missing-field --------
        legacy = {"finding_id": "L", "reporter": "architect", "source": "governance-agent",
                  "impact": ["I6"], "exposure": ["E0"], "severity_mapped": "SHOULD",
                  "disposition": "open", "run_id": "9-legacy.X"}
        lf = M.check_fragment(_write(d, "9-legacy.X", [legacy]))
        expect(not any(f.rule == "missing-field" for f in lf),
               f"legacy row (no schema_version) not flagged missing-field (F11) (got {_rules(lf)})")

        # -------- robustness: odd types / invalid json don't crash --------
        p = Path(d) / "9-weird.X.jsonl"
        p.write_text(json.dumps(_full(finding_id="z", run_id="9-weird.X")) + "\n{bad}\n",
                     encoding="utf-8")
        expect(any(f.rule == "invalid-json" for f in M.check_fragment(str(p))),
               "invalid-json flagged without crashing")

        # -------- (6) CLI exit-code contract (F10), via subprocess --------
        def cli(*a):
            return subprocess.run([sys.executable, str(_SCRIPT), *a],
                                  capture_output=True, text=True).returncode
        expect(cli("--files", good) == 0, "CLI: clean fragment exits 0")
        bad = _write(d, "9-badcli.X", [_full(finding_id="s", impact=["I3"], exposure=["E0"],
                                             severity_mapped="SHOULD")])
        expect(cli("--files", bad) == 1, "CLI: fragment with findings exits 1")
        expect(cli("--files", str(Path(d) / "nope.jsonl")) == 1, "CLI: nonexistent --files exits 1")
        expect(cli("--base", "refs/heads/definitely-not-a-ref-xyz") == 2,
               "CLI: bad --base fails CLOSED, exit 2 (F4)")

    if _FAILURES:
        print(f"\ngovernance-ledger-check self-test: FAILED ({len(_FAILURES)} case(s))")
        return 1
    print("\ngovernance-ledger-check self-test: OK - constants pinned; linter discriminates "
          "on every seeded defect incl. sparse-merge and restored-middle-row")
    return 0


if __name__ == "__main__":
    sys.exit(run())
