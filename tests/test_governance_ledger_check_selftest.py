#!/usr/bin/env python3
"""Self-test for scripts/ci/check-governance-ledger.py - the author-side
governance-ledger linter.

The linter is ADVISORY (a pre-push self-check the /governance skill runs on the
current run's fragment, not a corpus CI gate). This self-test does NOT lint the
real corpus; it (1) PINS the linter's policy constants against literals so a
silent edit to a band, an enum, or the eight per-row mandatory fields fails
here in reviewed test code (mirroring tests/test_seam_closure_selftest.py),
and (2) feeds the checker synthetic good/bad fragments and asserts it
DISCRIMINATES - a conforming ledger (including the prescribed SPARSE-
supersession shape, which restates ONLY changed fields plus the eight
per-row-mandatory ones) yields nothing, a NON-conforming sparse row that omits
one of the eight fires, an intermediate violation a later row restores is
still caught (the ledger is a FIELD-WISE MERGE, not last-row-wins), and a
malformed `recorded_at` is flagged rather than silently swallowed - including
the dangerous direction where it can hide a real severity escalation.
(3) exercises the CLI exit-code contract via subprocess, pinned to a scratch
git repo so the --base tests don't depend on this checkout's own state.

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
_REPO_ROOT = _SCRIPT.parents[2]


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
    """A complete, conforming governance-agent row - carries all eight fields
    SKILL.md mandates on EVERY row (schema_version, run_id, finding_id,
    recorded_by, recorded_at, pass_ordinal, reviewed_at_sha, disposition),
    plus epistemic_status/provenance/classification at valid non-null values
    (SKILL.md marks these required, not nullable, unlike impact/exposure) and
    the usual finding-content fields."""
    base = {
        "schema_version": 1, "run_id": None, "finding_id": "f1",
        "reporter": "architect", "source": "governance-agent",
        "reviewed_at_sha": "abc123 (merge-base def456)", "recorded_by": "Claude",
        "recorded_at": "2026-09-15T10:00:00Z", "pass_ordinal": 0,
        "severity_native": "MEDIUM", "severity_mapped": "SHOULD",
        "impact": ["I6"], "exposure": ["E0"], "policy_floor": None,
        "classification": "truth-contradiction", "epistemic_status": "likely",
        "provenance": "introduced", "disposition": "open", "independent_reporters": 1,
        "adjudicated_by": None, "adjudication_rationale": None,
    }
    base.update(kw)
    return base


def _sparse(**kw):
    """A CONFORMING sparse supersession row: carries exactly the eight
    per-row-mandatory fields (defaults matching _full()'s finding_id/sha/etc)
    plus whatever else the caller wants to restate. Fields NOT in the eight
    (impact, severity_native, classification, ...) are legitimately omitted
    when unchanged - the whole point of the sparse shape."""
    base = {
        "schema_version": 1, "run_id": None, "finding_id": "f1",
        "recorded_by": "Claude", "reviewed_at_sha": "abc123 (merge-base def456)",
        "recorded_at": "2026-09-15T11:00:00Z", "pass_ordinal": 0,
        "disposition": "fixed",
    }
    base.update(kw)
    return base


def _write(dirpath, stem, rows, stamp_run_id=True):
    p = Path(dirpath) / f"{stem}.jsonl"
    if stamp_run_id:
        for r in rows:
            if "run_id" in r:  # only stamp rows that carry the key (keep sparse rows sparse)
                r["run_id"] = stem
    p.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    return str(p)


def _rules(findings):
    return sorted({f.rule for f in findings})


def _scratch_git_repo(tmp):
    """A throwaway one-commit git repo, isolated from this checkout's actual
    history/working tree, so the CLI --base tests are fully deterministic
    regardless of what's currently staged/changed in the real repository."""
    repo = Path(tmp) / "scratch-repo"
    repo.mkdir()
    for args in (["init", "-q"], ["config", "user.email", "t@t.example"],
                ["config", "user.name", "test"]):
        subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)
    (repo / "README.md").write_text("x")
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=repo, check=True, capture_output=True)
    return repo


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
    expect(set(M.LIST_FIELDS) == {"impact", "exposure"}, "pin LIST_FIELDS")
    expect(set(M._HIGH_CAPPED) == {"I4", "I7"}, "pin _HIGH_CAPPED")
    expect(M._LABEL_CEILING == {"BLOCKING": "CRITICAL", "SHOULD": "MEDIUM", "NICE": "LOW"},
           "pin _LABEL_CEILING")
    expect(M._ORDER == ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"], "pin _ORDER")
    expect(tuple(M.REQUIRED_ROW_FIELDS) == ("schema_version", "run_id", "finding_id", "recorded_by",
                                            "recorded_at", "pass_ordinal", "reviewed_at_sha", "disposition"),
           "pin REQUIRED_ROW_FIELDS (the eight SKILL.md mandates on every row)")
    expect(set(M.EPISTEMIC_STATUSES) == {"verified", "likely", "speculative"}, "pin EPISTEMIC_STATUSES")
    expect(set(M.PROVENANCES) == {"introduced", "newly-reachable", "pre-existing"}, "pin PROVENANCES")
    expect(set(M.CLASSIFICATIONS) == {"wording", "truth-contradiction", "absence"}, "pin CLASSIFICATIONS")
    expect(set(M.DISPOSITIONS_CLOSED) == {"open", "fixed", "split", "re-cut", "rejected", "refuted"},
           "pin DISPOSITIONS_CLOSED")
    expect(tuple(M.DISPOSITION_PREFIXES) == ("deferred-to-issue #", "roadmap-#", "linked-to-#"),
           "pin DISPOSITION_PREFIXES")
    expect(tuple(M._FLOOR_MARKERS) == ("CLAUDE.md", "ADR", "routed-concern", "routed concern"),
           "pin _FLOOR_MARKERS")
    expect(set(M._V2619_ONLY_FIELDS) == {"schema_version", "source", "reporter_ref", "reviewed_at_sha",
                                         "recorded_at", "recorded_by", "adjudication_rationale",
                                         "refuted_by", "refuted_by_reporter"},
           "pin _V2619_ONLY_FIELDS (SKILL.md's own citation of what a legacy row lacks)")
    expect(M._looks_versioned({"recorded_by": "x"}) is True,
           "_looks_versioned: a single #2619-only field is sufficient (round-3 fix)")
    expect(M._looks_versioned({"classification": "absence"}) is True,
           "_looks_versioned: classification=='absence' counts too")
    expect(M._looks_versioned({"reporter": "architect", "impact": ["I6"]}) is False,
           "_looks_versioned: none of the markers present -> genuinely legacy")
    expect(M.min_derived_band(["I9"], ["E0"]) == "INFO", "derive I9/E0 -> INFO")
    expect(M.min_derived_band(["I3"], ["E0"]) == "HIGH", "derive I3/E0 -> HIGH")
    expect(M.min_derived_band(["I6"], ["E1"]) == "HIGH", "derive I6/E1 -> HIGH (E1 raises)")
    expect(M.min_derived_band(["I2"], ["E6"]) == "LOW", "derive I2/E6 -> LOW (E6 caps)")
    expect(M.min_derived_band(["I4"], ["E1"]) == "HIGH", "derive I4/E1 -> HIGH (I4 cap, F9)")
    expect(M.min_derived_band([], ["E0"]) == "INFO", "derive empty -> INFO")
    expect(M.min_derived_band(["I1", "I4"], ["E1"]) == "CRITICAL",
           "per-impact cap: I1 escalates to CRITICAL under E1 even alongside I4's own HIGH cap")
    expect(M.floor_cites_closed_source("CLAUDE.md standing rule 2") is True,
           "floor_cites_closed_source recognizes a real citation")
    expect(M.floor_cites_closed_source("just because") is False,
           "floor_cites_closed_source rejects a bare excuse string")
    # round-4 review blocker: a parsed-but-offset-less recorded_at must be
    # treated as AMBIGUOUS, not silently coerced to UTC (one parseability
    # tier away from the wholly-invalid-string case round 2 already fixed).
    expect(M._instant("2026-09-15") is None, "_instant rejects a bare date (no time, no offset)")
    expect(M._instant("2026-09-15T08:00:00") is None, "_instant rejects a naive datetime (no offset)")
    expect(M._instant("2026-09-15T08:00:00Z") is not None, "_instant still accepts a Z-suffixed instant")
    expect(M._instant("2026-09-15T08:00:00+05:00") is not None, "_instant still accepts an explicit offset")

    with tempfile.TemporaryDirectory() as d:
        # -------- (2a) field-wise merge: a CONFORMING sparse supersession is clean --------
        # row1 is the full finding; row2 restates the eight per-row-mandatory
        # fields PLUS disposition (the only content field that changed) -
        # exactly the shape SKILL.md prescribes. Last-row-replace would
        # false-fire missing-field; the field-wise merge keeps row1's content.
        sparse = _write(d, "1234-sparse.AbCd", [
            _full(finding_id="a"),
            _sparse(finding_id="a"),
        ])
        expect(M.check_fragment(sparse) == [],
               f"conforming sparse supersession (all 8 mandatory fields + disposition) is clean "
               f"(got {_rules(M.check_fragment(sparse))})")

        # -------- (2a-neg) a NON-conforming sparse row (omits mandatory fields) fires --------
        nonconforming = _write(d, "1234-nonconf.AbCd", [
            _full(finding_id="a"),
            {"finding_id": "a", "recorded_at": "2026-09-15T11:00:00Z", "disposition": "fixed"},
        ])
        ncf = M.check_fragment(nonconforming)
        expect(_rules(ncf) == ["missing-row-field"],
               f"non-conforming sparse row (omits schema_version/run_id/recorded_by/pass_ordinal/"
               f"reviewed_at_sha) fires missing-row-field only (got {_rules(ncf)})")
        expect(sum(f.rule == "missing-row-field" for f in ncf) == 5,
               f"exactly the 5 omitted mandatory fields are each reported (got {len(ncf)})")

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
            # a genuine, valid empty-impact + closed-source-floor BLOCKING row - not flagged
            _full(finding_id="k", impact=[], exposure=["E0"], severity_mapped="BLOCKING",
                  severity_native="HIGH", policy_floor="CLAUDE.md standing rule 2"),
            # every closed-vocabulary field at a valid value
            _full(finding_id="m", epistemic_status="likely", provenance="introduced",
                  classification="truth-contradiction", disposition="deferred-to-issue #17"),
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
        # policy_floor gaming vector: a bogus/fabricated floor string must NOT
        # excuse an empty-impact BLOCKING claim; only a closed-source citation does.
        fires("9-fakefloor.X", [_full(finding_id="s", impact=[], exposure=["E0"],
                                      severity_mapped="BLOCKING", policy_floor="just because")],
              "severity-empty-impact", "empty impact + BLOCKING + FABRICATED floor still fires")
        clean_of("9-realfloor.X", [_full(finding_id="s", impact=[], exposure=["E0"],
                                         severity_mapped="BLOCKING",
                                         policy_floor="CLAUDE.md standing rule 2")],
                 "severity-empty-impact", "empty impact + BLOCKING + REAL closed-source floor is excused")
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

        # omission-then-presence is the SAME fabrication as null-then-presence:
        # the finding's first row never mentions severity_native at all (not
        # even as null), and a later row introduces "HIGH" out of nowhere.
        omit_first = _full(finding_id="oo", recorded_at="2026-09-15T10:00:00Z",
                           impact=["I6"], severity_mapped="SHOULD")
        omit_first.pop("severity_native")
        fires("9-nativeomit.X", [
            omit_first,
            _full(finding_id="oo", recorded_at="2026-09-15T11:00:00Z", severity_native="HIGH",
                  impact=["I6"], severity_mapped="SHOULD")],
            "native-mutated", "absent-key-then-present-value invents native too (minor fix)")

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

        # bad-recorded-at: a versioned row whose timestamp doesn't parse is
        # reported, not silently swallowed as legacy.
        fires("9-badra.X", [
            _full(finding_id="br"),
            _sparse(finding_id="br", recorded_at="NOT-A-TIMESTAMP")],
            "bad-recorded-at", "unparseable recorded_at on a versioned row fires")

        # THE dangerous direction (round-2 review): a malformed timestamp on a
        # genuine severity ESCALATION must not let the fragment read as clean -
        # the escalation can silently lose the merge to the earlier, lower row.
        esc = _write(d, "9-escalation.X", [
            _full(finding_id="e1", recorded_at="2026-09-15T10:00:00Z",
                  severity_native="INFO", severity_mapped="NICE", impact=["I9"], exposure=["E0"]),
            _full(finding_id="e1", recorded_at="NOT-A-TIMESTAMP",
                  severity_native="HIGH", severity_mapped="BLOCKING", impact=["I1"], exposure=["E3"]),
        ])
        ef = M.check_fragment(esc)
        expect(any(f.rule == "bad-recorded-at" for f in ef),
               f"malformed-timestamp escalation is NOT reported clean (got {_rules(ef)})")

        # round-4 review blocker: an AMBIGUOUS timestamp (parses, but no
        # timezone offset) on a genuine escalation is just as dangerous as a
        # wholly-invalid one - reproduced for both the bare-date and the
        # naive-datetime forms.
        for ambiguous_ra, label in (("2026-09-15", "bare date"), ("2026-09-15T08:00:00", "naive datetime")):
            esc2 = _write(d, f"9-ambig-{label.replace(' ', '')}.X", [
                _full(finding_id="e1", recorded_at="2026-09-15T10:00:00Z",
                      severity_native="INFO", severity_mapped="NICE", impact=["I9"], exposure=["E0"]),
                _full(finding_id="e1", recorded_at=ambiguous_ra,
                      severity_native="HIGH", severity_mapped="BLOCKING", impact=["I1"], exposure=["E3"]),
            ])
            ef2 = M.check_fragment(esc2)
            expect(any(f.rule == "bad-recorded-at" for f in ef2),
                   f"ambiguous recorded_at ({label}) on an escalation is NOT reported clean "
                   f"(got {_rules(ef2)})")

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
        fires("9-emptyrep.X", [_full(finding_id="j", reporter="")],
              "empty-reporter", "empty-string reporter fires")
        fires("9-intrep.X", [_full(finding_id="j", reporter=7)],
              "bad-reporter-type", "bare-integer reporter fires")
        fires("9-boolrep.X", [_full(finding_id="j", reporter=True)],
              "bad-reporter-type", "boolean reporter fires (bool is not a valid reporter string)")
        fires("9-src.X", [_full(finding_id="j", source="robot")], "bad-source", "bad source fires")
        badref = _full(finding_id="j", source="external-model"); badref.pop("reporter_ref", None)
        badref["reporter_ref"] = None
        fires("9-ref.X", [badref], "missing-reporter-ref", "external-model without ref fires")
        fires("9-scalar.X", [_full(finding_id="j", impact="I5")],
              "scalar-list-field", "scalar impact fires (F8)")
        fires("9-scalarexp.X", [_full(finding_id="j", exposure="E0")],
              "scalar-list-field", "scalar exposure ALSO fires (not just impact)")
        nofloor = _full(finding_id="j"); nofloor.pop("policy_floor")
        fires("9-floorkey.X", [nofloor], "missing-field", "missing policy_floor key fires")
        fires("9-boolir.X", [_full(finding_id="j", independent_reporters=True)],
              "bad-independent-reporters", "boolean independent_reporters fires (bool is not an int here)")
        fires("9-boolsv.X", [_full(finding_id="j", schema_version=True)],
              "bad-schema-version", "boolean schema_version fires")
        fires("9-negpo.X", [_full(finding_id="j", pass_ordinal=-1)],
              "bad-pass-ordinal", "negative pass_ordinal fires")
        fires("9-epi.X", [_full(finding_id="j", epistemic_status="certain")],
              "bad-epistemic-status", "off-enum epistemic_status fires")
        fires("9-prov.X", [_full(finding_id="j", provenance="somewhere")],
              "bad-provenance", "off-enum provenance fires")
        fires("9-cls.X", [_full(finding_id="j", classification="invented")],
              "bad-classification", "off-enum classification fires")
        fires("9-disp.X", [_full(finding_id="j", disposition="no_change_needed")],
              "bad-disposition", "off-enum disposition fires")
        clean_of("9-dispok.X", [_full(finding_id="j", disposition="deferred-to-issue #4")],
                 "bad-disposition", "valid '#N'-suffixed disposition is NOT flagged")
        # disposition TYPE violations (bedrock, apply regardless of legacy status)
        for bad_disp in (7, True, None, [], {}):
            fires(f"9-disptype-{type(bad_disp).__name__}.X", [_full(finding_id="j", disposition=bad_disp)],
                  "bad-disposition", f"non-string disposition {bad_disp!r} fires")
        # an empty '#' suffix is genuinely malformed - nothing follows the prefix
        fires("9-dispempty.X", [_full(finding_id="j", disposition="roadmap-#")],
              "bad-disposition", "empty '#' suffix ('roadmap-#') fires")
        # a non-empty but non-numeric suffix is DELIBERATELY still accepted: the
        # real corpus carries free-text notes trailing a placeholder
        # ("#TBD (draft: ...)"), so requiring a strictly numeric/placeholder
        # suffix would false-positive on legitimate historical/future entries.
        clean_of("9-dispgarbage.X", [_full(finding_id="j", disposition="linked-to-#garbage")],
                 "bad-disposition", "non-empty non-numeric '#' suffix is accepted (documented leniency)")
        clean_of("9-dispplaceholder.X", [_full(finding_id="j", disposition="deferred-to-issue #?")],
                 "bad-disposition", "the schema's own '#?' unfilled-park placeholder is accepted")
        # schema_version/pass_ordinal are two of the eight per-row-mandatory
        # fields: an explicit null is never legitimate once the key exists (it
        # would otherwise hide behind "key present", passing missing-row-field
        # for free) - unlike independent_reporters, which legitimately carries
        # null in the real corpus as "not yet counted".
        fires("9-svnull.X", [_full(finding_id="j", schema_version=None)],
              "bad-schema-version", "explicit null schema_version fires (not silently 'absent')")
        fires("9-ponull.X", [_full(finding_id="j", pass_ordinal=None)],
              "bad-pass-ordinal", "explicit null pass_ordinal fires (not silently 'absent')")
        clean_of("9-irnull.X", [_full(finding_id="j", independent_reporters=None)],
                 "bad-independent-reporters", "explicit null independent_reporters is NOT flagged (legit 'uncounted')")

        # round-4 review should-fix: generalize the pass_ordinal/run_id
        # per-row-VALUE pattern to the rest of the eight mandatory fields - a
        # bad value on an EARLY row that a later valid row "corrects" must
        # still fire, since the merge would otherwise erase all trace of it.
        fires("9-svearly.X", [
            _full(finding_id="e", recorded_at="2026-09-15T10:00:00Z", schema_version="one"),
            _full(finding_id="e", recorded_at="2026-09-15T11:00:00Z", schema_version=1, disposition="fixed")],
            "bad-schema-version", "a bad schema_version on an EARLY row still fires even though a later row corrects it")
        fires("9-shaempty.X", [_full(finding_id="j", reviewed_at_sha="")],
              "bad-reviewed-at-sha", "empty-string reviewed_at_sha fires")
        fires("9-shanull.X", [_full(finding_id="j", reviewed_at_sha=None)],
              "bad-reviewed-at-sha", "null reviewed_at_sha fires")
        # Sol's round-4 review caught that a bare truthiness/None check on
        # these two fields lets wrong-typed and whitespace-only values slip
        # through (7 and "   " are both truthy; [] is falsy but not a SHA).
        fires("9-shawrongtype.X", [_full(finding_id="j", reviewed_at_sha=7)],
              "bad-reviewed-at-sha", "a non-string reviewed_at_sha (e.g. int) fires")
        fires("9-shawhitespace.X", [_full(finding_id="j", reviewed_at_sha="   ")],
              "bad-reviewed-at-sha", "a whitespace-only reviewed_at_sha fires")
        # recorded_by is the ONE conditional case: nullable on the row that
        # FIRST raises the finding, required (non-null, non-empty-string) on
        # any supersession.
        clean_of("9-rbfirstnull.X", [_full(finding_id="j", recorded_by=None)],
                 "bad-recorded-by", "null recorded_by on the FIRST (raising) row is legitimate")
        fires("9-rblatenull.X", [
            _full(finding_id="j", recorded_at="2026-09-15T10:00:00Z"),
            _full(finding_id="j", recorded_at="2026-09-15T11:00:00Z", recorded_by=None, disposition="fixed")],
            "bad-recorded-by", "null recorded_by on a SUPERSESSION fires (someone must be named as recorder)")
        fires("9-rbwrongtype.X", [
            _full(finding_id="j", recorded_at="2026-09-15T10:00:00Z"),
            _full(finding_id="j", recorded_at="2026-09-15T11:00:00Z", recorded_by=7, disposition="fixed")],
            "bad-recorded-by", "a non-string recorded_by (e.g. int) on a supersession fires")
        fires("9-rbempty.X", [
            _full(finding_id="j", recorded_at="2026-09-15T10:00:00Z"),
            _full(finding_id="j", recorded_at="2026-09-15T11:00:00Z", recorded_by="", disposition="fixed")],
            "bad-recorded-by", "an empty-string recorded_by on a supersession fires")
        # Fable's round-4 misattribution note: row_pos depends on sort order,
        # which a prior bad-recorded-at row already makes indeterminate - the
        # genuine raising row (legitimately null recorded_by) can get displaced
        # to row_pos!=0 and misfire bad-recorded-by. The fragment is already
        # non-clean via bad-recorded-at either way, but the message must own
        # the ambiguity rather than assert a wrong attribution as fact.
        misattr = M.check_fragment(_write(d, "9-rbmisattr.X", [
            _full(finding_id="m", recorded_at="NOT-A-TIMESTAMP"),
            _full(finding_id="m", recorded_at="2026-09-15T10:00:00Z", recorded_by=None)]))
        rb_msgs = [f.msg for f in misattr if f.rule == "bad-recorded-by"]
        expect(len(rb_msgs) == 1 and "indeterminate" in rb_msgs[0] and "misattributing" in rb_msgs[0],
               f"a bad-recorded-by fired alongside bad-recorded-at discloses the row-order ambiguity "
               f"rather than silently asserting a possibly-wrong attribution (got {rb_msgs})")
        fires("9-dispearly.X", [
            _full(finding_id="e2", recorded_at="2026-09-15T10:00:00Z", disposition=7),
            _full(finding_id="e2", recorded_at="2026-09-15T11:00:00Z", disposition="fixed")],
            "bad-disposition", "a non-string disposition on an EARLY row still fires per row")
        # positive control: a LEGITIMATE corrective supersession of an earlier
        # omission of epistemic_status/provenance/classification must stay
        # clean - the required-presence check resolves via the MERGE (like
        # every other content field), not strictly the raising row.
        missing_then_fixed = _full(finding_id="corr", recorded_at="2026-09-15T10:00:00Z")
        missing_then_fixed.pop("epistemic_status")
        epicorrected = M.check_fragment(_write(d, "9-epicorrected.X", [
            missing_then_fixed,
            _sparse(finding_id="corr", recorded_at="2026-09-15T11:00:00Z", epistemic_status="likely")]))
        expect(epicorrected == [],
               f"a later CONFORMING sparse row legitimately supplying an earlier-omitted "
               f"epistemic_status is fully clean, not merely missing-field-free (got {_rules(epicorrected)})")

        # bad-finding-id: previously zero self-test coverage (mutation-tested
        # by both round-4 reviewers - deleting the rule left the suite green).
        p_badfid = Path(d) / "9-badfid.X.jsonl"
        p_badfid.write_text(json.dumps({**_full(), "finding_id": None, "run_id": "9-badfid.X"}) + "\n",
                            encoding="utf-8")
        expect(any(f.rule == "bad-finding-id" for f in M.check_fragment(str(p_badfid))),
               "a row with a null/non-string finding_id fires bad-finding-id")

        # -------- (5) round-3 review: the two-discriminator legacy heuristic --------
        # A row is genuinely legacy ONLY if it carries NONE of the fields
        # #2619 introduced (SKILL.md's own citation: source, reporter_ref,
        # reviewed_at_sha, recorded_at, recorded_by, adjudication_rationale,
        # the refuted pair, classification=="absence") - checking only
        # schema_version/recorded_at missed a row that omits BOTH of those
        # two while still carrying e.g. recorded_by/reviewed_at_sha, letting a
        # real escalation vanish with zero findings.
        double_omit_row1 = _full(finding_id="e1", severity_native="INFO", severity_mapped="NICE",
                                 impact=["I9"], exposure=["E0"])
        double_omit_row2 = {"finding_id": "e1", "recorded_by": "x", "reviewed_at_sha": "def",
                            "pass_ordinal": 1, "severity_native": "HIGH", "severity_mapped": "BLOCKING",
                            "impact": ["I1"], "exposure": ["E3"], "disposition": "open"}
        do = M.check_fragment(_write(d, "9-doubleomit.X", [double_omit_row1, double_omit_row2]))
        expect(do != [],
               f"a row carrying recorded_by/reviewed_at_sha but omitting BOTH schema_version and "
               f"recorded_at is still recognized as modern, not silently legacy (got {_rules(do)})")
        expect("missing-row-field" in _rules(do),
               f"...specifically via missing-row-field for the omitted schema_version/recorded_at "
               f"(got {_rules(do)})")

        # round-3 review, blocker 2: pass_ordinal determines MERGE ORDER via
        # _order_key BEFORE anything validates its value - a bad value on the
        # LOSING row of a tie can silently determine the wrong outcome and then
        # vanish, since only merged["pass_ordinal"] (the WINNING row's own,
        # possibly-fine value) was ever checked. Two rows at an IDENTICAL
        # timestamp, one with a genuine escalation and a string pass_ordinal.
        tie_row1 = _full(finding_id="e2", recorded_at="2026-09-15T10:00:00Z", pass_ordinal=1,
                         severity_native="INFO", severity_mapped="NICE", impact=["I9"], exposure=["E0"])
        tie_row2 = _full(finding_id="e2", recorded_at="2026-09-15T10:00:00Z", pass_ordinal="2",
                         severity_native="HIGH", severity_mapped="BLOCKING", impact=["I1"], exposure=["E3"])
        tf = M.check_fragment(_write(d, "9-tiepo.X", [tie_row1, tie_row2]))
        expect(any(f.rule == "bad-pass-ordinal" for f in tf),
               f"a string pass_ordinal on a tied-timestamp row fires bad-pass-ordinal on ITS OWN row, "
               f"not only checked after it already determined (and lost) the merge (got {_rules(tf)})")

        # per-row run_id mismatch (minor, side effect of the pass_ordinal fix):
        # a MID-history wrong run_id that a later row incidentally restates
        # correctly must still fire, since the merged view alone would read
        # clean. NOTE: _write() normally stamps every row's run_id to match
        # the stem (so ordinary fixtures don't have to care) - these two
        # tests need stamp_run_id=False to deliberately keep a WRONG value.
        midrow1 = _full(finding_id="rid", recorded_at="2026-09-15T10:00:00Z", run_id="WRONG-STEM")
        midrow2 = _full(finding_id="rid", recorded_at="2026-09-15T11:00:00Z", disposition="fixed")
        midf = M.check_fragment(_write(d, "9-runidmid.X", [midrow1, midrow2], stamp_run_id=False))
        expect("run-id-mismatch" in _rules(midf),
               f"a mid-history wrong run_id still fires even though a later row restates it "
               f"correctly (got {_rules(midf)})")

        # -------- (6) the 5 previously-unfixtured rules (mutation-tested: stripping
        # any of these rule bodies from a copy of the checker left the suite green) --------
        ridtop = _full(finding_id="j", run_id="totally-different-stem")
        rtf = M.check_fragment(_write(d, "9-ridtop.X", [ridtop], stamp_run_id=False))
        expect("run-id-mismatch" in _rules(rtf),
               f"run_id not matching the filename stem fires (got {_rules(rtf)})")
        fires("9-impact.X", [_full(finding_id="j", impact=["I99"])],
              "bad-impact", "off-enum impact code fires")
        fires("9-exposure.X", [_full(finding_id="j", exposure=["E99"])],
              "bad-exposure", "off-enum exposure code fires")
        fires("9-sevmap.X", [_full(finding_id="j", severity_mapped="URGENT")],
              "bad-severity-mapped", "off-enum severity_mapped fires")
        fires("9-linktop.X", [_full(finding_id="j", impact=["I2"], exposure=["E0"],
                                    severity_mapped="BLOCKING", severity_native="HIGH",
                                    disposition="linked-to-#123")],
              "linked-top-severity", "linked-to- disposition on an I1/I2/I3 finding fires (a prompt, not a verdict)")

        # -------- (7) epistemic_status/provenance/classification are REQUIRED, --------
        # not nullable, per SKILL.md's field table (unlike impact/exposure,
        # which explicitly tolerate a null fact set) - on the FIRST-raising row,
        # resolved via the merge like any other content field (a later
        # supersession may correct an earlier omission).
        for req_field in ("epistemic_status", "provenance", "classification"):
            missing_row = _full(finding_id="j"); missing_row.pop(req_field)
            fires(f"9-missing-{req_field}.X", [missing_row], "missing-field",
                  f"omitted {req_field} on the raising row fires missing-field")
            null_row = _full(finding_id="j", **{req_field: None})
            fires(f"9-null-{req_field}.X", [null_row], "missing-field",
                  f"explicit null {req_field} fires missing-field too (unlike impact/exposure)")
        # severity_mapped is set to NICE here specifically so severity-empty-impact
        # (a SEPARATE, legitimate rule - empty impact + a non-NICE label + no
        # floor) doesn't also fire and confuse what this fixture is isolating.
        impactnull_findings = M.check_fragment(_write(d, "9-impactnull.X",
            [_full(finding_id="j", impact=None, severity_mapped="NICE", severity_native="INFO")]))
        expect(_rules(impactnull_findings) == [],
               f"explicit null impact fires NEITHER missing-field NOR scalar-list-field - a "
               f"legit empty fact set (got {_rules(impactnull_findings)})")

        # -------- (8) F11: legacy row (no ANY #2619-introduced field) is PARTIALLY exempt --------
        # Exempt: the eight per-row-mandatory fields, the NEW required-content
        # fields (epistemic_status/provenance/classification presence), and
        # disposition's CLOSED-ENUM half (a #2643-era convention, later than
        # #2619's schema_version). NOT exempt: disposition's own
        # must-be-a-string check, and the content enums' VALUE validity
        # (classification/epistemic_status/provenance still reject a garbage
        # value if present) - those are general contracts predating any
        # schema-versioning split, so a genuinely ancient row can still carry
        # a value worth flagging. Deliberately carries NO `source` key: source
        # is ITSELF one of the #2619-introduced markers (SKILL.md's own
        # citation), so a fixture that includes it is not actually legacy-shaped.
        legacy = {"finding_id": "L", "reporter": "architect",
                  "impact": ["I6"], "exposure": ["E0"], "severity_mapped": "SHOULD",
                  "disposition": "open", "run_id": "9-legacy.X"}
        lf = M.check_fragment(_write(d, "9-legacy.X", [legacy]))
        expect(not any(f.rule in ("missing-field", "missing-row-field", "bad-disposition")
                       for f in lf),
               f"legacy row (no #2619-introduced field at all) not flagged missing-*/bad-disposition-enum "
               f"(F11) (got {_rules(lf)})")
        legacy_bad_cls = dict(legacy, classification="invented")
        lbc = M.check_fragment(_write(d, "9-legacycls.X", [legacy_bad_cls]))
        expect("bad-classification" in _rules(lbc),
               f"legacy row with an off-enum classification STILL fires - content-value validity is not "
               f"legacy-exempt, only the per-row-mandatory-8/required-content-presence and disposition's "
               f"closed-enum half are (got {_rules(lbc)})")

        # Fable review (post-round-3): the finding-level `legacy` flag must be
        # computed from the RAW rows, not the merged view - merged_view()
        # strips the three attestation-only markers (adjudication_rationale,
        # refuted_by, refuted_by_reporter), so a finding whose ONLY #2619
        # marker is one of those three would read as versioned per-row but
        # legacy at the merged level, wrongly exempting it from the merged-view
        # checks below (source/policy_floor/required-content presence).
        att_only = {"finding_id": "att-only", "reporter": "architect", "impact": ["I6"],
                   "exposure": ["E0"], "severity_mapped": "SHOULD", "disposition": "refuted",
                   "refuted_by": "git show ... proves it false", "refuted_by_reporter": "not-the-author",
                   "run_id": "9-attonly.X"}
        af = M.check_fragment(_write(d, "9-attonly.X", [att_only]))
        expect(any(f.rule == "missing-field" and "'source'" in f.msg for f in af),
               f"a row whose ONLY #2619 marker is an attestation field (refuted_by) is still treated "
               f"as non-legacy at the FINDING level, so merged-view checks (e.g. missing 'source') "
               f"still apply (got {_rules(af)})")

        # -------- robustness: odd types / invalid json don't crash --------
        p = Path(d) / "9-weird.X.jsonl"
        p.write_text(json.dumps(_full(finding_id="z", run_id="9-weird.X")) + "\n{bad}\n",
                     encoding="utf-8")
        expect(any(f.rule == "invalid-json" for f in M.check_fragment(str(p))),
               "invalid-json flagged without crashing")

        # -------- (6) CLI exit-code contract (F10), via subprocess, pinned cwd --------
        scratch = _scratch_git_repo(d)

        def cli(*a, cwd=None):
            return subprocess.run([sys.executable, str(_SCRIPT), *a], capture_output=True,
                                  text=True, cwd=cwd or str(_REPO_ROOT)).returncode

        expect(cli("--files", good) == 0, "CLI: clean fragment exits 0")
        bad = _write(d, "9-badcli.X", [_full(finding_id="s", impact=["I3"], exposure=["E0"],
                                             severity_mapped="SHOULD")])
        expect(cli("--files", bad) == 1, "CLI: fragment with findings exits 1")
        expect(cli("--files", str(Path(d) / "nope.jsonl")) == 1, "CLI: nonexistent --files exits 1")
        # positive control: a scratch repo with no governance.d changes and a
        # genuinely resolvable --base (HEAD itself) must exit 0 - proves the
        # diff-scoped path works at all, not just that it fails on a bad ref.
        expect(cli("--base", "HEAD", cwd=str(scratch)) == 0,
               "CLI: good --base (HEAD, isolated scratch repo) exits 0 (positive control)")
        expect(cli("--base", "refs/heads/definitely-not-a-ref-xyz", cwd=str(scratch)) == 2,
               "CLI: bad --base fails CLOSED, exit 2 (F4), pinned cwd")

    if _FAILURES:
        print(f"\ngovernance-ledger-check self-test: FAILED ({len(_FAILURES)} case(s))")
        return 1
    print("\ngovernance-ledger-check self-test: OK - constants pinned; linter discriminates "
          "on every seeded defect incl. sparse-merge, per-row-mandatory-fields, and "
          "malformed-timestamp escalation-loss")
    return 0


if __name__ == "__main__":
    sys.exit(run())
