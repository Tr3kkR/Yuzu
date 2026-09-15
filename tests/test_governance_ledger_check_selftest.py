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
    recorded_by, recorded_at, pass_ordinal, reviewed_at_sha, disposition) plus
    the usual finding-content fields."""
    base = {
        "schema_version": 1, "run_id": None, "finding_id": "f1",
        "reporter": "architect", "source": "governance-agent",
        "reviewed_at_sha": "abc123 (merge-base def456)", "recorded_by": "Claude",
        "recorded_at": "2026-09-15T10:00:00Z", "pass_ordinal": 0,
        "severity_native": "MEDIUM", "severity_mapped": "SHOULD",
        "impact": ["I6"], "exposure": ["E0"], "policy_floor": None,
        "classification": None, "disposition": "open", "independent_reporters": 1,
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


def _write(dirpath, stem, rows):
    p = Path(dirpath) / f"{stem}.jsonl"
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

        # -------- (5) F11: legacy row (no schema_version, no recorded_at) is PARTIALLY exempt --------
        # Exempt: the eight per-row-mandatory fields, and disposition's CLOSED-
        # ENUM half (a #2643-era convention, later than #2619's schema_version).
        # NOT exempt: disposition's own must-be-a-string check, and the
        # content-shape enums (classification/epistemic_status/provenance),
        # which are general contracts predating any schema-versioning split -
        # a genuinely ancient row can still carry a value worth flagging there.
        legacy = {"finding_id": "L", "reporter": "architect", "source": "governance-agent",
                  "impact": ["I6"], "exposure": ["E0"], "severity_mapped": "SHOULD",
                  "disposition": "open", "run_id": "9-legacy.X"}
        lf = M.check_fragment(_write(d, "9-legacy.X", [legacy]))
        expect(not any(f.rule in ("missing-field", "missing-row-field", "bad-disposition")
                       for f in lf),
               f"legacy row (no schema_version/recorded_at) not flagged missing-*/bad-disposition-enum "
               f"(F11) (got {_rules(lf)})")
        legacy_bad_cls = dict(legacy, classification="invented")
        lbc = M.check_fragment(_write(d, "9-legacycls.X", [legacy_bad_cls]))
        expect("bad-classification" in _rules(lbc),
               f"legacy row with an off-enum classification STILL fires - content enums are not "
               f"legacy-exempt, only the per-row-mandatory-8 and disposition's closed-enum half are "
               f"(got {_rules(lbc)})")

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
