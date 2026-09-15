#!/usr/bin/env python3
"""check-governance-ledger.py - author-side self-consistency linter for a
governance.d run-ledger fragment.

WHAT THIS IS: a LINTER you run on YOUR OWN run's ledger fragment before you
push, to preview the self-consistency problems a strict reviewer will flag -
so a governance ledger stops taking multiple review rounds to converge. PR
#4337 took seven review rounds, every one a ledger-metadata self-consistency
defect while the code under review was byte-identical from round 1; each check
below is one of those rounds' lessons turned into a machine test.

WHAT THIS IS EXPLICITLY NOT: a blocking CI gate over the whole corpus.
Calibration against all ~330 historical fragments showed the strict rules here
are NOT project-wide invariants - most predate them. Wiring these as a required
check would break on the corpus. So this is an ADVISORY tool: the `/governance`
skill runs it on the current run's fragment as a pre-push step, and you can run
it by hand. The schema authority remains `.claude/skills/governance/SKILL.md`
(Gate 8 field table + the write/merge model at SKILL.md "the live view of a
finding is FIELD-WISE last-write-wins"); this script encodes a checkable subset
and loses to it on any conflict. It judges only mechanical field-consistency,
never whether a finding is true or a severity right.

THE LIVE VIEW IS A FIELD-WISE MERGE, NOT THE LAST ROW. SKILL.md is explicit: a
finding's live view is field-wise last-write-wins across every row sharing its
`finding_id`, ordered by `recorded_at` as a true instant (a row with no
`recorded_at` predates #2619 and sorts BEFORE timestamped rows, in file order;
ties break on higher `pass_ordinal`). List fields (`impact`/`exposure`) REPLACE
wholesale, and the five ATTESTATION fields (`adjudicated_by`,
`adjudication_rationale`, `refuted_by`, `refuted_by_reporter`,
`waiver_rationale`) are ROW-SCOPED and EXEMPT from the merge - they attach to
the row that performed the act, never inherited and never cleared forward.

A superseding row restates ONLY what changed - PLUS eight fields SKILL.md
requires on EVERY row regardless of whether they changed: `schema_version`,
`run_id`, `finding_id`, `recorded_by`, `recorded_at`, `pass_ordinal`,
`reviewed_at_sha`, `disposition`. That per-row minimum is checked on every row
that participates in the post-#2619 regime (identified by carrying either
`recorded_at` or `schema_version` - a row with neither is genuinely legacy and
exempt). Attestation pairing and the one frozen field (`severity_native`,
compared against the FINDING's first row, not merely the first row that
happens to mention the key - an omission-then-later-invention is the same
fabrication as a null-then-later-invention) are also checked PER ROW, so an
intermediate violation a later row incidentally restores is still caught.
`reviewed_at_sha` is deliberately NOT treated as immutable: correcting it
across a supersession is legitimate (its field definition is "the head the
reporter read", not a permanent record).

A `recorded_at` that is PRESENT but does not parse as ISO-8601 is reported
(`bad-recorded-at`) rather than silently treated as legacy: precedence for
that row becomes genuinely indeterminate, and a malformed timestamp on a
severity ESCALATION can silently vanish from the merged view with nothing
else in the format able to surface it - so the fragment must not read as
clean while one exists, even though this script still sorts it legacy-first
as the least-surprising deterministic placement.

USAGE
  check-governance-ledger.py --files governance.d/<frag>.jsonl   # lint one run
  check-governance-ledger.py                                     # diff-scoped: fragments changed vs --base
  check-governance-ledger.py --all                              # audit whole corpus (always report-only)

Exit is nonzero when a targeted fragment has any finding; `--all` always 0. A
git failure in the diff-scoped default FAILS CLOSED (nonzero), never a silent
empty scope.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
import re
import subprocess
import sys
from pathlib import Path

LEDGER_DIR = "governance.d"

IMPACTS = frozenset(f"I{i}" for i in range(1, 10))
EXPOSURES = frozenset({f"E{i}" for i in range(0, 7)} | {"unresolved"})
MAPPED = frozenset({"BLOCKING", "SHOULD", "NICE"})
SOURCES = frozenset({"governance-agent", "collaborator", "external-model"})
ATTESTATION = frozenset({"adjudicated_by", "adjudication_rationale", "refuted_by",
                         "refuted_by_reporter", "waiver_rationale"})
LIST_FIELDS = frozenset({"impact", "exposure"})

# The eight fields SKILL.md requires on EVERY row, changed or not (the write
# model: "Only the fields that CHANGE need restating on a superseding row,
# plus schema_version, run_id, finding_id, recorded_by, recorded_at,
# pass_ordinal, reviewed_at_sha and disposition").
REQUIRED_ROW_FIELDS = ("schema_version", "run_id", "finding_id", "recorded_by",
                       "recorded_at", "pass_ordinal", "reviewed_at_sha", "disposition")

# Closed vocabularies from the Gate 8 field table.
EPISTEMIC_STATUSES = frozenset({"verified", "likely", "speculative"})
PROVENANCES = frozenset({"introduced", "newly-reachable", "pre-existing"})
CLASSIFICATIONS = frozenset({"wording", "truth-contradiction", "absence"})
DISPOSITIONS_CLOSED = frozenset({"open", "fixed", "split", "re-cut", "rejected", "refuted"})
# "deferred-to-issue #N" is a space before '#'; "roadmap-#N" / "linked-to-#N" are a dash.
DISPOSITION_PREFIXES = ("deferred-to-issue #", "roadmap-#", "linked-to-#")

# A policy_floor is a valid gate only if it cites one of the three CLOSED
# sources (a routed-concern catastrophic clause / a CLAUDE.md standing-rule
# sentence / an accepted ADR's normative requirement) - this is a necessary-
# marker check, not proof the citation is real, but it catches "floor sourced
# to nothing" / an invented label (the empty-impact gaming vector).
_FLOOR_MARKERS = ("CLAUDE.md", "ADR", "routed-concern", "routed concern")

# base band per impact code (SKILL.md "IMPACT - gives the base band")
_BASE = {"I1": "HIGH", "I2": "HIGH", "I3": "HIGH", "I4": "HIGH",
         "I5": "MEDIUM", "I6": "MEDIUM", "I7": "MEDIUM",
         "I8": "LOW", "I9": "INFO"}
_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
# impacts whose band is explicitly capped at HIGH regardless of exposure raises
_HIGH_CAPPED = frozenset({"I4", "I7"})
_UNSET = object()
_LABEL_CEILING = {"BLOCKING": "CRITICAL", "SHOULD": "MEDIUM", "NICE": "LOW"}


def _as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _in(value, allowed):
    try:
        return value in allowed
    except TypeError:
        return False


def _is_int(v):
    """int, excluding bool (a bool IS an int in Python; a JSON true/false is
    never a legitimate schema_version/pass_ordinal/independent_reporters)."""
    return isinstance(v, int) and not isinstance(v, bool)


def floor_cites_closed_source(floor):
    return isinstance(floor, str) and any(m in floor for m in _FLOOR_MARKERS)


def min_derived_band(impact, exposure):
    """The FLOOR of the finding's band from the recorded facts alone.

    Only the mechanical parts of the derivation are modelled: base band per
    impact code, the E1/E2 single raise, the E6 LOW cap, and the I4/I7 HIGH
    cap - applied PER IMPACT CODE before taking the max, so a mixed finding
    (e.g. I1+I4 under E1) correctly floors at I1's escalated CRITICAL rather
    than being dragged down to I4's own HIGH ceiling. The CONDITIONAL raises
    SKILL.md defines (I5(a)-(c), I6 FALSE-ASSURANCE/DORMANT-AUTH, I7-conceals)
    can only push the true band HIGHER and cannot be evaluated from the fields
    alone, so this is a lower bound, not the exact band. Used only to catch
    UNDER-grading (a label whose ceiling cannot even reach this floor);
    over-labeling is left alone because it is indistinguishable from a
    legitimate conditional raise.
    """
    codes = [i for i in impact if i in _BASE]
    if not codes:
        return "INFO"
    def _code_band(c):
        idx = _ORDER.index(_BASE[c])
        if any(e in ("E1", "E2") for e in exposure):
            idx = min(idx + 1, len(_ORDER) - 1)
        if c in _HIGH_CAPPED:
            idx = min(idx, _ORDER.index("HIGH"))
        return idx
    idx = max(_code_band(c) for c in codes)
    if "E6" in exposure:
        idx = min(idx, _ORDER.index("LOW"))
    return _ORDER[idx]


class Finding:
    __slots__ = ("path", "fid", "tier", "rule", "msg")

    def __init__(self, path, fid, tier, rule, msg):
        self.path, self.fid, self.tier, self.rule, self.msg = path, fid, tier, rule, msg


_MIN_INSTANT = datetime.min.replace(tzinfo=timezone.utc)


def _instant(ra):
    """Parse an ISO-8601 recorded_at to a tz-aware instant, or None if absent
    or unparseable. Compares actual instants, so fractional seconds and non-Z
    offsets order correctly (a plain string sort does not)."""
    if not isinstance(ra, str) or not ra:
        return None
    s = ra[:-1] + "+00:00" if ra.endswith("Z") else ra
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def _order_key(item):
    idx, r = item
    inst = _instant(r.get("recorded_at"))
    po = r.get("pass_ordinal") if _is_int(r.get("pass_ordinal")) else 0
    if inst is not None:
        return (1, inst, po, idx)          # timestamped: by instant, then pass_ordinal, then file order
    return (0, _MIN_INSTANT, 0, idx)       # no parseable recorded_at: sorts first, in file order


def merged_view(ordered_rows):
    """Field-wise last-write-wins over ordered rows; attestation fields excluded
    (row-scoped); list fields replace wholesale (plain dict assignment)."""
    m = {}
    for _, r in ordered_rows:
        for k, v in r.items():
            if k in ATTESTATION:
                continue
            m[k] = v
    return m


def check_fragment(path):
    out = []

    def add(fid, tier, rule, msg):
        out.append(Finding(path, fid, tier, rule, msg))

    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as e:
        add("", "STRUCTURAL", "unreadable", str(e))
        return out

    rows = []  # (line_no, obj)
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as e:
            add("", "STRUCTURAL", "invalid-json", f"line {n}: {e}")
            continue
        if not isinstance(obj, dict):
            add("", "STRUCTURAL", "invalid-json", f"line {n}: not a JSON object")
            continue
        rows.append((n, obj))
    if not rows:
        return out

    expected_run = Path(path).name[:-len(".jsonl")]

    # group rows by finding_id, preserving file order for the ordering key
    by_fid = {}
    for i, (n, r) in enumerate(rows):
        fid = r.get("finding_id")
        if not isinstance(fid, str) or not fid:
            add("", "STRUCTURAL", "bad-finding-id", f"line {n}: finding_id absent or not a string")
            continue
        by_fid.setdefault(fid, []).append((i, (n, r)))

    for fid, entries in by_fid.items():
        ordered = sorted(((idx, r) for idx, (n, r) in entries), key=_order_key)
        line_of = {id(r): n for _, (n, r) in entries}
        merged = merged_view(ordered)
        legacy = "schema_version" not in merged  # true legacy: NO row ever carried it

        # ---------- PER-ROW checks ----------
        # These run per ROW, not first-vs-live, so an intermediate violation a
        # later row incidentally restores is still caught (the append-only
        # ledger permanently contains the act it recorded).
        native_established = False
        native_seen = None
        for row_pos, (_, r) in enumerate(ordered):
            ln = line_of[id(r)]

            # attestation pairing is a property of the ROW that performed the act
            if bool(r.get("adjudicated_by")) != bool(r.get("adjudication_rationale")):
                add(fid, "STRICT", "adjudication-pairing",
                    f"line {ln}: adjudicated_by and adjudication_rationale must be set together on the same row")

            # severity_native is the reporter's own word, frozen. Baseline is
            # the FIRST ROW's value (None if that row omits the key entirely -
            # the field's own documented default is null when "they gave
            # none"), not merely the first row that happens to mention it: a
            # later row that INTRODUCES a concrete value where the finding's
            # own first row never gave one is the same attribution fabrication
            # as an explicit null-to-value flip, just via omission.
            if row_pos == 0:
                native_seen = r.get("severity_native")
                native_established = True
            elif "severity_native" in r:
                val = r.get("severity_native")
                if val != native_seen:
                    add(fid, "STRICT", "native-mutated",
                        f"line {ln}: severity_native set to {val!r}, "
                        f"differs from the finding's first-row value {native_seen!r} (reporter's own word, immutable)")

            # scalar impact/exposure - the shape the jq park probe's array check exists to catch
            for lf in LIST_FIELDS:
                if lf in r and not isinstance(r[lf], list):
                    add(fid, "STRUCTURAL", "scalar-list-field",
                        f"line {ln}: {lf} must be a JSON array, got {r[lf]!r}")

            # a row that participates in the post-#2619 append model (carries
            # EITHER recorded_at or schema_version - a genuinely legacy row
            # carries neither) must restate the eight mandatory fields, even
            # when otherwise sparse. A malformed recorded_at is reported
            # (precedence for THIS row is then indeterminate) but still sorts
            # legacy-first as the least-surprising deterministic placement -
            # the finding must not read as clean while one exists, since a
            # malformed timestamp on an ESCALATION can silently lose the merge
            # to an earlier, lower-severity row with no other signal.
            ra_present = "recorded_at" in r
            sv_present = "schema_version" in r
            if ra_present and _instant(r.get("recorded_at")) is None:
                add(fid, "STRUCTURAL", "bad-recorded-at",
                    f"line {ln}: recorded_at {r.get('recorded_at')!r} does not parse as ISO-8601; "
                    f"this row's precedence relative to its peers is indeterminate")
            if ra_present or sv_present:
                for req in REQUIRED_ROW_FIELDS:
                    if req not in r:
                        add(fid, "STRUCTURAL", "missing-row-field",
                            f"line {ln}: row omits required field {req!r} "
                            f"(SKILL.md: every row restates it, changed or not - "
                            f"only OTHER fields may be omitted when unchanged)")
        assert native_established  # ordered is never empty (fid groups only nonempty entries)

        # ---------- STRUCTURAL: schema hygiene on the merged view ----------
        # schema_version/run_id/finding_id/disposition PRESENCE is now covered
        # by the per-row 8-field check above for every versioned finding; this
        # loop covers the fields that MAY legitimately be introduced only once
        # and then omitted forever after (they are not in the per-row eight).
        if not legacy:
            for req in ("source", "impact", "exposure", "severity_mapped"):
                if req not in merged:
                    add(fid, "STRUCTURAL", "missing-field",
                        f"live view lacks required field '{req}'")
            if "policy_floor" not in merged:
                add(fid, "STRUCTURAL", "missing-field",
                    "live view lacks 'policy_floor' key (write null, do not omit)")
        if "run_id" in merged and merged.get("run_id") != expected_run:
            add(fid, "STRUCTURAL", "run-id-mismatch",
                f"run_id {merged.get('run_id')!r} != filename stem {expected_run!r}")
        if "source" in merged and not _in(merged.get("source"), SOURCES):
            add(fid, "STRUCTURAL", "bad-source",
                f"source {merged.get('source')!r} not one of {sorted(SOURCES)}")
        if merged.get("source") and merged.get("source") != "governance-agent" and not merged.get("reporter_ref"):
            add(fid, "STRUCTURAL", "missing-reporter-ref",
                "non-governance-agent finding needs reporter_ref (or 'unresolved')")
        for i in _as_list(merged.get("impact")):
            if not _in(i, IMPACTS):
                add(fid, "STRUCTURAL", "bad-impact", f"impact {i!r}")
        for e in _as_list(merged.get("exposure")):
            if not _in(e, EXPOSURES):
                add(fid, "STRUCTURAL", "bad-exposure", f"exposure {e!r}")
        if "severity_mapped" in merged and not _in(merged.get("severity_mapped"), MAPPED):
            add(fid, "STRUCTURAL", "bad-severity-mapped",
                f"severity_mapped {merged.get('severity_mapped')!r}")

        # reporter: exactly one non-empty string value.
        if not legacy:
            rep = merged.get("reporter")
            if rep is None:
                add(fid, "STRUCTURAL", "missing-reporter", "reporter absent (needs exactly one value)")
            elif isinstance(rep, list):
                add(fid, "STRUCTURAL", "list-reporter", f"reporter must be one value, got a list {rep!r}")
            elif not isinstance(rep, str) or isinstance(rep, bool):
                add(fid, "STRUCTURAL", "bad-reporter-type",
                    f"reporter must be a string, got {type(rep).__name__} {rep!r}")
            elif not rep.strip():
                add(fid, "STRUCTURAL", "empty-reporter", "reporter is an empty string (needs exactly one value)")
            elif re.search(r"[+,]| and ", rep):
                add(fid, "STRUCTURAL", "joined-reporter", f"reporter must be one value, got {rep!r}")

        # independent_reporters: null is a legitimate "not yet counted" value in
        # real practice (the corpus carries it), so only a PRESENT-and-wrong-type
        # value fires - unlike schema_version/pass_ordinal below, which are two
        # of the eight per-row-mandatory fields and so are never legitimately
        # null once the key exists (a null there hides behind "key present",
        # passing the separate missing-row-field presence check for free).
        ir = merged.get("independent_reporters")
        if ir is not None and not _is_int(ir):
            add(fid, "STRUCTURAL", "bad-independent-reporters",
                f"independent_reporters must be an integer, got {ir!r}")
        if not legacy:
            sv = merged.get("schema_version")  # key guaranteed present: that's the def'n of `legacy`
            if not _is_int(sv):
                add(fid, "STRUCTURAL", "bad-schema-version", f"schema_version must be an integer, got {sv!r}")
        if "pass_ordinal" in merged:
            po = merged["pass_ordinal"]
            if not _is_int(po) or po < 0:
                add(fid, "STRUCTURAL", "bad-pass-ordinal",
                    f"pass_ordinal must be a non-negative integer, got {po!r}")
        # epistemic_status/provenance/classification are FINDING-CONTENT enums,
        # not append-machinery fields the #2619 schema versioning introduced -
        # their valid values are a general contract, so these checks are NOT
        # legacy-gated (a genuinely ancient row can still carry an off-enum
        # value worth flagging). Only disposition's closed-enum HALF below is
        # legacy-gated, because THAT convention is #2643-era, later than #2619.
        es = merged.get("epistemic_status")
        if es is not None and not _in(es, EPISTEMIC_STATUSES):
            add(fid, "STRUCTURAL", "bad-epistemic-status",
                f"epistemic_status {es!r} not one of {sorted(EPISTEMIC_STATUSES)}")
        prov = merged.get("provenance")
        if prov is not None and not _in(prov, PROVENANCES):
            add(fid, "STRUCTURAL", "bad-provenance", f"provenance {prov!r} not one of {sorted(PROVENANCES)}")
        cls = merged.get("classification")
        if cls is not None and not _in(cls, CLASSIFICATIONS):
            add(fid, "STRUCTURAL", "bad-classification",
                f"classification {cls!r} not one of {sorted(CLASSIFICATIONS)} (or null)")
        # disposition has TWO independent checks. (1) It must always be a
        # non-empty string - bedrock, true in every generation, NOT legacy-
        # gated: a null/int/list/dict disposition is never valid. (2) ONLY once
        # it IS a string is it checked against the closed enum + '#<id>' prefix
        # forms - that convention is #2643-era, so this half stays legacy-gated.
        # A prefix match additionally requires something after the '#' ("roadmap-#"
        # alone, with nothing following, still fails); a non-empty but non-numeric
        # suffix ("linked-to-#garbage") is deliberately still accepted - the real
        # corpus carries free-text notes trailing a placeholder ("#TBD (draft: ...)"),
        # so requiring a strictly numeric/placeholder suffix would false-positive
        # on legitimate historical and future entries.
        disp_val = merged.get("disposition")
        if "disposition" in merged and not (isinstance(disp_val, str) and disp_val.strip()):
            add(fid, "STRUCTURAL", "bad-disposition",
                f"disposition must be a non-empty string, got {type(disp_val).__name__} {disp_val!r}")
        elif not legacy and isinstance(disp_val, str) and disp_val not in DISPOSITIONS_CLOSED:
            prefix_match = next((p for p in DISPOSITION_PREFIXES if disp_val.startswith(p)), None)
            if prefix_match is None or len(disp_val) == len(prefix_match):
                add(fid, "STRUCTURAL", "bad-disposition",
                    f"disposition {disp_val!r} is not in the closed enum {sorted(DISPOSITIONS_CLOSED)} "
                    f"or a valid non-empty '#<id>' prefix form ({DISPOSITION_PREFIXES})")

        # ---------- STRICT: reviewer-class self-consistency on the merged view ----------
        impact = [i for i in _as_list(merged.get("impact")) if _in(i, IMPACTS)]
        exposure = [e for e in _as_list(merged.get("exposure")) if _in(e, EXPOSURES)]
        mapped = merged.get("severity_mapped")
        raw_impact_present = bool(_as_list(merged.get("impact")))
        if _in(mapped, MAPPED):
            floor_band = min_derived_band(impact, exposure)
            ceiling = _LABEL_CEILING[mapped]
            # UNDER-grading only: a label whose ceiling cannot even reach the
            # facts' floor band is definitely too weak. Conditional raises can
            # only push the true band up, so over-labeling is left alone (F2).
            if _ORDER.index(ceiling) < _ORDER.index(floor_band):
                add(fid, "STRICT", "severity-under-derived",
                    f"severity_mapped {mapped!r} (ceiling {ceiling}) is below the facts' "
                    f"floor band {floor_band} (impact={impact} exposure={exposure}); "
                    f"a finding cannot be graded weaker than its own facts derive")
            # empty/absent impact derives INFO unconditionally (no conditional
            # raise applies to no facts). A non-NICE label is then excused ONLY
            # by a policy_floor that cites one of the three closed sources -
            # any other string (or none) is either a bare disagreement or a
            # fabricated floor used to dodge scrutiny, and both must fire.
            if not impact and not raw_impact_present and mapped != "NICE" \
                    and not floor_cites_closed_source(merged.get("policy_floor")):
                add(fid, "STRICT", "severity-empty-impact",
                    f"severity_mapped {mapped!r} with empty impact and a policy_floor that is either "
                    f"absent or does not cite a closed source (CLAUDE.md standing rule / accepted ADR / "
                    f"routed-concern clause) (empty facts derive INFO -> NICE; a genuine floor gates separately)")
        if merged.get("classification") == "wording" and "I7" in impact:
            add(fid, "STRICT", "wording-carries-i7",
                "classification 'wording' cannot carry I7 (standing rule 3 caps wording-only at NICE)")
        # Gate-7 park constraint (mirrors the SKILL.md jq probe): an I1/I2/I3
        # finding may not be parked. roadmap-* is a hard violation; linked-to-*
        # over-matches (a valid ending if the target issue is itself parked), so
        # it is a prompt to verify the target's labels, not an assertion. This
        # deliberately matches on the BARE prefix (no dash), broader than the
        # closed-enum check above, so a truncated off-enum value ("roadmap")
        # still trips the park constraint even though it also trips bad-disposition.
        top = {"I1", "I2", "I3"} & set(impact)
        if isinstance(disp_val, str) and top:
            if disp_val.startswith("roadmap"):
                add(fid, "STRICT", "parked-top-severity",
                    f"disposition {disp_val!r} parks an {sorted(top)} finding (Gate-7 constraint 1 bars this)")
            elif disp_val.startswith("linked-to"):
                add(fid, "STRICT", "linked-top-severity",
                    f"disposition {disp_val!r} links an {sorted(top)} finding to an existing issue - "
                    f"verify that issue is itself parked, else this is a park the constraint bars (prompt, not a verdict)")
    return out


def changed_fragments(base):
    """Diff-scoped discovery. Fails CLOSED: a git error raises, so the caller
    turns it into a nonzero exit rather than a silent empty scope (F4)."""
    mb = subprocess.run(["git", "merge-base", base, "HEAD"],
                        capture_output=True, text=True, check=True).stdout.strip()
    names = subprocess.run(["git", "diff", "--name-only", "--diff-filter=d", f"{mb}...HEAD"],
                           capture_output=True, text=True, check=True).stdout.splitlines()
    return [f for f in names if f.startswith(LEDGER_DIR + "/") and f.endswith(".jsonl")]


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--all", action="store_true",
                   help="audit every governance.d fragment (always report-only, exit 0)")
    g.add_argument("--files", nargs="+", metavar="FILE", help="lint exactly these fragments")
    ap.add_argument("--base", default=os.environ.get("GOV_LEDGER_BASE", "origin/dev"),
                    help="base ref for the diff-scoped default (default: origin/dev)")
    ap.add_argument("--github", action="store_true",
                    help="emit ::error:: / ::warning:: GitHub-Actions annotations")
    args = ap.parse_args()

    if args.files:
        targets, audit = args.files, False
    elif args.all:
        targets, audit = sorted(str(p) for p in Path(LEDGER_DIR).glob("*.jsonl")), True
    else:
        try:
            targets = changed_fragments(args.base)
        except subprocess.CalledProcessError as e:
            print(f"::error::check-governance-ledger: git diff against base {args.base!r} failed "
                  f"({e}); refusing to report an empty scope (would under-lint). "
                  f"Pass --files explicitly or fix --base.", file=sys.stderr)
            return 2
        audit = False

    if not targets:
        print("check-governance-ledger: no fragments in scope — nothing to lint")
        return 0

    findings = []
    for t in targets:
        findings.extend(check_fragment(t))

    if not findings:
        print(f"check-governance-ledger: OK — {len(targets)} fragment(s) lint clean")
        return 0

    structural = [f for f in findings if f.tier == "STRUCTURAL"]
    strict = [f for f in findings if f.tier == "STRICT"]
    for group, items in (("STRUCTURAL (schema hygiene)", structural),
                         ("STRICT (reviewer-class self-consistency)", strict)):
        if not items:
            continue
        print(f"\n== {group}: {len(items)} ==")
        for f in items:
            loc = f"{f.path}" + (f" [{f.fid}]" if f.fid else "")
            if args.github:
                sev = "error" if f.tier == "STRUCTURAL" else "warning"
                print(f"::{sev}::check-governance-ledger: {loc}: {f.rule}: {f.msg}")
            else:
                print(f"  {loc}: {f.rule}: {f.msg}")

    print(f"\ncheck-governance-ledger: {len(findings)} finding(s) "
          f"({len(structural)} structural, {len(strict)} strict) "
          f"across {len({f.path for f in findings})} fragment(s)")
    return 0 if audit else 1


if __name__ == "__main__":
    sys.exit(main())
