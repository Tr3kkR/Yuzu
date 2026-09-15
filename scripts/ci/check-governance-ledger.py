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
`finding_id`, ordered by `recorded_at` (a row with no `recorded_at` predates
#2619 and sorts BEFORE timestamped rows, in file order; ties break on higher
`pass_ordinal`). A superseding row restates ONLY what changed (a sparse `fixed`
row is the prescribed shape), list fields (`impact`/`exposure`) REPLACE
wholesale, and the five ATTESTATION fields (`adjudicated_by`,
`adjudication_rationale`, `refuted_by`, `refuted_by_reporter`,
`waiver_rationale`) are ROW-SCOPED and EXEMPT from the merge - they attach to
the row that performed the act, never inherited and never cleared forward. So
finding-level checks run on the MERGE, while attestation pairing and the one
frozen field (`severity_native`) are checked PER ROW (an intermediate violation
a later row incidentally restores must still be caught). `reviewed_at_sha` is
NOT treated as immutable - correcting it across a supersession is legitimate.

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

# base band per impact code (SKILL.md "IMPACT - gives the base band")
_BASE = {"I1": "HIGH", "I2": "HIGH", "I3": "HIGH", "I4": "HIGH",
         "I5": "MEDIUM", "I6": "MEDIUM", "I7": "MEDIUM",
         "I8": "LOW", "I9": "INFO"}
_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
# impacts whose band is explicitly capped at HIGH regardless of exposure raises
_HIGH_CAPPED = frozenset({"I4", "I7"})


def _as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def min_derived_band(impact, exposure):
    """The FLOOR of the finding's band from the recorded facts alone.

    Only the mechanical parts of the derivation are modelled: base band, the
    E1/E2 single raise, the E6 LOW cap, and the I4/I7 HIGH cap. The CONDITIONAL
    raises SKILL.md defines (I5(a)-(c), I6 FALSE-ASSURANCE / DORMANT-AUTH,
    I7-conceals) can only push the true band HIGHER and cannot be evaluated from
    the fields, so this is a lower bound, not the exact band. Used only to catch
    UNDER-grading (a label that cannot even reach this floor); over-labeling is
    left alone because it is indistinguishable from a legitimate conditional
    raise.
    """
    codes = [i for i in impact if i in _BASE]
    if not codes:
        return "INFO"
    idx = max(_ORDER.index(_BASE[c]) for c in codes)
    if any(e in ("E1", "E2") for e in exposure):
        idx = min(idx + 1, len(_ORDER) - 1)
    if any(c in _HIGH_CAPPED for c in codes):
        idx = min(idx, _ORDER.index("HIGH"))
    if "E6" in exposure:
        idx = min(idx, _ORDER.index("LOW"))
    return _ORDER[idx]


_UNSET = object()
_LABEL_CEILING = {"BLOCKING": "CRITICAL", "SHOULD": "MEDIUM", "NICE": "LOW"}


class Finding:
    __slots__ = ("path", "fid", "tier", "rule", "msg")

    def __init__(self, path, fid, tier, rule, msg):
        self.path, self.fid, self.tier, self.rule, self.msg = path, fid, tier, rule, msg


def _in(value, allowed):
    try:
        return value in allowed
    except TypeError:
        return False


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
    po = r.get("pass_ordinal") if isinstance(r.get("pass_ordinal"), int) else 0
    if inst is not None:
        return (1, inst, po, idx)          # timestamped: by instant, then pass_ordinal, then file order
    return (0, _MIN_INSTANT, 0, idx)       # no recorded_at (pre-#2619): sorts first, in file order


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
        legacy = "schema_version" not in merged  # pre-#2619 finding

        # ---------- PER-ROW checks (attestation + the frozen field) ----------
        # These run per ROW, not first-vs-live, so an intermediate violation a
        # later row incidentally restores is still caught (the append-only ledger
        # permanently contains the act). NOTE: only severity_native is checked as
        # immutable - SKILL.md explicitly freezes it ("the REPORTER's own word,
        # unmodified"). reviewed_at_sha is deliberately NOT treated as immutable:
        # its field definition is "the head the reporter read", and correcting it
        # across a supersession is legitimate (e.g. superseding an early row whose
        # pre-rebase SHA no longer resolves - the prescribed fix, not a defect).
        native_seen = _UNSET
        for _, r in ordered:
            ln = line_of[id(r)]
            # attestation pairing is a property of the ROW that performed the act
            if bool(r.get("adjudicated_by")) != bool(r.get("adjudication_rationale")):
                add(fid, "STRICT", "adjudication-pairing",
                    f"line {ln}: adjudicated_by and adjudication_rationale must be set together on the same row")
            # severity_native is the reporter's own word, frozen. A sparse row may
            # OMIT the key (no change), but a row that PRESENTS the key with a
            # different value - including flipping to/from null, which invents or
            # erases a band the reporter did or did not give - is a mutation.
            if "severity_native" in r:
                val = r.get("severity_native")
                if native_seen is _UNSET:
                    native_seen = val
                elif val != native_seen:
                    add(fid, "STRICT", "native-mutated",
                        f"line {ln}: severity_native set to {val!r}, "
                        f"differs from earlier {native_seen!r} (reporter's own word, immutable)")
            # scalar impact/exposure - the shape the jq park probe's array check exists to catch
            for lf in LIST_FIELDS:
                if lf in r and not isinstance(r[lf], list):
                    add(fid, "STRUCTURAL", "scalar-list-field",
                        f"line {ln}: {lf} must be a JSON array, got {r[lf]!r}")

        first_line = line_of[id(ordered[0][1])]

        # ---------- STRUCTURAL: schema hygiene on the merged view ----------
        if not legacy:
            for req in ("schema_version", "run_id", "finding_id", "source",
                        "impact", "exposure", "severity_mapped", "disposition"):
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
        # reporter: exactly one value. absent, list-valued, or joined all fail.
        if not legacy:
            rep = merged.get("reporter")
            if rep is None:
                add(fid, "STRUCTURAL", "missing-reporter", "reporter absent (needs exactly one value)")
            elif isinstance(rep, list):
                add(fid, "STRUCTURAL", "list-reporter", f"reporter must be one value, got a list {rep!r}")
            elif isinstance(rep, str) and re.search(r"[+,]| and ", rep):
                add(fid, "STRUCTURAL", "joined-reporter", f"reporter must be one value, got {rep!r}")
        ir = merged.get("independent_reporters")
        if ir is not None and not isinstance(ir, int):
            add(fid, "STRUCTURAL", "bad-independent-reporters",
                f"independent_reporters must be an integer, got {ir!r}")

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
            # raise applies to no facts); a non-NICE label with no floor to
            # justify gating is a definite disagreement.
            if not impact and not raw_impact_present and mapped != "NICE" and not merged.get("policy_floor"):
                add(fid, "STRICT", "severity-empty-impact",
                    f"severity_mapped {mapped!r} with empty impact and no policy_floor "
                    f"(empty facts derive INFO -> NICE; a floor would gate separately)")
        if merged.get("classification") == "wording" and "I7" in impact:
            add(fid, "STRICT", "wording-carries-i7",
                "classification 'wording' cannot carry I7 (standing rule 3 caps wording-only at NICE)")
        # Gate-7 park constraint (mirrors the SKILL.md jq probe): an I1/I2/I3
        # finding may not be parked. roadmap-* is a hard violation; linked-to-*
        # over-matches (a valid ending if the target issue is itself parked), so
        # it is a prompt to verify the target's labels, not an assertion.
        disp = merged.get("disposition")
        top = {"I1", "I2", "I3"} & set(impact)
        if isinstance(disp, str) and top:
            if disp.startswith("roadmap"):
                add(fid, "STRICT", "parked-top-severity",
                    f"disposition {disp!r} parks an {sorted(top)} finding (Gate-7 constraint 1 bars this)")
            elif disp.startswith("linked-to"):
                add(fid, "STRICT", "linked-top-severity",
                    f"disposition {disp!r} links an {sorted(top)} finding to an existing issue - "
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
