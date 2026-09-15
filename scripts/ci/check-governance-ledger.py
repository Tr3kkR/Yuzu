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
are NOT project-wide invariants - ~93% of existing ledgers predate them (e.g.
the "severity_mapped == derived band" rule). Wiring these as a required CI
check would break on the corpus and impose a contested standard on every future
run. So this is an ADVISORY tool: the `/governance` skill runs it on the
current run's fragment as a pre-push step, and you can run it by hand. The
schema authority remains `.claude/skills/governance/SKILL.md` (Gate 8 field
table); this script encodes a checkable subset and loses to it on any conflict.

It does NOT judge whether a finding is true, whether a severity is morally
right, or whether a reviewer's grant is genuine - only properties that follow
mechanically from the recorded fields.

USAGE
  check-governance-ledger.py --files governance.d/<frag>.jsonl   # lint one run
  check-governance-ledger.py                                     # diff-scoped: fragments changed vs --base
  check-governance-ledger.py --all                               # audit whole corpus (always report-only)

Findings are grouped STRUCTURAL (schema hygiene) and STRICT (the reviewer-class
self-consistency rules). Exit is nonzero when a targeted fragment has any
finding (so a pre-push step surfaces it); `--all` always exits 0.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

LEDGER_DIR = "governance.d"

IMPACTS = {f"I{i}" for i in range(1, 10)}
EXPOSURES = {f"E{i}" for i in range(0, 7)} | {"unresolved"}
MAPPED = {"BLOCKING", "SHOULD", "NICE"}
SOURCES = {"governance-agent", "collaborator", "external-model"}

_BASE = {"I1": "HIGH", "I2": "HIGH", "I3": "HIGH", "I4": "HIGH",
         "I5": "MEDIUM", "I6": "MEDIUM", "I7": "MEDIUM",
         "I8": "LOW", "I9": "INFO"}
_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def derived_band(impact, exposure):
    ic = [i for i in impact if i in _BASE]
    if not ic:
        return "INFO"
    idx = max(_ORDER.index(_BASE[i]) for i in ic)
    if any(e in ("E1", "E2") for e in exposure):
        idx = min(idx + 1, len(_ORDER) - 1)
    if "E6" in exposure:
        idx = min(idx, 1)
    return _ORDER[idx]


def mapped_of(band):
    if band in ("HIGH", "CRITICAL"):
        return "BLOCKING"
    if band == "MEDIUM":
        return "SHOULD"
    return "NICE"


class Finding:
    __slots__ = ("path", "fid", "tier", "rule", "msg")

    def __init__(self, path, fid, tier, rule, msg):
        self.path, self.fid, self.tier, self.rule, self.msg = path, fid, tier, rule, msg


def _scalar_in(value, allowed):
    """membership test that is safe when a corpus field holds an unhashable."""
    try:
        return value in allowed
    except TypeError:
        return False


def check_fragment(path):
    out = []

    def add(fid, tier, rule, msg):
        out.append(Finding(path, fid, tier, rule, msg))

    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as e:
        add("", "STRUCTURAL", "unreadable", str(e))
        return out

    rows = []
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
    first, live, live_line = {}, {}, {}
    for n, r in rows:
        fid = r.get("finding_id")
        if isinstance(fid, str):
            first.setdefault(fid, r)
            live[fid] = r
            live_line[fid] = n
        else:
            add("", "STRUCTURAL", "missing-field", f"line {n}: finding_id absent or not a string")

    # The ledger is append-only / supersede-never-edit: an earlier row is
    # FROZEN history that a later same-id row corrects, and cannot itself be
    # rewritten. So schema + self-consistency checks run on the LIVE VIEW (the
    # last row per finding_id) - the current state of each finding - not on
    # superseded rows. (JSON validity above is the one inherently per-row check.)
    for fid in live:
        r = live[fid]
        n = live_line[fid]
        for req in ("schema_version", "run_id", "finding_id", "source",
                    "impact", "exposure", "severity_mapped", "disposition"):
            if req not in r:
                add(fid, "STRUCTURAL", "missing-field", f"line {n}: field '{req}' absent")
        if "policy_floor" not in r:
            add(fid, "STRUCTURAL", "missing-field",
                f"line {n}: 'policy_floor' key absent (write null, do not omit)")
        if "run_id" in r and r.get("run_id") != expected_run:
            add(fid, "STRUCTURAL", "run-id-mismatch",
                f"line {n}: run_id {r.get('run_id')!r} != filename stem {expected_run!r}")
        if "source" in r and not _scalar_in(r.get("source"), SOURCES):
            add(fid, "STRUCTURAL", "bad-source",
                f"line {n}: source {r.get('source')!r} not one of {sorted(SOURCES)}")
        if r.get("source") and r.get("source") != "governance-agent" and not r.get("reporter_ref"):
            add(fid, "STRUCTURAL", "missing-reporter-ref",
                f"line {n}: non-governance-agent row needs reporter_ref (or 'unresolved')")
        for i in _as_list(r.get("impact")):
            if not _scalar_in(i, IMPACTS):
                add(fid, "STRUCTURAL", "bad-impact", f"line {n}: impact {i!r}")
        for e in _as_list(r.get("exposure")):
            if not _scalar_in(e, EXPOSURES):
                add(fid, "STRUCTURAL", "bad-exposure", f"line {n}: exposure {e!r}")
        if "severity_mapped" in r and not _scalar_in(r.get("severity_mapped"), MAPPED):
            add(fid, "STRUCTURAL", "bad-severity-mapped",
                f"line {n}: severity_mapped {r.get('severity_mapped')!r}")
        rep = r.get("reporter")
        if isinstance(rep, str) and re.search(r"\s\+\s|,| and ", rep):
            add(fid, "STRUCTURAL", "joined-reporter",
                f"line {n}: reporter must be a single value, got {rep!r}")
        ir = r.get("independent_reporters")
        if ir is not None and not isinstance(ir, int):
            add(fid, "STRUCTURAL", "bad-independent-reporters",
                f"line {n}: independent_reporters must be an integer, got {ir!r}")
        if bool(r.get("adjudicated_by")) != bool(r.get("adjudication_rationale")):
            add(fid, "STRUCTURAL", "adjudication-pairing",
                f"line {n}: adjudicated_by and adjudication_rationale must be set together")

    # ---- STRICT: reviewer-class self-consistency, live view ----
    for fid, r in live.items():
        impact = [i for i in _as_list(r.get("impact")) if _scalar_in(i, IMPACTS)]
        exposure = [e for e in _as_list(r.get("exposure")) if _scalar_in(e, EXPOSURES)]
        mapped = r.get("severity_mapped")
        want = mapped_of(derived_band(impact, exposure))
        if _scalar_in(mapped, MAPPED) and impact and mapped != want:
            add(fid, "STRICT", "severity-not-derived",
                f"severity_mapped {mapped!r} != derived band {want} "
                f"(impact={impact} exposure={exposure}); the derived band goes in "
                f"severity_mapped and a floor gates separately via policy_floor")
        if r.get("classification") == "wording" and "I7" in impact:
            add(fid, "STRICT", "wording-carries-i7",
                "classification 'wording' cannot carry I7 (standing rule 3 caps wording-only at NICE)")
        if r.get("severity_native") != first[fid].get("severity_native"):
            add(fid, "STRICT", "native-mutated",
                f"severity_native changed across supersession "
                f"({first[fid].get('severity_native')!r} -> {r.get('severity_native')!r}); "
                f"it is the reporter's own word, frozen at first record")
        if r.get("reviewed_at_sha") != first[fid].get("reviewed_at_sha"):
            add(fid, "STRICT", "reviewed-sha-mutated",
                f"reviewed_at_sha changed across supersession "
                f"({first[fid].get('reviewed_at_sha')!r} -> {r.get('reviewed_at_sha')!r}); "
                f"it is the head the reporter actually read")
        ir = r.get("independent_reporters")
        if isinstance(ir, int) and ir > 1 and r.get("source") == "external-model":
            add(fid, "STRICT", "inflated-independent-reporters",
                f"independent_reporters={ir} on an external-model row "
                f"(a reviewer echoing an existing ledger row is not an independent discovery)")
    return out


def changed_fragments(base):
    try:
        mb = subprocess.run(["git", "merge-base", base, "HEAD"],
                            capture_output=True, text=True, check=True).stdout.strip()
    except subprocess.CalledProcessError:
        mb = base
    try:
        names = subprocess.run(["git", "diff", "--name-only", "--diff-filter=d", f"{mb}...HEAD"],
                               capture_output=True, text=True, check=True).stdout.splitlines()
    except subprocess.CalledProcessError:
        return []
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
        targets, audit = changed_fragments(args.base), False

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
            line = f"  {loc}: {f.rule}: {f.msg}"
            if args.github:
                sev = "error" if f.tier == "STRUCTURAL" else "warning"
                print(f"::{sev}::check-governance-ledger: {loc}: {f.rule}: {f.msg}")
            else:
                print(line)

    print(f"\ncheck-governance-ledger: {len(findings)} finding(s) "
          f"({len(structural)} structural, {len(strict)} strict) "
          f"across {len({f.path for f in findings})} fragment(s)")
    if audit:
        return 0  # --all is always report-only
    return 1


if __name__ == "__main__":
    sys.exit(main())
