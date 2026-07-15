#!/usr/bin/env python3
"""apply_decisions.py -- the ONLY mutating layer of the tracker sweep (ADR-3001 A1 §10).

Operator-run, under the OPERATOR's credentials (never a workflow token), and
FAIL-CLOSED: on any uncertainty it refuses the whole batch with zero mutations.
It is the deliberate inverse of the PreToolUse hooks -- those fail OPEN so they
never block a human; this fails CLOSED so it never closes the wrong issue.

There is NO autonomous tier and none is coming (A1 §10): once close-on-merge is
live, an issue that satisfies a claiming-PR probe yet stays open is one the
PRIMARY automation FAILED on -- closing it here would repair the symptom and
destroy the evidence. Every close is a typed human decision produced by the
`/issue-triage` skill and applied here.

Flow:
  1. `/issue-triage` reads the latest tracker-report comment on the
     `triage-sweep` issue, presents the flagged candidates, and writes a
     decisions file: {report_hash, decisions: [{number, category, reason,
     verified_gone_at?, duplicate_of?}]}.
  2. `apply_decisions.py --decisions FILE --snapshot SNAP`  (dry-run, DEFAULT)
     -- validates every fail-closed rule against LIVE issue state, prints the
     diff most-dangerous-first, and writes SNAP (the reviewed identity).
  3. `apply_decisions.py --decisions FILE --snapshot SNAP --execute`
     -- refuses unless SNAP exists and its decisions-hash still matches the
     file (no execute without a matching prior dry-run; edits after review are
     the known attack shape). Posts a per-run LEDGER comment to the tracking
     issue BEFORE any close, then closes each issue (state change first, then
     the evidence comment carrying the idempotency marker).
  4. `apply_decisions.py --revert RUN_ID`  -- reopens exactly the batch a ledger
     records, verified by this tool's own trusted close marker.

Fail-closed refusals (each a selftest in tests/test_tracker.py; ALL abort the
whole run with zero mutations, exit 4 unless noted):
  R0  decisions file unreadable / wrong schema ................ exit 3
  R0b do-not-close.txt missing or unparseable ................. exit 3
  R1  > DECISION_CAP decisions, or a repeated issue number
  R2  a decision targets a committed never-close issue
      (in do-not-close.txt OR carrying the do-not-close label)
  R3  a security/P0/P1 issue without a well-formed
      `verified_gone_at` (a real sha + what was grepped), or in
      any category other than fixed-elsewhere, or > HIGHRISK_CAP such closes
  R4  a roadmap issue in a judgment category (roadmap is
      eligible for fixed-elsewhere only -- A1 §6)
  R5  a decision target that is assigned or has an open linked
      PR (issue-standard.md §5.1 never-close union)
  R6  a decision target already closed (a stale batch), OR any
      do-not-close.txt issue found already closed (a guardrail
      breach -- refuse and shout)
  R7  the decisions' report_hash != the live latest report's
      hash (decisions made against a stale report)
  --execute without a matching --snapshot ......... exit 2 (missing) / 4 (drift)

GitHub access reuses close_linked_issues.gh_api (the `gh` CLI; never raw curl).
Stdlib only. Run as `python` on Windows dev boxes (python3 is the Store stub).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import close_linked_issues as cli   # noqa: E402  (gh_api, load_do_not_close, markers, plumbing)
import tracker_report as report     # noqa: E402  (the report subsystem: hash + tracking issue)

REPO = cli.REPO
TARGET_BRANCH = cli.TARGET_BRANCH

DECISION_CAP = 10   # A1 §10: 10 operator decisions per run, no carry-over
HIGHRISK_CAP = 3    # A1 §10: at most 3 security/P0/P1 closes per run, each typed

# category -> GitHub state_reason. fixed-elsewhere is the ONLY category eligible
# for a security/P0/P1 issue and the ONLY one allowed on a roadmap issue.
CATEGORY_STATE = {
    "fixed-elsewhere": "completed",
    "obsolete": "not_planned",
    "too-trivial": "not_planned",
    "duplicate": "not_planned",
}
JUDGMENT_CATEGORIES = {"obsolete", "too-trivial", "duplicate"}  # never on roadmap
HIGHRISK_LABELS = {"security", "P0", "P1"}

DECISION_MARKER = "yuzu-tracker-decision: run={run} issue={issue}"
LEDGER_MARKER = "yuzu-tracker-ledger: run={run}"

# A typed verification line: a real commit-ish sha (7-40 hex) then a dash/colon
# then a non-empty "what I grepped". A checkbox does not satisfy this.
_VERIFIED_RE = re.compile(r"^\s*([0-9a-fA-F]{7,40})\s*[-—:]\s*(\S.*\S|\S)\s*$")


class DecisionsError(cli.GhError):
    """A structural problem with the decisions file -> exit 3 (fail-closed)."""


# ---------------------------------------------------------------------------
# Load + schema (structural failures are exit 3)

def load_decisions(path: str) -> dict:
    p = pathlib.Path(path)
    if not p.exists():
        raise DecisionsError(f"decisions file {path} does not exist -- fail-closed")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (ValueError, OSError) as e:
        raise DecisionsError(f"decisions file {path} is not readable JSON ({e}) -- fail-closed")
    if not isinstance(data, dict):
        raise DecisionsError("decisions file must be a JSON object -- fail-closed")
    if not isinstance(data.get("report_hash"), str) or not data["report_hash"]:
        raise DecisionsError("decisions file missing a string 'report_hash' -- fail-closed")
    decisions = data.get("decisions")
    if not isinstance(decisions, list):
        raise DecisionsError("decisions file missing a 'decisions' list -- fail-closed")
    for i, d in enumerate(decisions):
        if not isinstance(d, dict):
            raise DecisionsError(f"decision[{i}] is not an object -- fail-closed")
        if not isinstance(d.get("number"), int) or isinstance(d.get("number"), bool) or d["number"] <= 0:
            raise DecisionsError(f"decision[{i}] needs a positive integer 'number' -- fail-closed")
        if not isinstance(d.get("category"), str) or not d["category"]:
            raise DecisionsError(f"decision[{i}] (#{d.get('number')}) needs a string 'category' -- fail-closed")
        if not isinstance(d.get("reason"), str) or not d["reason"].strip():
            raise DecisionsError(f"decision[{i}] (#{d.get('number')}) needs a non-empty 'reason' -- fail-closed")
        if "verified_gone_at" in d and not isinstance(d["verified_gone_at"], str):
            raise DecisionsError(f"decision[{i}] 'verified_gone_at' must be a string -- fail-closed")
        if "duplicate_of" in d and (not isinstance(d["duplicate_of"], int) or isinstance(d["duplicate_of"], bool)):
            raise DecisionsError(f"decision[{i}] 'duplicate_of' must be an integer -- fail-closed")
    return data


def canonical_decisions(data: dict) -> str:
    """The reviewable identity of a decision list: sorted, whitespace-free JSON
    over the fields that change what executes (report_hash is included so a
    decision list re-pointed at a different report is a different identity)."""
    rows = sorted(
        [d["number"], d["category"],
         d["reason"].strip(),
         (d.get("verified_gone_at") or "").strip(),
         d.get("duplicate_of") or 0]
        for d in data["decisions"]
    )
    return json.dumps({"report_hash": data["report_hash"], "rows": rows},
                      sort_keys=True, separators=(",", ":"))


def decisions_hash(data: dict) -> str:
    return hashlib.sha256(canonical_decisions(data).encode("utf-8")).hexdigest()


def valid_verification(text: str) -> bool:
    return bool(_VERIFIED_RE.match(text or ""))


# ---------------------------------------------------------------------------
# Live-state fetch (read-only, before any mutation)

def fetch_live(numbers) -> dict:
    """{n: issue_json_or_None} for every issue number given."""
    live = {}
    for n in sorted(set(numbers)):
        live[n] = cli.gh_api(f"repos/{REPO}/issues/{n}")
    return live


def has_open_linked_pr(n: int) -> bool:
    return cli.has_open_linked_pr(n)


# ---------------------------------------------------------------------------
# Validation -- returns a list of refusal strings (empty == may proceed).
# Every entry aborts the whole run (exit 4). Pure given (data, dnc, live,
# linked_pr, report_hash_live), so it is fully unit-testable without network.

def validate(data: dict, dnc: set, live: dict, linked_pr: dict,
             report_hash_live) -> list:
    refusals = []
    decisions = data["decisions"]

    # R1 -- cap + no repeats
    if len(decisions) > DECISION_CAP:
        refusals.append(f"R1: {len(decisions)} decisions exceed the per-run cap of {DECISION_CAP} "
                        f"(no carry-over -- split across runs).")
    seen = {}
    for d in decisions:
        seen[d["number"]] = seen.get(d["number"], 0) + 1
    for n, c in seen.items():
        if c > 1:
            refusals.append(f"R1: issue #{n} appears {c} times -- one decision per issue.")

    highrisk = 0
    for d in decisions:
        n, cat = d["number"], d["category"]
        issue = live.get(n)
        labels = report._labels(issue) if issue else set()

        # category must be a known closing category
        if cat not in CATEGORY_STATE:
            refusals.append(f"#{n}: unknown category {cat!r} (want one of {sorted(CATEGORY_STATE)}).")
            continue

        # R6a -- stale batch: the target must exist and still be open
        if issue is None:
            refusals.append(f"R6: #{n} not found (404) -- a stale batch; re-run the report and re-triage.")
            continue
        # R2b -- a PR is not an issue. The REST issues endpoint returns PRs too,
        # so a PR number in the decisions would otherwise reach the close PATCH.
        # Mirror close_linked_issues.classify()'s "reference is a PR" skip.
        if "pull_request" in issue:
            refusals.append(f"R2: #{n} is a pull request, not an issue -- the sweep never closes PRs.")
            continue
        if issue.get("state") != "open":
            refusals.append(f"R6: #{n} is already {issue.get('state')} -- a stale batch; re-triage.")

        # R2 -- committed never-close set (file OR label): refuse the whole run
        if n in dnc:
            refusals.append(f"R2: #{n} is in do-not-close.txt -- the held-open set is never sweep-closed.")
        if report.DO_NOT_CLOSE_LABEL in labels:
            refusals.append(f"R2: #{n} carries the do-not-close label -- never sweep-closed.")

        # R5 -- never-close union: assigned / open linked PR (issue-standard §5.1)
        if issue.get("assignees"):
            refusals.append(f"R5: #{n} is assigned -- a human owns it; not sweep-closed.")
        if linked_pr.get(n):
            refusals.append(f"R5: #{n} has an open linked PR -- resolve or unlink it first.")

        # R3 -- security/P0/P1 gate
        if labels & HIGHRISK_LABELS:
            highrisk += 1
            if cat != "fixed-elsewhere":
                refusals.append(f"R3: #{n} is {sorted(labels & HIGHRISK_LABELS)} -- a high-risk issue "
                                f"may only be closed as 'fixed-elsewhere' with typed verification, not {cat!r}.")
            if not valid_verification(d.get("verified_gone_at", "")):
                refusals.append(f"R3: #{n} is {sorted(labels & HIGHRISK_LABELS)} and needs a typed "
                                f"'verified_gone_at' (<sha> — what you grepped), not a checkbox.")

        # R4 -- roadmap is fixed-elsewhere-only
        if report.ROADMAP_LABEL in labels and cat in JUDGMENT_CATEGORIES:
            refusals.append(f"R4: #{n} is roadmap -- eligible for 'fixed-elsewhere' only, not {cat!r}.")

        # duplicate needs a survivor pointer
        if cat == "duplicate":
            dup = d.get("duplicate_of")
            if not isinstance(dup, int) or dup <= 0 or dup == n:
                refusals.append(f"#{n}: category 'duplicate' needs a positive 'duplicate_of' != {n}.")

    if highrisk > HIGHRISK_CAP:
        refusals.append(f"R3: {highrisk} security/P0/P1 closes exceed the per-run cap of {HIGHRISK_CAP}.")

    # R6b -- guardrail-breach sentinel: no do-not-close.txt issue may be closed
    for n in sorted(dnc):
        issue = live.get(n)
        if issue is not None and issue.get("state") != "open":
            refusals.append(f"R6: GUARDRAIL BREACH -- held-open #{n} (do-not-close.txt) is "
                            f"{issue.get('state')}. Refusing to run until this is investigated.")

    # R7 -- decisions must be applied against the report they were made from
    if report_hash_live is None:
        refusals.append("R7: no tracker-report comment found on the triage-sweep issue -- "
                        "nothing to validate the decisions against.")
    elif data["report_hash"] != report_hash_live:
        refusals.append(f"R7: report_hash mismatch -- decisions were made against {data['report_hash'][:12]}… "
                        f"but the live report is {report_hash_live[:12]}…. A newer report exists; re-triage.")
    return refusals


# ---------------------------------------------------------------------------
# Mutation (only after validate() returned empty)

def _close(n: int, state_reason: str, execute: bool):
    if not execute:
        return
    cli.gh_api(f"repos/{REPO}/issues/{n}", "-f", "state=closed", "-f", f"state_reason={state_reason}",
               method="PATCH")
    time.sleep(cli.MUTATION_SLEEP_S)


def _no_comment_delims(text: str) -> str:
    """Neutralize HTML-comment delimiters in operator-authored text so it cannot
    disturb the idempotency marker's own <!-- --> below. Defense-in-depth: the
    marker is matched by substring so this is hygiene, not a security boundary."""
    return (text or "").replace("<!--", "<! --").replace("-->", "-- >")


def decision_comment(d: dict, run_id: str) -> str:
    cat = d["category"]
    state = CATEGORY_STATE[cat]
    extra = ""
    if cat == "duplicate":
        extra = f" Duplicate of #{d['duplicate_of']}."
    ver = d.get("verified_gone_at")
    if ver:
        extra += f" Verified gone at `{_no_comment_delims(ver.strip())}`."
    return (
        f"Closed as `{state}` by the tracker sweep ({cli.run_context()}): "
        f"operator decision — **{cat}**. {_no_comment_delims(d['reason'].strip())}{extra}\n\n"
        f"Performed under the operator's credentials from a reviewed decision list. "
        f"Wrong close? Reopen and add the `do-not-close` label "
        f"(docs/agents/issue-standard.md §5.1), or run "
        f"`apply_decisions.py --revert {run_id}` to reverse this whole batch.\n\n"
        f"<!-- {DECISION_MARKER.format(run=run_id, issue=d['number'])} -->"
    )


def ledger_comment(data: dict, run_id: str) -> str:
    lines = []
    for d in sorted(data["decisions"], key=lambda x: x["number"]):
        lines.append(f"- #{d['number']} — {d['category']} → {CATEGORY_STATE[d['category']]}")
    return (
        f"### Tracker decision ledger — run `{run_id}`\n\n"
        f"{cli.run_context()} · report `{data['report_hash'][:12]}…` · "
        f"{len(data['decisions'])} issue(s).\n\n"
        f"{chr(10).join(lines)}\n\n"
        f"This ledger is posted BEFORE any close. "
        f"`apply_decisions.py --revert {run_id}` reverses exactly this batch "
        f"(each reopen is verified by this run's own close marker).\n\n"
        f"<!-- {LEDGER_MARKER.format(run=run_id)} -->"
    )


def post_ledger(data: dict, run_id: str, execute: bool):
    """Post the ledger to the triage-sweep tracking issue before any close."""
    issue = report.find_tracking_issue()
    if issue is None:
        raise cli.GhError(f"no open issue labelled '{report.TRIAGE_SWEEP_LABEL}' to post the ledger to -- "
                          f"fail-closed (the ledger is the reversible record; run bootstrap-labels.sh "
                          f"and open the tracking issue first).")
    body = ledger_comment(data, run_id)
    if execute:
        cli.gh_api(f"repos/{REPO}/issues/{issue['number']}/comments", "-f", f"body={body}", method="POST")
        time.sleep(cli.MUTATION_SLEEP_S)
    return issue["number"]


def _live_close_block(d: dict, dnc: set) -> "str | None":
    """Re-fetch the issue immediately before closing it and return a refusal
    reason if a never-close signal is now present, else None. The last line of
    defense against a validate-to-PATCH race (a label/assignment/linked-PR added
    after the pre-mutation revalidation). Preserves the security exception: a
    now-`security` issue is still closeable iff it is a verified fixed-elsewhere."""
    n = d["number"]
    issue = cli.gh_api(f"repos/{REPO}/issues/{n}")
    if issue is None:
        return "not found (404)"
    if "pull_request" in issue:
        return "is a pull request"
    if issue.get("state") != "open":
        return f"already {issue.get('state')}"
    labels = report._labels(issue)
    if n in dnc:
        return "in do-not-close.txt"
    if report.DO_NOT_CLOSE_LABEL in labels:
        return "carries the do-not-close label"
    if issue.get("assignees"):
        return "is assigned"
    if cli.has_open_linked_pr(n):
        return "has an open linked PR"
    if (labels & HIGHRISK_LABELS) and not (
            d["category"] == "fixed-elsewhere" and valid_verification(d.get("verified_gone_at", ""))):
        return f"is now {sorted(labels & HIGHRISK_LABELS)} without a verified fixed-elsewhere decision"
    return None


def apply_decisions(data: dict, run_id: str, execute: bool, dnc: set):
    """The one mutating loop. Ledger first, then per-issue: a final live re-check
    (validate-to-PATCH TOCTOU), state change, then the evidence comment (marker).
    Mirrors close_linked_issues.apply_plan -- comment-first would plant the
    marker on a still-open issue if the close failed, blinding --revert and the
    leak scan at once."""
    ledger_issue = post_ledger(data, run_id, execute)
    print(f"{'posted' if execute else '[dry-run] would post'} ledger for run {run_id} "
          f"to tracking issue #{ledger_issue}")
    closed = 0
    for d in sorted(data["decisions"], key=lambda x: x["number"]):
        n, state = d["number"], CATEGORY_STATE[d["category"]]
        if execute:
            block = _live_close_block(d, dnc)
            if block:
                print(f"ABORT before closing #{n}: it {block} since the reviewed dry-run. "
                      f"Zero further closes; re-run the dry-run and re-triage.", file=sys.stderr)
                sys.exit(4)
        _close(n, state, execute)
        if execute:
            print(f"  closed #{n} as {state} ({d['category']})", flush=True)
        else:
            print(f"  [dry-run] would close #{n} as {state} ({d['category']})")
        cli.post_comment(n, decision_comment(d, run_id), execute)
        if execute:
            print(f"  evidence comment posted on #{n}", flush=True)
        closed += 1
    mode = "EXECUTED" if execute else "DRY-RUN (nothing mutated)"
    print(f"{mode}: {closed} issue(s) {'closed' if execute else 'would close'} (run {run_id})")


def print_plan(data: dict, live: dict):
    """Dry-run diff, most-dangerous-first (security/P0/P1/assigned first)."""
    def danger(d):
        labels = report._labels(live.get(d["number"]))
        return (-(bool(labels & HIGHRISK_LABELS)), -bool((live.get(d["number"]) or {}).get("assignees")),
                d["number"])
    for d in sorted(data["decisions"], key=danger):
        n = d["number"]
        labels = ",".join(sorted(report._labels(live.get(n)))) or "-"
        title = (live.get(n) or {}).get("title", "?")[:60]
        state = CATEGORY_STATE[d["category"]]
        print(f"  CLOSE #{n:<5} as {state:11} [{labels}] {title!r} — {d['category']}: {d['reason'].strip()[:80]}")


# ---------------------------------------------------------------------------
# Modes

def fetch_and_validate(data: dict, dnc: set) -> tuple:
    """Fetch LIVE issue state for every target (+ the do-not-close set) and run
    the full fail-closed validation against it. Returns (refusals, live).
    Called once for the dry-run plan AND again on fresh state immediately before
    any mutation (the validate-to-close TOCTOU guard)."""
    numbers = {d["number"] for d in data["decisions"]} | set(dnc)
    live = fetch_live(numbers)
    linked_pr = {}
    for d in data["decisions"]:
        n = d["number"]
        issue = live.get(n)
        # only the network-cheap path when the issue is present and open
        linked_pr[n] = has_open_linked_pr(n) if issue is not None and issue.get("state") == "open" else False
    report_hash_live = report.latest_report_hash()
    return validate(data, dnc, live, linked_pr, report_hash_live), live


def _print_refusals(refusals: list, header: str):
    print(f"{header} ({len(refusals)} fail-closed violation(s), zero mutations):", file=sys.stderr)
    for r in refusals:
        print(f"  ::error::{r}", file=sys.stderr)


def mode_apply(decisions_file: str, snapshot_file: str, execute: bool) -> int:
    data = load_decisions(decisions_file)          # exit 3 on schema/read failure
    dnc = cli.load_do_not_close()                  # exit 3 if the list is missing

    refusals, live = fetch_and_validate(data, dnc)
    if refusals:
        _print_refusals(refusals, "REFUSED")
        return 4

    run_id = decisions_hash(data)[:12]
    print(f"decision run id: {run_id} ({len(data['decisions'])} issue(s))")
    print_plan(data, live)

    if execute:
        if not snapshot_file or not pathlib.Path(snapshot_file).exists():
            print("--execute requires --snapshot FILE from a prior dry-run "
                  "(no execute without a reviewed dry-run).", file=sys.stderr)
            return 2
        try:
            snap = json.loads(pathlib.Path(snapshot_file).read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            print(f"FATAL: --snapshot {snapshot_file} is unreadable / not JSON ({e}) -- cannot "
                  f"confirm it matches the reviewed dry-run. Zero mutations.", file=sys.stderr)
            return 4
        if not isinstance(snap, dict) or snap.get("decisions_hash") != decisions_hash(data):
            print("FATAL: the decisions file changed since the reviewed dry-run "
                  "(decisions_hash drift). Zero mutations. Re-run the dry-run, re-review, "
                  "re-execute.", file=sys.stderr)
            return 4
        # TOCTOU guard: re-fetch LIVE state and re-validate immediately before any
        # mutation. A never-close signal (do-not-close/security/assign/linked-PR)
        # added AFTER the reviewed dry-run must abort the batch, zero mutations.
        refusals2, live = fetch_and_validate(data, dnc)
        if refusals2:
            _print_refusals(refusals2, "REFUSED (issue state changed since the reviewed dry-run)")
            return 4
    elif snapshot_file:
        pathlib.Path(snapshot_file).write_text(
            json.dumps({"run_id": run_id, "report_hash": data["report_hash"],
                        "decisions_hash": decisions_hash(data), "decisions": data["decisions"]}, indent=1),
            encoding="utf-8")
        print(f"snapshot written to {snapshot_file} (pass the same file to --execute)")

    apply_decisions(data, run_id, execute, dnc)
    return 0


def mode_revert(run_id: str, execute: bool) -> int:
    """Reopen exactly the batch a ledger records. Each reopen is gated on this
    run's OWN trusted close marker on the issue, so a spoofed ledger or a
    hand-closed issue is never touched."""
    cli.load_do_not_close()  # fail-closed applies to revert too
    issue = report.find_tracking_issue()
    if issue is None:
        raise cli.GhError(f"no open '{report.TRIAGE_SWEEP_LABEL}' tracking issue -- cannot locate a ledger")
    comments = cli.gh_api(
        f"repos/{REPO}/issues/{issue['number']}/comments", "-f", "per_page=100", paginate=True,
    ) or []
    ledger = None
    marker = LEDGER_MARKER.format(run=run_id)
    for c in comments:
        login = ((c.get("user") or {}).get("login")) or ""
        assoc = c.get("author_association") or ""
        if login != cli.TRUSTED_BOT and assoc not in cli.TRUSTED_ASSOCIATIONS:
            continue  # a drive-by ledger is not trusted
        if marker in (c.get("body") or ""):
            ledger = c
            break
    if ledger is None:
        raise cli.GhError(f"no trusted ledger comment for run {run_id!r} on #{issue['number']}")

    numbers = [int(m) for m in re.findall(r"^- #(\d+) —", ledger["body"], re.MULTILINE)]
    reopened = 0
    for n in numbers:
        target, blob = cli.issue_with_comments(n)
        if target is None:
            print(f"  #{n}: not found -- skipping")
            continue
        if DECISION_MARKER.format(run=run_id, issue=n) not in blob:
            print(f"  #{n}: no trusted close marker for run {run_id} -- not ours, skipping")
            continue
        if target.get("state") == "open":
            print(f"  #{n}: already open -- skipping")
            continue
        if execute:
            cli.gh_api(f"repos/{REPO}/issues/{n}", "-f", "state=open", method="PATCH")
            time.sleep(cli.MUTATION_SLEEP_S)
            cli.post_comment(n, f"Reopened by `apply_decisions.py --revert {run_id}` "
                                f"({cli.run_context()}).\n\n"
                                f"<!-- yuzu-tracker-revert: run={run_id} issue={n} -->", execute)
            cli.add_label(n, "needs-triage", execute)
        print(f"  {'reopened' if execute else '[dry-run] would reopen'} #{n}")
        reopened += 1
    print(f"revert {run_id}: {reopened} issue(s) {'reopened' if execute else 'would reopen'}")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--decisions", help="the decisions JSON from /issue-triage")
    ap.add_argument("--snapshot", default="", help="dry-run writes the reviewed identity here; "
                                                   "--execute requires the same file and aborts on drift")
    ap.add_argument("--revert", metavar="RUN_ID", help="reopen exactly the batch a ledger records")
    ap.add_argument("--execute", action="store_true", help="mutate (default: dry-run)")
    args = ap.parse_args(argv)

    try:
        if args.revert:
            return mode_revert(args.revert, args.execute)
        if not args.decisions:
            ap.error("one of --decisions or --revert is required")
        return mode_apply(args.decisions, args.snapshot, args.execute)
    except DecisionsError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 3
    except cli.GhError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
