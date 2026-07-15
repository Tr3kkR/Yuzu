#!/usr/bin/env python3
"""close_linked_issues.py -- close issues that merged dev PRs claim (ADR-3001 A1 par.3-5).

The one driver behind every mode of the close automation. All modes share
closing_refs.py (the single parser) and the same decision ladder, so the leak
scan can never disagree with the close path it audits.

Modes (default is ALWAYS --dry-run; nothing mutates without --execute):

  --push BEFORE AFTER     workflow mode: close what the PRs merged by this
                          push range claim. Used by close-linked-issues.yml.
  --backfill              one-time #2139 backfill: sweep ALL merged dev PRs,
                          list still-open claimed issues. --execute
                          additionally requires --yes-i-reviewed (the dry-run
                          diff is reviewed per-issue by the maintainer on
                          #2139 first -- never a count target).
  --undo-push BEFORE AFTER  recompute the closure set for an exact prior push
                          range and reopen what THIS automation closed there
                          (verified by its own idempotency marker).
  --leak-scan             completeness backstop: refs in recently-merged PR
                          bodies that are still open with no marker and no
                          never-close protection. Non-empty => exit 1 (the
                          workflow's alert job fires).

Decision ladder, order load-bearing (issue-standard.md 5.1; A1 par.4-5):
  cap (>6 refs on one PR => close NOTHING for that PR, file a cap-skip issue,
  exit 0) -> self-ref -> not-an-issue/404 -> not-open -> already-marked
  (idempotent) -> `security` label => ADVISORY ONLY -> `do-not-close` label or
  scripts/tracker/do-not-close.txt => ADVISORY ONLY -> assigned => ADVISORY ->
  open linked PR => ADVISORY -> close as completed + evidence comment +
  `fixed-on-dev` (label tolerated missing).

FAIL-CLOSED invariants:
  - scripts/tracker/do-not-close.txt missing or unparseable => the run refuses
    to close ANYTHING (exit 3). A deleted never-close list must never mean
    "nothing is protected". (Also makes this PR safe to merge before/after the
    PR that introduces the file.)
  - defense-in-depth assertion: if, after the ladder, any CLOSE action still
    carries the `security` label, abort the whole run with zero mutations
    (exit 4) -- that state is only reachable through a ladder bug.

GitHub access goes through the `gh` CLI (repo convention -- never raw curl),
authenticated by GH_TOKEN in CI or ambient `gh auth` locally. Mutations are
throttled (MUTATION_SLEEP_S) to stay clear of secondary rate limits.

Stdlib only. Run as `python` on Windows dev boxes (python3 is the Store stub).
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import closing_refs  # noqa: E402  (the single parser -- see module docstring)

REPO = "Tr3kkR/Yuzu"
TARGET_BRANCH = "dev"
PER_PR_CAP = 6  # A1 par.5: observed max on 360 merged dev PRs is 6; >6 is anomalous
MUTATION_SLEEP_S = 2
LEAK_SCAN_WINDOW = 50
DNC_PATH = pathlib.Path(__file__).resolve().parent / "do-not-close.txt"

CLOSE_MARKER = "yuzu-close-linked: pr={pr} issue={issue}"
ADVISORY_MARKER = "yuzu-close-linked-advisory: pr={pr} issue={issue}"
CAPSKIP_MARKER = "yuzu-close-linked-capskip: pr={pr}"
UNDO_MARKER = "yuzu-close-linked-undo: pr={pr} issue={issue}"

# Actions
CLOSE, ADVISORY, SKIP = "CLOSE", "ADVISORY", "SKIP"


class GhError(RuntimeError):
    pass


def gh_api(path: str, *args: str, method: str = "GET", paginate: bool = False):
    """Call `gh api` and return parsed JSON (None for 404 on GET)."""
    cmd = ["gh", "api", path, "--method", method]
    if paginate:
        cmd.append("--paginate")
        cmd += ["--slurp"]
    cmd += list(args)
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
    if proc.returncode != 0:
        if method == "GET" and ("HTTP 404" in proc.stderr or "Not Found" in proc.stderr):
            return None
        raise GhError(f"gh api {path} failed (exit {proc.returncode}): {proc.stderr.strip()[:400]}")
    if not proc.stdout.strip():
        return {}
    data = json.loads(proc.stdout)
    if paginate and isinstance(data, list) and data and isinstance(data[0], list):
        # --slurp wraps each page in an array; flatten
        data = [item for page in data for item in page]
    return data


def load_do_not_close() -> set:
    """Parse the committed never-close list. Any problem => GhError (fail closed)."""
    if not DNC_PATH.exists():
        raise GhError(
            f"{DNC_PATH} is MISSING -- refusing to close anything (fail-closed; "
            f"the never-close list is a load-bearing input, see issue-standard.md 5.1)"
        )
    numbers = set()
    for lineno, line in enumerate(DNC_PATH.read_text(encoding="utf-8").splitlines(), 1):
        body = line.split("#", 1)[0].strip()
        if not body:
            continue
        if not (body.isascii() and body.isdigit() and not (len(body) > 1 and body[0] == "0")):
            raise GhError(f"do-not-close.txt:{lineno}: unparseable entry {body!r} -- fail-closed")
        numbers.add(int(body))
    if not numbers:
        raise GhError("do-not-close.txt parsed EMPTY -- fail-closed")
    return numbers


# ---------------------------------------------------------------------------
# Pure classification (unit-tested without network)

def classify(issue: dict, pr_number: int, dnc: set, comments_blob: str) -> tuple:
    """Return (action, reason) for one referenced issue. `issue` is the REST
    issue JSON (or None for 404); `comments_blob` is the concatenated comment
    bodies used for marker idempotency."""
    n = None if issue is None else issue.get("number")
    if issue is None:
        return SKIP, "not found (404)"
    if n == pr_number:
        return SKIP, "self-reference"
    if "pull_request" in issue:
        return SKIP, "reference is a PR, not an issue"
    if issue.get("state") != "open":
        return SKIP, "already closed"
    if CLOSE_MARKER.format(pr=pr_number, issue=n) in comments_blob:
        return SKIP, "already closed by this automation for this PR (marker)"
    labels = {l["name"] for l in issue.get("labels", [])}
    advisory_done = ADVISORY_MARKER.format(pr=pr_number, issue=n) in comments_blob
    if "security" in labels:
        return (SKIP if advisory_done else ADVISORY), "`security` label -- never closed by automation"
    if "do-not-close" in labels:
        return (SKIP if advisory_done else ADVISORY), "`do-not-close` label -- never closed by automation"
    if n in dnc:
        return (SKIP if advisory_done else ADVISORY), "listed in scripts/tracker/do-not-close.txt"
    if issue.get("assignees"):
        return (SKIP if advisory_done else ADVISORY), "assigned -- a human owns this issue"
    return CLOSE, "claimed by merged PR"


def has_open_linked_pr(issue_number: int) -> bool:
    """Timeline check: any OPEN PR cross-references this issue. Bounded to the
    first 300 timeline events -- enough for every issue in this tracker."""
    events = gh_api(
        f"repos/{REPO}/issues/{issue_number}/timeline",
        "-f", "per_page=100",
        paginate=True,
    ) or []
    for ev in events[:300]:
        src = (ev.get("source") or {}).get("issue") or {}
        if "pull_request" in src and src.get("state") == "open":
            return True
    return False


# ---------------------------------------------------------------------------
# GitHub plumbing

def run_context() -> str:
    server = os.environ.get("GITHUB_SERVER_URL")
    repo = os.environ.get("GITHUB_REPOSITORY")
    run_id = os.environ.get("GITHUB_RUN_ID")
    if server and repo and run_id:
        return f"[workflow run]({server}/{repo}/actions/runs/{run_id})"
    who = os.environ.get("USERNAME") or os.environ.get("USER") or "operator"
    return f"local run by `{who}`"


def merged_prs_for_range(before: str, after: str) -> list:
    """PRs merged into TARGET_BRANCH whose merge/squash commit is inside the
    pushed range, resolved via the compare API + commit-PR association."""
    if set(before) == {"0"}:  # branch-creation push: no meaningful range
        return []
    cmp_data = gh_api(f"repos/{REPO}/compare/{before}...{after}")
    if cmp_data is None:
        raise GhError(f"compare {before}...{after} not found")
    shas = [c["sha"] for c in cmp_data.get("commits", [])]
    prs, seen = [], set()
    for sha in shas:
        assoc = gh_api(f"repos/{REPO}/commits/{sha}/pulls") or []
        for pr in assoc:
            num = pr["number"]
            if num in seen:
                continue
            seen.add(num)
            if not pr.get("merged_at"):
                continue
            if pr.get("base", {}).get("ref") != TARGET_BRANCH:
                continue
            if pr.get("merge_commit_sha") not in shas:
                continue  # associated but merged by an earlier push
            prs.append(pr)
    return prs


def all_merged_dev_prs() -> list:
    prs = gh_api(
        f"repos/{REPO}/pulls",
        "-f", "state=closed", "-f", f"base={TARGET_BRANCH}", "-f", "per_page=100",
        paginate=True,
    ) or []
    return [p for p in prs if p.get("merged_at")]


def issue_with_comments(n: int) -> tuple:
    issue = gh_api(f"repos/{REPO}/issues/{n}")
    if issue is None:
        return None, ""
    comments = gh_api(f"repos/{REPO}/issues/{n}/comments", "-f", "per_page=100", paginate=True) or []
    blob = "\n".join(c.get("body") or "" for c in comments)
    return issue, blob


def post_comment(n: int, body: str, execute: bool):
    if not execute:
        return
    gh_api(f"repos/{REPO}/issues/{n}/comments", "-f", f"body={body}", method="POST")
    time.sleep(MUTATION_SLEEP_S)


def close_issue(n: int, execute: bool):
    if not execute:
        return
    gh_api(f"repos/{REPO}/issues/{n}", "-f", "state=closed", "-f", "state_reason=completed", method="PATCH")
    time.sleep(MUTATION_SLEEP_S)


def add_label(n: int, label: str, execute: bool):
    """Tolerates a missing label (A1: an early merge cannot fail a close)."""
    if not execute:
        return
    try:
        gh_api(f"repos/{REPO}/issues/{n}/labels", "-f", f"labels[]={label}", method="POST")
        time.sleep(MUTATION_SLEEP_S)
    except GhError as e:
        print(f"  note: could not add label {label!r} to #{n} ({e}); continuing", file=sys.stderr)


def evidence_comment(pr: dict, issue_n: int) -> str:
    merger = (pr.get("merged_by") or {}).get("login") or "unknown"
    sha = (pr.get("merge_commit_sha") or "")[:10]
    return (
        f"Closed automatically by `close-linked-issues` ({run_context()}): "
        f"PR #{pr['number']} (merge `{sha}`, merged into `{TARGET_BRANCH}` by @{merger}) "
        f"declares it closes this issue.\n\n"
        f"Performed by automation; the authorizing human is the PR's merger. "
        f"Wrong close? Reopen and add the `do-not-close` label -- automation "
        f"never touches it again (docs/agents/issue-standard.md 5.1).\n\n"
        f"<!-- {CLOSE_MARKER.format(pr=pr['number'], issue=issue_n)} -->"
    )


def advisory_comment(pr: dict, issue_n: int, reason: str) -> str:
    return (
        f"Merged PR #{pr['number']} claims to close this issue, but it is "
        f"protected from automated closure ({reason}). A human must verify the "
        f"fix against current `origin/{TARGET_BRANCH}` before closing "
        f"(docs/agents/issue-standard.md 5.1).\n\n"
        f"<!-- {ADVISORY_MARKER.format(pr=pr['number'], issue=issue_n)} -->"
    )


def capskip_issue(pr: dict, refs: list, execute: bool):
    title = f"close-linked-issues: cap-skip on PR #{pr['number']} ({len(refs)} closing refs)"
    existing = gh_api(
        "search/issues",
        "-f", f"q=repo:{REPO} is:issue is:open in:title \"cap-skip on PR #{pr['number']}\"",
    ) or {}
    if existing.get("total_count", 0) > 0:
        print(f"  cap-skip issue already open for PR #{pr['number']}")
        return
    body = (
        f"PR #{pr['number']} resolves {len(refs)} issues ({', '.join(f'#{n}' for n in refs)}), "
        f"over the per-PR sanity cap of {PER_PR_CAP} (ADR-3001 A1 par.5). The automation closed "
        f"NOTHING for this PR; a human should review and close the genuine ones by hand.\n\n"
        f"Run: {run_context()}\n\n<!-- {CAPSKIP_MARKER.format(pr=pr['number'])} -->"
    )
    if execute:
        gh_api(f"repos/{REPO}/issues", "-f", f"title={title}", "-f", f"body={body}", method="POST")
        time.sleep(MUTATION_SLEEP_S)
        # labels applied separately and tolerantly (they may not exist yet)
        created = gh_api(
            "search/issues", "-f",
            f"q=repo:{REPO} is:issue is:open in:title \"cap-skip on PR #{pr['number']}\"",
        ) or {}
        items = created.get("items") or []
        if items:
            for lbl in ("needs-triage", "P2"):
                add_label(items[0]["number"], lbl, execute)
    else:
        print(f"  [dry-run] would open cap-skip issue: {title}")


# ---------------------------------------------------------------------------
# Modes

def process_prs(prs: list, dnc: set, execute: bool, check_linked_pr: bool = True) -> tuple:
    """Shared engine for --push and --backfill. Returns (actions, leaks)
    where actions = list of (pr, issue_n, action, reason)."""
    plan = []
    for pr in prs:
        refs = closing_refs.closing_numbers(pr.get("body") or "")
        if not refs:
            continue
        if len(refs) > PER_PR_CAP:
            print(f"PR #{pr['number']}: {len(refs)} refs > cap {PER_PR_CAP} -- closing nothing for this PR")
            capskip_issue(pr, refs, execute)
            continue
        for n in refs:
            issue, blob = issue_with_comments(n)
            action, reason = classify(issue, pr["number"], dnc, blob)
            if action == CLOSE and check_linked_pr and has_open_linked_pr(n):
                action, reason = ADVISORY, "an open PR still references this issue"
                if ADVISORY_MARKER.format(pr=pr["number"], issue=n) in blob:
                    action, reason = SKIP, reason + " (advisory already posted)"
            plan.append((pr, n, action, reason, issue))

    # Defense-in-depth: a CLOSE that still carries `security` is only reachable
    # through a ladder bug -- abort the entire run, zero mutations (A1 par.4).
    for pr, n, action, reason, issue in plan:
        if action == CLOSE and issue and any(
            l["name"] == "security" for l in issue.get("labels", [])
        ):
            print(f"FATAL: ladder bug -- CLOSE action for security-labelled #{n}. Aborting with zero mutations.")
            sys.exit(4)

    return plan


def print_plan(plan: list):
    def sort_key(item):
        pr, n, action, reason, issue = item
        labels = {l["name"] for l in (issue or {}).get("labels", [])}
        danger = ("security" in labels, "P0" in labels, "P1" in labels, bool((issue or {}).get("assignees")))
        return (-sum(danger), action != ADVISORY, n)

    for pr, n, action, reason, issue in sorted(plan, key=sort_key):
        labels = ",".join(l["name"] for l in (issue or {}).get("labels", [])) if issue else "-"
        title = (issue or {}).get("title", "?")[:60]
        print(f"  {action:8} #{n:<5} (PR #{pr['number']}) [{labels}] {title!r} -- {reason}")


def apply_plan(plan: list, execute: bool):
    closed = advised = 0
    for pr, n, action, reason, issue in plan:
        if action == CLOSE:
            post_comment(n, evidence_comment(pr, n), execute)
            close_issue(n, execute)
            add_label(n, "fixed-on-dev", execute)
            closed += 1
        elif action == ADVISORY:
            post_comment(n, advisory_comment(pr, n, reason), execute)
            advised += 1
    mode = "EXECUTED" if execute else "DRY-RUN (nothing mutated)"
    print(f"{mode}: {closed} close(s), {advised} advisory comment(s), "
          f"{sum(1 for p in plan if p[2] == SKIP)} skip(s)")


def mode_push(before: str, after: str, execute: bool) -> int:
    dnc = load_do_not_close()
    prs = merged_prs_for_range(before, after)
    if not prs:
        print(f"no merged {TARGET_BRANCH}-base PRs in {before[:10]}..{after[:10]}")
        return 0
    print(f"{len(prs)} merged PR(s) in range: {', '.join('#' + str(p['number']) for p in prs)}")
    plan = process_prs(prs, dnc, execute)
    print_plan(plan)
    apply_plan(plan, execute)
    return 0


def mode_backfill(execute: bool, reviewed: bool) -> int:
    dnc = load_do_not_close()
    if execute and not reviewed:
        print("--backfill --execute requires --yes-i-reviewed: the dry-run diff is "
              "reviewed per-issue by the maintainer on #2139 first (A1 par.4).")
        return 2
    prs = all_merged_dev_prs()
    print(f"scanning {len(prs)} merged {TARGET_BRANCH}-base PRs...")
    plan = process_prs(prs, dnc, execute)
    live = [p for p in plan if p[2] != SKIP]
    print(f"\nbackfill plan ({len(live)} action(s)), most dangerous first:")
    print_plan(live)
    apply_plan(plan, execute)
    return 0


def mode_undo_push(before: str, after: str, execute: bool) -> int:
    dnc = load_do_not_close()  # fail-closed applies to undo too
    prs = merged_prs_for_range(before, after)
    undone = 0
    for pr in prs:
        for n in closing_refs.closing_numbers(pr.get("body") or ""):
            issue, blob = issue_with_comments(n)
            if issue is None:
                continue
            marker = CLOSE_MARKER.format(pr=pr["number"], issue=n)
            if marker not in blob:
                print(f"  #{n}: no close marker for PR #{pr['number']} -- not ours, skipping")
                continue
            if issue.get("state") == "open":
                print(f"  #{n}: already open -- skipping")
                continue
            if execute:
                gh_api(f"repos/{REPO}/issues/{n}", "-f", "state=open", method="PATCH")
                time.sleep(MUTATION_SLEEP_S)
                post_comment(n, f"Reopened by `close-linked-issues --undo-push` for PR #{pr['number']}."
                                f"\n\n<!-- {UNDO_MARKER.format(pr=pr['number'], issue=n)} -->", execute)
                add_label(n, "needs-triage", execute)
                try:
                    gh_api(f"repos/{REPO}/issues/{n}/labels/fixed-on-dev", method="DELETE")
                except GhError:
                    pass
            print(f"  {'reopened' if execute else '[dry-run] would reopen'} #{n} (PR #{pr['number']})")
            undone += 1
    print(f"undo: {undone} issue(s) {'reopened' if execute else 'would reopen'}")
    return 0


def mode_leak_scan(window: int) -> int:
    """Exit 1 if any merged PR's claimed issue is still open with no marker and
    no never-close protection -- the completeness backstop (A1 par.11)."""
    dnc = load_do_not_close()
    prs = all_merged_dev_prs()[:window]
    leaks = []
    for pr in prs:
        refs = closing_refs.closing_numbers(pr.get("body") or "")
        if not refs or len(refs) > PER_PR_CAP:  # identical cap rule as the close path
            continue
        for n in refs:
            issue, blob = issue_with_comments(n)
            action, reason = classify(issue, pr["number"], dnc, blob)
            if action == CLOSE:
                leaks.append((pr["number"], n))
    if leaks:
        print(f"LEAK: {len(leaks)} claimed-but-open issue(s) with no marker/protection:")
        for pr_n, n in leaks:
            print(f"  #{n} (claimed by merged PR #{pr_n})")
        return 1
    print(f"leak scan clean over the last {len(prs)} merged PRs")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--push", nargs=2, metavar=("BEFORE", "AFTER"))
    mode.add_argument("--backfill", action="store_true")
    mode.add_argument("--undo-push", nargs=2, metavar=("BEFORE", "AFTER"))
    mode.add_argument("--leak-scan", action="store_true")
    ap.add_argument("--execute", action="store_true", help="mutate (default: dry-run)")
    ap.add_argument("--yes-i-reviewed", action="store_true",
                    help="backfill only: confirm the dry-run diff was reviewed per-issue")
    ap.add_argument("--window", type=int, default=LEAK_SCAN_WINDOW)
    args = ap.parse_args(argv)

    try:
        if args.push:
            return mode_push(args.push[0], args.push[1], args.execute)
        if args.backfill:
            return mode_backfill(args.execute, args.yes_i_reviewed)
        if args.undo_push:
            return mode_undo_push(args.undo_push[0], args.undo_push[1], args.execute)
        if args.leak_scan:
            return mode_leak_scan(args.window)
    except GhError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
