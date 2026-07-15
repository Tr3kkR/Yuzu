#!/usr/bin/env python3
"""tracker_report.py -- the weekly issue-tracker dashboard (ADR-3001 pillar 5, A1 §10).

READ-ONLY and NO-LLM by contract. This script GETs from the GitHub API and
greps the current checkout; it NEVER closes, reopens, relabels, or comments.
Its output is a markdown dashboard written to a file; the ONLY write is the
`.github/workflows/tracker-report.yml` step that posts that file as one comment
to the `triage-sweep` tracking issue (or the operator running it locally). All
issue-lifecycle mutation happens out-of-band, operator-approved, through the
fail-closed scripts/tracker/apply_decisions.py -- never here.

Why no LLM (ADR-3001 "Alternatives considered"): the report's core operation is
counting labels and grepping the checkout. An Actions-hosted model would need an
API-key secret (admin provisioning) to do arithmetic. This is `gh api` + grep.

Sections (A1 §10: "telemetry, leak scan, duplicate candidates, closure-integrity
sample"):
  - TELEMETRY -- open / active / needs-triage / ready-for-agent / governance
    inflow / 7-day inflow+outflow / backlog age, every gauge keyed on the
    ACTIVE set (is:open -label:roadmap) per A1 §6. Two alarm thresholds ship
    GREEN on day one (A1 §10): `leak > 0` and `needs-triage(active) > 100`;
    the net-inflow alarm is deleted (measured inflow permanently breaches any
    threshold and would bury the one signal that matters). A dead-man's-switch
    fires if the previous report is > STALENESS_DAYS old.
  - LEAK SCAN -- issues a merged PR claims but that are still open, computed
    through close_linked_issues.build_plan (the SAME planning path as the close
    workflow, so a protected/advisory item is never a false leak). `leak > 0`
    means an earlier close run failed. Redundant with PR 2's per-push scan but
    cheap and independent.
  - LABEL HYGIENE -- the issue-standard.md §4 invariants (exactly one type,
    exactly one triage state, a priority once triaged, roadmap XOR
    priority/triage-state) plus do-not-close label-vs-file divergence.
  - DUPLICATE CANDIDATES -- open issues clustered by a shared file-path citation
    (issue-standard.md mandates file:line evidence; this is that index). Roadmap
    issues STAY in this snapshot (A1 §6: excluding a third of the corpus would
    blind it) though the judgment categories never run on them.
  - CLOSURE-INTEGRITY SAMPLE -- recent not_planned closures listed with their
    cited file:line, for a human spot-check that closures stayed durable as the
    architecture moved. Listed, never judged automatically.

Report identity: the dashboard footer carries `<!-- yuzu-tracker-report:
hash=<sha256> run=<id> -->`. The hash covers only the FLAGGED CANDIDATE SET
(the issue numbers a human would triage), not the volatile telemetry counts, so
a re-run over an unchanged candidate set is byte-stable -- that is what
apply_decisions.py verifies a decision list against (a stale report => refuse).

FAIL-CLOSED: the leak scan reads scripts/tracker/do-not-close.txt through
close_linked_issues.load_do_not_close(), which raises if the list is missing or
unparseable. The dashboard renders that as a RED leak-scan row rather than a
silent zero; a hard gh error exits 3 so the workflow's failure alert fires.

Stdlib only. Run as `python` on Windows dev boxes (python3 is the Store stub).
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import close_linked_issues as cli  # noqa: E402  (reuse gh_api, build_plan, the never-close list)

REPO = cli.REPO
TARGET_BRANCH = cli.TARGET_BRANCH

TRIAGE_SWEEP_LABEL = "triage-sweep"
ROADMAP_LABEL = "roadmap"
NEEDS_TRIAGE = "needs-triage"
GOVERNANCE_DEFERRED = "governance-deferred"
DO_NOT_CLOSE_LABEL = "do-not-close"

# issue-standard.md §4 / triage-labels.md axes.
TYPE_LABELS = {"bug", "enhancement", "task", "decision", "spike",
               "documentation", "question", "operational"}
PRIORITY_LABELS = {"P0", "P1", "P2"}
TRIAGE_STATE_LABELS = {"needs-triage", "needs-info", "ready-for-agent",
                       "ready-for-human", "wontfix"}

# Alarm thresholds -- both ship green on day one (A1 §10). The net-inflow alarm
# is deliberately ABSENT (measured inflow 83-173/wk permanently breaches it).
NEEDS_TRIAGE_ACTIVE_THRESHOLD = 100
STALENESS_DAYS = 10
LEAK_SCAN_WINDOW = cli.LEAK_SCAN_WINDOW
CLOSURE_SAMPLE_SIZE = 10
DUP_MIN_CLUSTER = 2

# A file-path citation: a slash-separated path with a real extension, optionally
# ":line". Conservative on purpose -- a bare word must not cluster issues.
_PATH_CITE_RE = re.compile(r"\b([A-Za-z0-9_][A-Za-z0-9_./-]*?/[A-Za-z0-9_./-]+\.[A-Za-z0-9]{1,6})(?::(\d+))?\b")
# Paths so common they cluster unrelated issues -- excluded from the dup index.
_PATH_CITE_STOPLIST = {"docs/agents/issue-standard.md", "docs/agents/triage-labels.md"}

REPORT_MARKER = "yuzu-tracker-report: hash={hash} run={run}"
_REPORT_MARKER_RE = re.compile(r"yuzu-tracker-report:\s*hash=([0-9a-f]{64})\s+run=(\S+)")


class TrackerError(cli.GhError):
    """A report-generation failure that should exit 3 (fail-closed)."""


# ---------------------------------------------------------------------------
# Injectable clock (tests pin it; production uses real UTC).

def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _parse_iso(ts: str) -> "datetime.datetime | None":
    if not ts:
        return None
    try:
        return datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def _labels(issue: dict) -> set:
    return {l["name"] for l in (issue or {}).get("labels", [])}


def _is_issue(obj: dict) -> bool:
    """A REST issues listing includes PRs; a real issue has no pull_request key."""
    return "pull_request" not in obj


# ---------------------------------------------------------------------------
# Fetch (read-only)

def fetch_open_issues() -> list:
    """Every OPEN issue (PRs filtered out). One paginated GET -- the single
    dataset every telemetry/hygiene/duplicate computation reads."""
    raw = cli.gh_api(
        f"repos/{REPO}/issues",
        "-f", "state=open", "-f", "per_page=100",
        paginate=True,
    ) or []
    return [i for i in raw if _is_issue(i)]


def search_count(query: str) -> int:
    """total_count for a search query (inflow/outflow windows)."""
    data = cli.gh_api("search/issues", "-f", f"q={query}") or {}
    return int(data.get("total_count", 0))


def find_tracking_issue() -> "dict | None":
    """The open issue labelled `triage-sweep` the report comments on. First
    such issue wins; None if the label has not been applied to one yet."""
    raw = cli.gh_api(
        f"repos/{REPO}/issues",
        "-f", f"labels={TRIAGE_SWEEP_LABEL}", "-f", "state=open", "-f", "per_page=10",
    ) or []
    for i in raw:
        if _is_issue(i):
            return i
    return None


def latest_report_hash() -> "str | None":
    """The hash on the most recent tracker-report comment on the tracking
    issue -- the value apply_decisions.py checks a decision list against. Only
    a github-actions[bot] comment counts (the report is bot-posted); a
    user-pasted marker must not spoof it. None if there is no report yet."""
    issue = find_tracking_issue()
    if not issue:
        return None
    comments = cli.gh_api(
        f"repos/{REPO}/issues/{issue['number']}/comments",
        "-f", "per_page=100", paginate=True,
    ) or []
    newest = None  # (created_at, hash)
    for c in comments:
        if ((c.get("user") or {}).get("login")) != cli.TRUSTED_BOT:
            continue
        m = _REPORT_MARKER_RE.search(c.get("body") or "")
        if not m:
            continue
        created = c.get("created_at") or ""
        if newest is None or created > newest[0]:
            newest = (created, m.group(1))
    return newest[1] if newest else None


def previous_report_datetime() -> "datetime.datetime | None":
    """created_at of the most recent tracker-report comment (dead-man's-switch)."""
    issue = find_tracking_issue()
    if not issue:
        return None
    comments = cli.gh_api(
        f"repos/{REPO}/issues/{issue['number']}/comments",
        "-f", "per_page=100", paginate=True,
    ) or []
    newest = None
    for c in comments:
        if ((c.get("user") or {}).get("login")) != cli.TRUSTED_BOT:
            continue
        if not _REPORT_MARKER_RE.search(c.get("body") or ""):
            continue
        dt = _parse_iso(c.get("created_at") or "")
        if dt and (newest is None or dt > newest):
            newest = dt
    return newest


# ---------------------------------------------------------------------------
# Pure computations (unit-tested without network)

def compute_telemetry(open_issues: list, inflow7: int, outflow7: int,
                      gov_inflow7: int, now: datetime.datetime) -> dict:
    active = [i for i in open_issues if ROADMAP_LABEL not in _labels(i)]
    roadmap = [i for i in open_issues if ROADMAP_LABEL in _labels(i)]
    needs_triage_active = [i for i in active if NEEDS_TRIAGE in _labels(i)]
    ready_for_agent_active = [i for i in active if "ready-for-agent" in _labels(i)]
    gov_deferred = [i for i in open_issues if GOVERNANCE_DEFERRED in _labels(i)]

    ages = []
    for i in active:
        dt = _parse_iso(i.get("created_at") or "")
        if dt:
            ages.append((now - dt).days)
    ages.sort()
    median_age = ages[len(ages) // 2] if ages else 0
    oldest_age = ages[-1] if ages else 0

    return {
        "open": len(open_issues),
        "active": len(active),
        "roadmap": len(roadmap),
        "needs_triage_active": len(needs_triage_active),
        "ready_for_agent_active": len(ready_for_agent_active),
        "governance_deferred": len(gov_deferred),
        "inflow_7d": inflow7,
        "outflow_7d": outflow7,
        "governance_inflow_7d": gov_inflow7,
        "backlog_age_median_days": median_age,
        "backlog_age_oldest_days": oldest_age,
    }


def label_hygiene(open_issues: list, dnc_numbers: "set | None") -> list:
    """issue-standard.md §4 invariant violations. Each row: (number, problem).
    Forward-looking: only OPEN issues are audited (closures predating ADR-3001
    are never re-read through this taxonomy)."""
    rows = []
    for i in open_issues:
        n = i["number"]
        labels = _labels(i)
        is_roadmap = ROADMAP_LABEL in labels
        types = labels & TYPE_LABELS
        states = labels & TRIAGE_STATE_LABELS
        prios = labels & PRIORITY_LABELS

        if len(types) != 1:
            rows.append((n, f"{len(types)} type labels (want exactly 1): {sorted(types) or '-'}"))
        if is_roadmap:
            # roadmap carries a type only -- no priority, no triage state.
            if prios:
                rows.append((n, f"roadmap + priority {sorted(prios)} (roadmap is scope, not triaged)"))
            if states:
                rows.append((n, f"roadmap + triage state {sorted(states)} (roadmap XOR triage)"))
        else:
            if len(states) != 1:
                rows.append((n, f"{len(states)} triage-state labels (want exactly 1): {sorted(states) or '-'}"))
            # A priority is required ONCE TRIAGED; a still-needs-triage issue
            # legitimately lacks one (issue-standard.md §4, priority timing).
            if NEEDS_TRIAGE not in labels and len(prios) != 1:
                rows.append((n, f"triaged but {len(prios)} priority labels (want exactly 1): {sorted(prios) or '-'}"))
        # do-not-close label vs committed file divergence (both are §5.1 signals;
        # a label without a file entry survives only until a slow review).
        if dnc_numbers is not None and DO_NOT_CLOSE_LABEL in labels and n not in dnc_numbers:
            rows.append((n, "carries do-not-close label but is NOT in do-not-close.txt (label-only, unreviewed)"))
    return rows


def _cited_paths(body: str) -> set:
    out = set()
    for m in _PATH_CITE_RE.finditer(body or ""):
        path = m.group(1)
        if path not in _PATH_CITE_STOPLIST:
            out.add(path)
    return out


def duplicate_candidates(open_issues: list) -> list:
    """Clusters of open issues sharing a cited file path. Returns a list of
    (path, [issue numbers]) for clusters of >= DUP_MIN_CLUSTER, most-cited
    first. Candidates only -- a shared file is a hint, not a verdict. Roadmap
    issues are INCLUDED (A1 §6: excluding them blinds a third of the corpus)."""
    by_path: dict = {}
    for i in open_issues:
        for path in _cited_paths(i.get("body") or ""):
            by_path.setdefault(path, set()).add(i["number"])
    clusters = [(p, sorted(nums)) for p, nums in by_path.items() if len(nums) >= DUP_MIN_CLUSTER]
    clusters.sort(key=lambda c: (-len(c[1]), c[0]))
    return clusters


# ---------------------------------------------------------------------------
# Leak scan + closure-integrity (reuse PR 2's planning path)

def leak_scan(window: int) -> "tuple[str, list]":
    """(status, leaks). status is 'ok' | 'leak' | 'unavailable'. Reuses
    build_plan so a never-close/advisory item can never be a false leak."""
    try:
        dnc = cli.load_do_not_close()
    except cli.GhError as e:
        # do-not-close.txt missing/unparseable -> render RED, do not silently
        # zero the one signal that matters (dormant-until-#2168 caveat).
        return "unavailable", [str(e)]
    prs = cli.all_merged_dev_prs(max_pages=max(3, (window * 2) // 100 + 1))[:window]
    plan = cli.build_plan(prs, dnc)
    leaks = [(pr["number"], n) for pr, n, action, _r, _i in plan if action == cli.CLOSE]
    return ("leak" if leaks else "ok"), leaks


def closure_integrity_sample(n: int) -> list:
    """Recent not_planned closures with their first cited file:line, for a
    human spot-check. Listed, never judged (A1 §10 'closure-integrity sample').
    Returns [(number, cited_or_None)].

    Deliberately NO issue title: this dashboard is posted as a
    github-actions[bot] comment, and the README standing constraint forbids a
    bot comment relaying user-supplied text (a title carrying a marker would
    become a forgery oracle). Issue numbers and the regex-extracted path (which
    cannot contain `<!-- -->`) are the only fields echoed."""
    data = cli.gh_api(
        "search/issues",
        "-f", f"q=repo:{REPO} is:issue is:closed reason:not-planned sort:updated-desc",
        "-f", "per_page=%d" % max(1, min(n, 100)),
    ) or {}
    out = []
    for item in (data.get("items") or [])[:n]:
        m = _PATH_CITE_RE.search(item.get("body") or "")
        cited = None
        if m:
            cited = m.group(1) + (f":{m.group(2)}" if m.group(2) else "")
        out.append((item["number"], cited))
    return out


# ---------------------------------------------------------------------------
# Assemble

def candidate_set(leaks: list, hygiene: list, dups: list, closure: list) -> dict:
    """The FLAGGED issue numbers a human would triage -- the sole input to the
    report hash. Volatile counts are excluded so a re-run over an unchanged
    candidate set is byte-stable (apply_decisions.py pins a decision list to it)."""
    return {
        "leaks": sorted({n for _pr, n in leaks}),
        "hygiene": sorted({n for n, _p in hygiene}),
        "duplicates": sorted([nums for _p, nums in dups]),
        "closure_sample": sorted({n for n, _c in closure}),
    }


def report_hash(candidates: dict) -> str:
    return hashlib.sha256(
        json.dumps(candidates, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _row(ok: bool, label: str, value) -> str:
    return f"| {'🟢' if ok else '🔴'} | {label} | {value} |"


def render_markdown(telemetry: dict, leak_status: str, leaks: list,
                    hygiene: list, dups: list, closure: list,
                    staleness_days: "int | None", chash: str, run_id: str) -> str:
    L = []
    L.append("## Issue-tracker report")
    L.append("")
    L.append("Read-only weekly dashboard (ADR-3001 pillar 5 / A1 §10). Proposes "
             "nothing and closes nothing -- judgment runs through `/issue-triage` "
             "+ `scripts/tracker/apply_decisions.py`. All gauges key on the "
             "**active** set (`is:open -label:roadmap`) unless noted.")
    L.append("")

    # -- Telemetry + thresholds -------------------------------------------
    nt = telemetry["needs_triage_active"]
    leak_ok = leak_status == "ok"
    nt_ok = nt <= NEEDS_TRIAGE_ACTIVE_THRESHOLD
    stale_ok = staleness_days is None or staleness_days <= STALENESS_DAYS
    L.append("### Telemetry")
    L.append("")
    L.append("| | Gauge | Value |")
    L.append("|---|---|---|")
    L.append(_row(leak_ok, "leak scan (claimed-but-open)",
                  "see below" if leak_status != "unavailable" else "**UNAVAILABLE**"))
    L.append(_row(nt_ok, f"needs-triage, active (alarm > {NEEDS_TRIAGE_ACTIVE_THRESHOLD})", nt))
    L.append(_row(stale_ok, f"days since last report (dead-man's-switch > {STALENESS_DAYS})",
                  "first run" if staleness_days is None else staleness_days))
    L.append("| | open (all) | %d |" % telemetry["open"])
    L.append("| | active (open −roadmap) | %d |" % telemetry["active"])
    L.append("| | roadmap (parked) | %d |" % telemetry["roadmap"])
    L.append("| | ready-for-agent, active | %d |" % telemetry["ready_for_agent_active"])
    L.append("| | governance-deferred (agent inflow, all-time) | %d |" % telemetry["governance_deferred"])
    L.append("| | inflow, last 7d | %d |" % telemetry["inflow_7d"])
    L.append("| | outflow, last 7d | %d |" % telemetry["outflow_7d"])
    L.append("| | governance inflow, last 7d | %d |" % telemetry["governance_inflow_7d"])
    L.append("| | backlog age, median / oldest (active, days) | %d / %d |"
             % (telemetry["backlog_age_median_days"], telemetry["backlog_age_oldest_days"]))
    L.append("")
    L.append("> Inflow is a reported 4-week-trend gauge, **not** an alarm (A1 §10: "
             "measured inflow permanently breaches any threshold and would bury `leak > 0`).")
    L.append("")

    # -- Leak scan --------------------------------------------------------
    L.append("### Leak scan")
    L.append("")
    if leak_status == "unavailable":
        L.append(f"🔴 **UNAVAILABLE** -- the never-close list could not be read, so the "
                 f"completeness backstop is blind: {leaks[0] if leaks else 'unknown error'}. "
                 f"(Expected until #2168 lands; a RED row, never a silent zero.)")
    elif leak_status == "leak":
        L.append(f"🔴 **{len(leaks)} claimed-but-open issue(s)** the close ladder would close "
                 f"now -- an earlier close run failed on them:")
        for pr, n in sorted(leaks):
            L.append(f"- #{n} (claimed by merged PR #{pr})")
    else:
        L.append("🟢 clean -- no merged-PR claim is left unapplied over the recent window.")
    L.append("")

    # -- Label hygiene ----------------------------------------------------
    L.append("### Label hygiene (issue-standard.md §4)")
    L.append("")
    if not hygiene:
        L.append("🟢 no open-issue label-contract violations.")
    else:
        L.append(f"🔴 **{len(hygiene)} violation(s):**")
        for n, problem in sorted(hygiene)[:40]:
            L.append(f"- #{n}: {problem}")
        if len(hygiene) > 40:
            L.append(f"- …and {len(hygiene) - 40} more (see full run).")
    L.append("")

    # -- Duplicate candidates --------------------------------------------
    L.append("### Duplicate candidates (shared file citation)")
    L.append("")
    if not dups:
        L.append("No open issues share a cited file path.")
    else:
        L.append("Candidates only -- a shared file is a hint, not a verdict:")
        for path, nums in dups[:20]:
            L.append(f"- `{path}` — {', '.join('#' + str(n) for n in nums)}")
        if len(dups) > 20:
            L.append(f"- …and {len(dups) - 20} more clusters.")
    L.append("")

    # -- Closure-integrity sample ----------------------------------------
    L.append("### Closure-integrity sample (recent not_planned)")
    L.append("")
    if not closure:
        L.append("No recent not_planned closures to sample.")
    else:
        L.append("Spot-check whether each defect is genuinely gone from current "
                 f"`origin/{TARGET_BRANCH}` (listed, not judged; open each to read it):")
        for n, cited in closure:
            tail = f" — cited `{cited}`" if cited else ""
            L.append(f"- #{n}{tail}")
    L.append("")

    L.append("---")
    L.append(f"<sub>Generated by `scripts/tracker/tracker_report.py` "
             f"({cli.run_context()}). Candidate-set hash pins any decision list "
             f"applied against this report.</sub>")
    L.append("")
    L.append(f"<!-- {REPORT_MARKER.format(hash=chash, run=run_id)} -->")
    return "\n".join(L)


def build_report(window: int, sample: int, now: "datetime.datetime | None" = None) -> "tuple[str, dict]":
    """Generate the dashboard. Returns (markdown, candidate_set). Read-only."""
    now = now or _now()
    open_issues = fetch_open_issues()

    cutoff = (now - datetime.timedelta(days=7)).date().isoformat()
    inflow7 = search_count(f"repo:{REPO} is:issue created:>={cutoff}")
    outflow7 = search_count(f"repo:{REPO} is:issue closed:>={cutoff}")
    gov_inflow7 = search_count(f"repo:{REPO} is:issue label:{GOVERNANCE_DEFERRED} created:>={cutoff}")

    try:
        dnc = cli.load_do_not_close()
    except cli.GhError:
        dnc = None  # hygiene's do-not-close divergence check degrades gracefully

    telemetry = compute_telemetry(open_issues, inflow7, outflow7, gov_inflow7, now)
    leak_status, leaks = leak_scan(window)
    hygiene = label_hygiene(open_issues, dnc)
    dups = duplicate_candidates(open_issues)
    closure = closure_integrity_sample(sample)

    candidates = candidate_set(leaks if leak_status == "leak" else [], hygiene, dups, closure)
    chash = report_hash(candidates)
    run_id = os.environ.get("GITHUB_RUN_ID") or chash[:12]

    prev = previous_report_datetime()
    staleness = None if prev is None else (now - prev).days

    md = render_markdown(telemetry, leak_status, leaks, hygiene, dups, closure,
                         staleness, chash, run_id)
    return md, candidates


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", default="", help="write the dashboard markdown here (default: stdout)")
    ap.add_argument("--json", action="store_true", help="also print the candidate set + hash as JSON to stderr")
    ap.add_argument("--window", type=int, default=LEAK_SCAN_WINDOW, help="leak-scan PR window")
    ap.add_argument("--sample", type=int, default=CLOSURE_SAMPLE_SIZE, help="closure-integrity sample size")
    args = ap.parse_args(argv)

    try:
        md, candidates = build_report(args.window, args.sample)
    except cli.GhError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 3

    if args.out:
        pathlib.Path(args.out).write_text(md, encoding="utf-8")
        print(f"dashboard written to {args.out}")
    else:
        print(md)
    if args.json:
        print(json.dumps({"hash": report_hash(candidates), "candidates": candidates}),
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
