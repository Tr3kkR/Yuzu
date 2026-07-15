#!/usr/bin/env python3
"""Frozen tests for the tracker report + decision-apply layer (ADR-3001 PR 4).

Three surfaces, no network:

1. tracker_report.py pure logic -- telemetry gauges over the active set,
   issue-standard §4 label-hygiene invariants, duplicate clustering by cited
   file path, and the candidate-set hash's stability (a re-run over the same
   candidates must be byte-stable, since apply_decisions.py pins a decision
   list to it). Plus the leak scan reusing close_linked_issues.build_plan.

2. apply_decisions.py schema + hashing -- the decisions file's structural
   fail-closed contract (exit-3 cases) and the decisions-hash's order-
   independence (so --execute can pin to a reviewed --dry-run).

3. apply_decisions.py validate() -- every fail-closed refusal R1-R7. validate()
   is pure (it takes live issue state as arguments), so the whole safety
   surface is exercised without a network. Plus the dry-run/execute snapshot
   flow and --revert marker-verification through a fake `gh`.

Wired into tests/meson.build (suite: docs). scripts/ is code-side for the CI
docs-only gate, so any PR that can break these also runs the heavy platform
jobs -- meson coverage is structurally sufficient. Run locally as
`python tests/test_tracker.py`.
"""

import contextlib
import io
import json
import os
import pathlib
import re
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts" / "tracker"))

import close_linked_issues as cli   # noqa: E402
import tracker_report as report     # noqa: E402
import apply_decisions as ad        # noqa: E402

HEX64 = "a" * 64  # a valid report_hash for the marker regex ([0-9a-f]{64})


def _issue(n, state="open", labels=(), assignees=(), body="", title=None,
           created_at="2026-01-01T00:00:00Z", is_pr=False):
    d = {
        "number": n, "state": state, "title": title or f"issue {n}",
        "labels": [{"name": l} for l in labels],
        "assignees": [{"login": a} for a in assignees],
        "body": body, "created_at": created_at,
    }
    if is_pr:
        d["pull_request"] = {}
    return d


def _d(n, category="obsolete", reason="stale", **kw):
    d = {"number": n, "category": category, "reason": reason}
    d.update(kw)
    return d


# ==========================================================================
# 1. tracker_report pure logic

def run_telemetry_tests(failures):
    import datetime
    now = datetime.datetime(2026, 7, 15, tzinfo=datetime.timezone.utc)
    issues = [
        _issue(1, labels=["bug", "needs-triage"], created_at="2026-07-14T00:00:00Z"),
        _issue(2, labels=["bug", "P1", "ready-for-agent"], created_at="2026-06-15T00:00:00Z"),
        _issue(3, labels=["enhancement", "roadmap"], created_at="2026-01-01T00:00:00Z"),
        _issue(4, labels=["task", "P2", "ready-for-agent", "governance-deferred"],
               created_at="2026-07-01T00:00:00Z"),
    ]
    t = report.compute_telemetry(issues, inflow7=5, outflow7=3, gov_inflow7=2, now=now)
    checks = {
        "open": 4, "active": 3, "roadmap": 1, "needs_triage_active": 1,
        "ready_for_agent_active": 2, "governance_deferred": 1,
        "inflow_7d": 5, "outflow_7d": 3, "governance_inflow_7d": 2,
    }
    for k, want in checks.items():
        if t[k] != want:
            failures.append(f"telemetry: {k}={t[k]} want {want}")
    # median active age: ages {1, 30, 14} (issue 3 excluded, roadmap) -> sorted [1,14,30] -> 14
    if t["backlog_age_median_days"] != 14:
        failures.append(f"telemetry: median age {t['backlog_age_median_days']} want 14")
    if t["backlog_age_oldest_days"] != 30:
        failures.append(f"telemetry: oldest age {t['backlog_age_oldest_days']} want 30")


def run_hygiene_tests(failures):
    dnc = {520}
    issues = [
        _issue(1, labels=["bug", "P1", "ready-for-agent"]),                 # clean
        _issue(2, labels=["needs-triage"]),                                  # no type
        _issue(3, labels=["bug", "enhancement", "P1", "ready-for-agent"]),   # two types
        _issue(4, labels=["bug", "ready-for-agent"]),                        # triaged, no priority
        _issue(5, labels=["bug", "needs-triage"]),                           # needs-triage: priority exempt -> clean
        _issue(6, labels=["bug", "roadmap", "P1"]),                          # roadmap + priority
        _issue(7, labels=["bug", "roadmap", "needs-triage"]),                # roadmap + triage state
        _issue(8, labels=["bug", "P1", "ready-for-agent", "do-not-close"]),  # dnc label, not in file
        _issue(520, labels=["bug", "security", "P1", "ready-for-agent", "do-not-close"]),  # in file -> ok
    ]
    rows = report.label_hygiene(issues, dnc)
    flagged = {n for n, _p in rows}
    want_flagged = {2, 3, 4, 6, 7, 8}
    if flagged != want_flagged:
        failures.append(f"hygiene: flagged {sorted(flagged)} want {sorted(want_flagged)}")
    # #5 (needs-triage, no priority) and #1 (clean) and #520 (in file) must NOT flag
    for ok in (1, 5, 520):
        if ok in flagged:
            failures.append(f"hygiene: #{ok} must not be flagged")
    # dnc=None must degrade gracefully (skip the label-vs-file check, no crash)
    rows_none = report.label_hygiene([_issue(8, labels=["bug", "P1", "ready-for-agent", "do-not-close"])], None)
    if any("do-not-close.txt" in p for _n, p in rows_none):
        failures.append("hygiene: dnc=None must skip the label-vs-file divergence check")


def run_duplicate_tests(failures):
    issues = [
        _issue(1, body="root cause in src/core/auth.cpp:42 clearly"),
        _issue(2, body="also see src/core/auth.cpp near the token check"),
        _issue(3, body="unrelated, docs/agents/issue-standard.md line stuff"),  # stoplisted path
        _issue(4, body="another one docs/agents/issue-standard.md"),            # stoplisted -> no cluster
        _issue(5, body="lonely path lib/x/only.py:1"),
        _issue(6, roadmap_marker := "roadmap issues stay in snapshot src/core/auth.cpp"),
    ]
    # give #6 the roadmap label to prove roadmap issues remain in the dup snapshot
    issues[5] = _issue(6, labels=["roadmap"], body="roadmap issues stay src/core/auth.cpp")
    clusters = report.duplicate_candidates(issues)
    cmap = {p: nums for p, nums in clusters}
    if "src/core/auth.cpp" not in cmap:
        failures.append(f"duplicate: expected a src/core/auth.cpp cluster, got {cmap}")
    elif cmap["src/core/auth.cpp"] != [1, 2, 6]:
        failures.append(f"duplicate: auth.cpp cluster {cmap['src/core/auth.cpp']} want [1, 2, 6] (roadmap #6 kept)")
    if any("issue-standard.md" in p for p in cmap):
        failures.append("duplicate: stoplisted path must not cluster")
    if "lib/x/only.py" in cmap:
        failures.append("duplicate: a single-issue path must not be a cluster")


def run_report_hash_tests(failures):
    leaks = [(500, 77), (501, 88)]
    hygiene = [(3, "x"), (2, "y")]
    dups = [("a.cpp", [1, 2]), ("b.cpp", [3, 4])]
    closure = [(10, None), (11, "z.py:1")]
    c1 = report.candidate_set(leaks, hygiene, dups, closure)
    # order independence: same candidates in a different order -> identical hash
    c2 = report.candidate_set(list(reversed(leaks)), list(reversed(hygiene)),
                              list(reversed(dups)), list(reversed(closure)))
    if report.report_hash(c1) != report.report_hash(c2):
        failures.append("report_hash: candidate order must not change the hash")
    # a changed candidate set -> a changed hash
    c3 = report.candidate_set(leaks + [(502, 99)], hygiene, dups, closure)
    if report.report_hash(c1) == report.report_hash(c3):
        failures.append("report_hash: a new leak must change the hash")
    # hash must be 64 hex (the marker regex requires it)
    if not re.fullmatch(r"[0-9a-f]{64}", report.report_hash(c1)):
        failures.append("report_hash: not 64 lowercase hex")

    # No-user-text property: the dashboard is a bot comment, so it must relay no
    # user-authored strings. The rendered markdown must carry exactly ONE HTML
    # comment -- its own report marker -- and no other <!-- ... --> could ride in
    # on a title/path (numbers + regex-extracted paths only).
    md = report.render_markdown(
        report.compute_telemetry([], 0, 0, 0, __import__("datetime").datetime(
            2026, 7, 15, tzinfo=__import__("datetime").timezone.utc)),
        "ok", [], [(3, "x")], [("a.cpp", [1, 2])], [(10, "z.py:1")],
        None, report.report_hash(c1), "runid")
    if md.count("<!--") != 1:
        failures.append(f"render: expected exactly one HTML comment (the marker), got {md.count('<!--')}")
    if report.REPORT_MARKER.format(hash=report.report_hash(c1), run="runid") not in md:
        failures.append("render: report marker missing from the dashboard footer")


class _FakeWorld:
    """Monkeypatch the driver's network seams (mirrors PR 2's harness)."""

    def __init__(self, issues, timelines=None, merged_prs=None):
        self.issues = issues
        self.timelines = timelines or {}
        self.merged_prs = merged_prs or []
        self._saved = {}

    def __enter__(self):
        self._saved = {k: getattr(cli, k) for k in
                       ("issue_with_comments", "has_open_linked_pr", "gh_api", "all_merged_dev_prs")}
        cli.issue_with_comments = lambda n: (self.issues.get(n), "")
        cli.has_open_linked_pr = lambda n: any(
            "pull_request" in ((ev.get("source") or {}).get("issue") or {})
            and ((ev.get("source") or {}).get("issue") or {}).get("state") == "open"
            for ev in self.timelines.get(n, []))
        cli.gh_api = lambda *a, **k: (_ for _ in ()).throw(
            AssertionError(f"unexpected network call: {a}"))
        cli.all_merged_dev_prs = lambda max_pages=0: list(self.merged_prs)
        return self

    def __exit__(self, *exc):
        for k, v in self._saved.items():
            setattr(cli, k, v)


def _pr(number, body):
    return {"number": number, "body": body, "merged_at": "2026-01-01T00:00:00Z",
            "merge_commit_sha": "f" * 40, "base": {"ref": "dev"}}


def run_leak_scan_tests(failures):
    real = cli.DNC_PATH
    try:
        with tempfile.TemporaryDirectory() as td:
            cli.DNC_PATH = pathlib.Path(td) / "do-not-close.txt"
            cli.DNC_PATH.write_text("999  # placeholder\n", encoding="utf-8")
            # a claimed-but-open plain issue -> leak
            with _FakeWorld(issues={77: _issue(77, labels=["bug"])},
                            merged_prs=[_pr(500, "Closes #77")]):
                status, leaks = report.leak_scan(window=10)
            if status != "leak" or leaks != [(500, 77)]:
                failures.append(f"leak_scan: want ('leak', [(500,77)]), got ({status}, {leaks})")
            # a do-not-close-listed issue is protected -> never a leak
            cli.DNC_PATH.write_text("77\n", encoding="utf-8")
            with _FakeWorld(issues={77: _issue(77, labels=["bug"])},
                            merged_prs=[_pr(500, "Closes #77")]):
                status, leaks = report.leak_scan(window=10)
            if status != "ok":
                failures.append(f"leak_scan: dnc-protected issue must not leak, got {status} {leaks}")
            # missing list -> UNAVAILABLE (RED), never a silent clean
            cli.DNC_PATH = pathlib.Path(td) / "gone.txt"
            status, leaks = report.leak_scan(window=10)
            if status != "unavailable":
                failures.append(f"leak_scan: missing list must be 'unavailable', got {status}")
    finally:
        cli.DNC_PATH = real


# ==========================================================================
# 2. apply_decisions schema + hashing

def run_schema_tests(failures):
    good = {"report_hash": HEX64, "decisions": [_d(1, "obsolete", "stale")]}
    bad_cases = [
        ("not json", "{not json"),
        ("not object", "[1,2]"),
        ("no report_hash", json.dumps({"decisions": []})),
        ("no decisions list", json.dumps({"report_hash": HEX64})),
        ("decision not object", json.dumps({"report_hash": HEX64, "decisions": [1]})),
        ("number not positive", json.dumps({"report_hash": HEX64, "decisions": [_d(0)]})),
        ("number is bool", json.dumps({"report_hash": HEX64, "decisions": [{"number": True, "category": "obsolete", "reason": "x"}]})),
        ("empty reason", json.dumps({"report_hash": HEX64, "decisions": [_d(1, "obsolete", "  ")]})),
        ("category missing", json.dumps({"report_hash": HEX64, "decisions": [{"number": 1, "reason": "x"}]})),
        ("verified not str", json.dumps({"report_hash": HEX64, "decisions": [_d(1, "fixed-elsewhere", "x", verified_gone_at=5)]})),
        ("dup_of not int", json.dumps({"report_hash": HEX64, "decisions": [_d(1, "duplicate", "x", duplicate_of="2")]})),
    ]
    with tempfile.TemporaryDirectory() as td:
        for label, content in bad_cases:
            p = pathlib.Path(td) / "d.json"
            p.write_text(content, encoding="utf-8")
            try:
                ad.load_decisions(str(p))
                failures.append(f"schema: {label}: expected DecisionsError, got success")
            except ad.DecisionsError:
                pass
        # missing file
        try:
            ad.load_decisions(str(pathlib.Path(td) / "nope.json"))
            failures.append("schema: missing file: expected DecisionsError")
        except ad.DecisionsError:
            pass
        # happy path
        p = pathlib.Path(td) / "good.json"
        p.write_text(json.dumps(good), encoding="utf-8")
        try:
            data = ad.load_decisions(str(p))
            if len(data["decisions"]) != 1:
                failures.append("schema: happy path lost a decision")
        except ad.DecisionsError as e:
            failures.append(f"schema: happy path raised {e}")


def run_hash_tests(failures):
    a = {"report_hash": HEX64, "decisions": [_d(2, "obsolete", "b"), _d(1, "duplicate", "a", duplicate_of=9)]}
    b = {"report_hash": HEX64, "decisions": [_d(1, "duplicate", "a", duplicate_of=9), _d(2, "obsolete", "b")]}
    if ad.decisions_hash(a) != ad.decisions_hash(b):
        failures.append("decisions_hash: decision order must not change the hash")
    c = {"report_hash": HEX64, "decisions": [_d(2, "obsolete", "CHANGED"), _d(1, "duplicate", "a", duplicate_of=9)]}
    if ad.decisions_hash(a) == ad.decisions_hash(c):
        failures.append("decisions_hash: a changed reason must change the hash")
    d = {"report_hash": "b" * 64, "decisions": a["decisions"]}
    if ad.decisions_hash(a) == ad.decisions_hash(d):
        failures.append("decisions_hash: a different report_hash must change the hash")
    for good in ("abc1234 — grepped src/foo.cpp:42, still gone", "deadbeefcafe: checked auth.erl", "ABCDEF0 - x"):
        if not ad.valid_verification(good):
            failures.append(f"valid_verification: {good!r} should pass")
    for bad in ("", "[x] I checked", "notahexsha — x", "abc1234", "abc1234 — "):
        if ad.valid_verification(bad):
            failures.append(f"valid_verification: {bad!r} should fail")


# ==========================================================================
# 3. apply_decisions.validate() -- every refusal (pure)

def _run(decisions, dnc=(), live_over=None, linked=None, rh_live=HEX64, report_hash=HEX64):
    live = {d["number"]: _issue(d["number"]) for d in decisions}
    for n in dnc:
        live.setdefault(n, _issue(n))
    if live_over:
        live.update(live_over)
    data = {"report_hash": report_hash, "decisions": decisions}
    return ad.validate(data, set(dnc), live, linked or {}, rh_live)


def _has(refusals, code):
    return any(code in r for r in refusals)


def run_validate_tests(failures):
    # clean -> no refusals
    if _run([_d(1, "obsolete", "stale")]) != []:
        failures.append("validate: clean case must return no refusals")

    # R1 cap
    if not _has(_run([_d(n) for n in range(1, 12)]), "R1"):
        failures.append("validate R1: >10 decisions must refuse")
    # R1 repeat
    if not _has(_run([_d(1), _d(1)]), "R1"):
        failures.append("validate R1: repeated number must refuse")

    # R2 file
    if not _has(_run([_d(520)], dnc={520}, live_over={520: _issue(520)}), "R2"):
        failures.append("validate R2: do-not-close.txt number must refuse")
    # R2 label
    if not _has(_run([_d(7)], live_over={7: _issue(7, labels=["bug", "do-not-close"])}), "R2"):
        failures.append("validate R2: do-not-close label must refuse")

    # R3 security wrong category
    if not _has(_run([_d(7, "obsolete")], live_over={7: _issue(7, labels=["bug", "security"])}), "R3"):
        failures.append("validate R3: security in a judgment category must refuse")
    # R3 security missing verification
    if not _has(_run([_d(7, "fixed-elsewhere", "gone")],
                     live_over={7: _issue(7, labels=["bug", "security"])}), "R3"):
        failures.append("validate R3: security without verified_gone_at must refuse")
    # R3 security OK path (fixed-elsewhere + typed verification) -> allowed
    ok = _run([_d(7, "fixed-elsewhere", "gone", verified_gone_at="abc1234 — grepped x.cpp, gone")],
              live_over={7: _issue(7, labels=["bug", "security"])})
    if ok != []:
        failures.append(f"validate R3: verified security fixed-elsewhere must be allowed, got {ok}")
    # R3 high-risk cap (>3)
    hr = [_d(n, "fixed-elsewhere", "gone", verified_gone_at="abc1234 — x") for n in range(1, 5)]
    over = _run(hr, live_over={n: _issue(n, labels=["P1"]) for n in range(1, 5)})
    if not any("cap of 3" in r for r in over):
        failures.append("validate R3: >3 high-risk closes must refuse")

    # R4 roadmap + judgment
    if not _has(_run([_d(7, "obsolete")], live_over={7: _issue(7, labels=["bug", "roadmap"])}), "R4"):
        failures.append("validate R4: roadmap judgment category must refuse")
    # R4 roadmap fixed-elsewhere OK
    if _has(_run([_d(7, "fixed-elsewhere", "moved")], live_over={7: _issue(7, labels=["bug", "roadmap"])}), "R4"):
        failures.append("validate R4: roadmap fixed-elsewhere must be allowed")

    # R5 assigned / linked PR
    if not _has(_run([_d(7)], live_over={7: _issue(7, assignees=["alice"])}), "R5"):
        failures.append("validate R5: assigned issue must refuse")
    if not _has(_run([_d(7)], linked={7: True}), "R5"):
        failures.append("validate R5: open linked PR must refuse")

    # R2b a PR target must be refused (the REST issues endpoint returns PRs too)
    if not any("pull request" in r for r in _run([_d(7)], live_over={7: _issue(7, is_pr=True)})):
        failures.append("validate: a pull-request target must refuse")

    # R6 not found / already closed
    if not _has(_run([_d(7)], live_over={7: None}), "R6"):
        failures.append("validate R6: 404 target must refuse")
    if not _has(_run([_d(7)], live_over={7: _issue(7, state="closed")}), "R6"):
        failures.append("validate R6: already-closed target must refuse")
    # R6b guardrail breach: a held-open dnc issue found closed
    breach = _run([_d(1)], dnc={520}, live_over={520: _issue(520, state="closed")})
    if not any("GUARDRAIL BREACH" in r for r in breach):
        failures.append("validate R6b: a closed do-not-close.txt issue must shout")

    # R7 report hash
    if not _has(_run([_d(1)], rh_live=None), "R7"):
        failures.append("validate R7: no live report must refuse")
    if not _has(_run([_d(1)], rh_live="b" * 64), "R7"):
        failures.append("validate R7: report_hash mismatch must refuse")

    # duplicate needs a survivor
    if not any("duplicate_of" in r for r in _run([_d(1, "duplicate", "dup")])):
        failures.append("validate: duplicate without duplicate_of must refuse")
    if _run([_d(1, "duplicate", "dup", duplicate_of=9)],
            live_over={1: _issue(1)}) != []:
        failures.append("validate: duplicate with a valid duplicate_of must pass")

    # unknown category
    if not any("unknown category" in r for r in _run([_d(1, "frobnicate")])):
        failures.append("validate: unknown category must refuse")


# ==========================================================================
# 3b. apply flow (dry-run/execute snapshot) + revert, via a fake gh

class _FakeGh:
    """Path-dispatching fake for close_linked_issues.gh_api covering the calls
    mode_apply makes. Records POST/PATCH so the test can assert mutations
    happened only under --execute."""

    def __init__(self, issues, tracking=9000, report_hash=HEX64, linked=None, protect_after=None):
        self.issues = issues
        self.tracking = tracking
        self.report_hash = report_hash
        self.linked = linked or {}
        # protect_after[n] = (k, label): from the (k+1)-th GET of issue n onward,
        # return it carrying `label` -- simulates a never-close signal added
        # mid-run (the validate-to-close TOCTOU).
        self.protect_after = protect_after or {}
        self.get_count = {}
        self.posts, self.patches = [], []
        self.events = []  # ordered ('PATCH'|'POST', n) log, to assert close-before-comment
        self._saved = {}

    def __enter__(self):
        self._saved = {"gh_api": cli.gh_api, "has_open_linked_pr": cli.has_open_linked_pr,
                       "MUTATION_SLEEP_S": cli.MUTATION_SLEEP_S}
        cli.gh_api = self._gh
        cli.has_open_linked_pr = lambda n: self.linked.get(n, False)
        cli.MUTATION_SLEEP_S = 0  # gh is mocked; don't sleep through the real throttle
        return self

    def __exit__(self, *exc):
        for k, v in self._saved.items():
            setattr(cli, k, v)

    def _gh(self, path, *args, method="GET", paginate=False):
        rid = re.escape(cli.REPO)
        if path == f"repos/{cli.REPO}/issues" and any("labels=triage-sweep" in a for a in args):
            return [{"number": self.tracking}]
        if path == f"repos/{cli.REPO}/issues/{self.tracking}/comments" and method == "GET":
            return [{"user": {"login": cli.TRUSTED_BOT}, "author_association": "MEMBER",
                     "created_at": "2026-07-15T00:00:00Z",
                     "body": f"report <!-- yuzu-tracker-report: hash={self.report_hash} run=r -->"}]
        m = re.fullmatch(rf"repos/{rid}/issues/(\d+)", path)
        if m and method == "GET":
            n = int(m.group(1))
            self.get_count[n] = self.get_count.get(n, 0) + 1
            base = self.issues.get(n)
            if base and n in self.protect_after and self.get_count[n] > self.protect_after[n][0]:
                return {**base, "labels": base.get("labels", []) + [{"name": self.protect_after[n][1]}]}
            return base
        if m and method == "PATCH":
            n = int(m.group(1))
            self.patches.append((n, args))
            self.events.append(("PATCH", n))
            return {}
        m = re.fullmatch(rf"repos/{rid}/issues/(\d+)/comments", path)
        if m and method == "POST":
            n = int(m.group(1))
            self.posts.append((n, args))
            self.events.append(("POST", n))
            return {}
        m = re.fullmatch(rf"repos/{rid}/issues/(\d+)/labels", path)
        if m and method == "POST":
            return {}
        raise AssertionError(f"unexpected gh path {path} method={method} args={args}")


def run_apply_flow_tests(failures):
    real = cli.DNC_PATH
    # The meson docs suite runs under GITHUB_ACTIONS on CI runners; clear the
    # bot-context vars so the execute tests below aren't refused by COMP-2 (a
    # dedicated case re-sets GITHUB_ACTIONS to test that refusal).
    _bot_env = {v: os.environ.pop(v, None) for v in ("GITHUB_ACTIONS", "CI", "GITHUB_RUN_ID")}
    try:
        with tempfile.TemporaryDirectory() as td:
            cli.DNC_PATH = pathlib.Path(td) / "do-not-close.txt"
            cli.DNC_PATH.write_text("999\n", encoding="utf-8")
            decisions = {"report_hash": HEX64,
                         "decisions": [_d(11, "obsolete", "superseded"),
                                       _d(12, "duplicate", "dup", duplicate_of=11)]}
            dfile = pathlib.Path(td) / "decisions.json"
            dfile.write_text(json.dumps(decisions), encoding="utf-8")
            snap = pathlib.Path(td) / "snap.json"
            issues = {11: _issue(11, labels=["bug"]), 12: _issue(12, labels=["bug"])}

            # dry-run: writes snapshot, mutates nothing
            with _FakeGh(issues) as fg:
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    rc = ad.mode_apply(str(dfile), str(snap), execute=False)
                if rc != 0:
                    failures.append(f"apply dry-run: rc={rc} want 0")
                if fg.patches or fg.posts:
                    failures.append(f"apply dry-run: must not mutate (patches={fg.patches}, posts={fg.posts})")
            if not snap.exists():
                failures.append("apply dry-run: snapshot not written")

            # execute: closes both, posts ledger + 2 evidence comments
            with _FakeGh(issues) as fg:
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    rc = ad.mode_apply(str(dfile), str(snap), execute=True)
                if rc != 0:
                    failures.append(f"apply execute: rc={rc} want 0")
                closed = {n for n, _a in fg.patches}
                if closed != {11, 12}:
                    failures.append(f"apply execute: closed {closed} want {{11, 12}}")
                # ledger to tracking issue + one evidence comment per closed issue
                commented = [n for n, _a in fg.posts]
                if 9000 not in commented:
                    failures.append("apply execute: no ledger comment on the tracking issue")
                if commented.count(11) != 1 or commented.count(12) != 1:
                    failures.append(f"apply execute: evidence comments {commented} want one each on 11,12")
                # ledger must be posted BEFORE the first close (order load-bearing)
                if fg.posts[0][0] != 9000:
                    failures.append("apply execute: ledger must be the FIRST post (before any close)")

            # execute without a matching snapshot -> refuse (exit 2)
            missing = pathlib.Path(td) / "missing.json"
            with _FakeGh(issues):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    rc = ad.mode_apply(str(dfile), str(missing), execute=True)
                if rc != 2:
                    failures.append(f"apply execute w/o snapshot: rc={rc} want 2")

            # drift: snapshot from a different decision list -> refuse (exit 4)
            other = {"report_hash": HEX64, "decisions": [_d(11, "too-trivial", "different")]}
            snap.write_text(json.dumps({"decisions_hash": ad.decisions_hash(other)}), encoding="utf-8")
            with _FakeGh(issues):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    rc = ad.mode_apply(str(dfile), str(snap), execute=True)
                if rc != 4:
                    failures.append(f"apply execute drift: rc={rc} want 4")

            # a refusal (security w/o verification) -> exit 4, no snapshot consulted
            bad = {"report_hash": HEX64, "decisions": [_d(11, "obsolete", "x")]}
            bfile = pathlib.Path(td) / "bad.json"
            bfile.write_text(json.dumps(bad), encoding="utf-8")
            with _FakeGh({11: _issue(11, labels=["bug", "security"])}) as fg:
                with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                    rc = ad.mode_apply(str(bfile), str(snap), execute=True)
                if rc != 4 or fg.patches:
                    failures.append(f"apply refusal: rc={rc} want 4, patches={fg.patches}")

            # malformed snapshot on --execute -> exit 4 (fail-closed), not a crash/exit 1
            snap.write_text("{not valid json", encoding="utf-8")
            with _FakeGh(issues) as fg:
                with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                    rc = ad.mode_apply(str(dfile), str(snap), execute=True)
                if rc != 4 or fg.patches:
                    failures.append(f"apply malformed snapshot: rc={rc} want 4, patches={fg.patches}")

            # TOCTOU: a never-close signal added AFTER the reviewed dry-run (the
            # pre-mutation re-validation must abort with zero mutations). Snapshot
            # matches the decision list; #11 gains do-not-close on its 2nd GET
            # (initial validate passes on GET #1, re-validate refuses on GET #2).
            snap.write_text(json.dumps({"decisions_hash": ad.decisions_hash(decisions)}), encoding="utf-8")
            with _FakeGh(issues, protect_after={11: (1, "do-not-close")}) as fg:
                with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                    rc = ad.mode_apply(str(dfile), str(snap), execute=True)
                if rc != 4 or fg.patches:
                    failures.append(f"apply TOCTOU (batch revalidation): rc={rc} want 4, patches={fg.patches}")

            # TOCTOU in the residual window: #11 stays clean through BOTH batch
            # validations (GET 1 and 2) and only gains do-not-close on GET 3 --
            # the per-issue re-check right before the close PATCH must abort
            # (sys.exit(4)) with no PATCH sent.
            with _FakeGh(issues, protect_after={11: (2, "do-not-close")}) as fg:
                try:
                    with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                        ad.mode_apply(str(dfile), str(snap), execute=True)
                    failures.append("apply TOCTOU (per-issue): expected SystemExit(4)")
                except SystemExit as e:
                    if e.code != 4 or fg.patches:
                        failures.append(f"apply TOCTOU (per-issue): code={e.code} want 4, patches={fg.patches}")

            # CA-2: a roadmap label added in the residual window blocks a judgment
            # close (roadmap is fixed-elsewhere-only) via the per-issue guard.
            with _FakeGh(issues, protect_after={11: (2, "roadmap")}) as fg:
                try:
                    with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                        ad.mode_apply(str(dfile), str(snap), execute=True)
                    failures.append("apply TOCTOU (roadmap): expected SystemExit(4)")
                except SystemExit as e:
                    if e.code != 4 or fg.patches:
                        failures.append(f"apply TOCTOU (roadmap): code={e.code} want 4, patches={fg.patches}")

            # QE-1(a): #11 gains `security` under a judgment category mid-run ->
            # per-issue guard blocks (sys.exit 4, no PATCH).
            with _FakeGh(issues, protect_after={11: (2, "security")}) as fg:
                try:
                    with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                        ad.mode_apply(str(dfile), str(snap), execute=True)
                    failures.append("apply TOCTOU (security judgment): expected SystemExit(4)")
                except SystemExit as e:
                    if e.code != 4 or fg.patches:
                        failures.append(f"apply TOCTOU (security judgment): code={e.code} want 4, patches={fg.patches}")

            # QE-1(b): #21 gains `security` mid-run but IS a verified fixed-elsewhere
            # -> the exception holds, it still closes.
            fe = {"report_hash": HEX64,
                  "decisions": [_d(21, "fixed-elsewhere", "landed in #99",
                                   verified_gone_at="abc1234 — grepped src/x.cpp, gone")]}
            fefile = pathlib.Path(td) / "fe.json"
            fefile.write_text(json.dumps(fe), encoding="utf-8")
            fesnap = pathlib.Path(td) / "fesnap.json"
            fesnap.write_text(json.dumps({"decisions_hash": ad.decisions_hash(fe)}), encoding="utf-8")
            with _FakeGh({21: _issue(21, labels=["bug"])}, protect_after={21: (2, "security")}) as fg:
                with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                    rc = ad.mode_apply(str(fefile), str(fesnap), execute=True)
                if rc != 0 or {n for n, _a in fg.patches} != {21}:
                    failures.append(f"apply verified-security fixed-elsewhere: rc={rc} patches={fg.patches} want close #21")

            # QE-3: for each closed issue, its close PATCH must precede its own
            # evidence-comment POST (comment-first would strand the marker).
            with _FakeGh(issues) as fg:
                with contextlib.redirect_stdout(io.StringIO()):
                    ad.mode_apply(str(dfile), str(snap), execute=True)
                for n in (11, 12):
                    seq = [ev for ev in fg.events if ev[1] == n]
                    if seq != [("PATCH", n), ("POST", n)]:
                        failures.append(f"ordering: #{n} events {seq} want [PATCH, POST]")

            # UP-4: an empty decisions list closes nothing and posts no ledger.
            empty = pathlib.Path(td) / "empty.json"
            empty.write_text(json.dumps({"report_hash": HEX64, "decisions": []}), encoding="utf-8")
            with _FakeGh(issues) as fg:
                with contextlib.redirect_stdout(io.StringIO()):
                    rc = ad.mode_apply(str(empty), str(snap), execute=True)
                if rc != 0 or fg.posts or fg.patches:
                    failures.append(f"empty decisions: rc={rc} posts={fg.posts} patches={fg.patches} want no-op 0")

            # COMP-2: --execute under a CI/bot token refuses (exit 4, zero mutations).
            _saved_env = os.environ.get("GITHUB_ACTIONS")
            os.environ["GITHUB_ACTIONS"] = "true"
            try:
                with _FakeGh(issues) as fg:
                    with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                        rc = ad.mode_apply(str(dfile), str(snap), execute=True)
                    if rc != 4 or fg.patches:
                        failures.append(f"bot-context execute: rc={rc} want 4, patches={fg.patches}")
            finally:
                os.environ.pop("GITHUB_ACTIONS", None)
    finally:
        cli.DNC_PATH = real
        for _v, _val in _bot_env.items():
            if _val is not None:
                os.environ[_v] = _val


def run_marker_hygiene_tests(failures):
    # An operator reason containing HTML-comment delimiters must not disturb the
    # decision marker: the rendered comment must carry exactly one <!-- and -->,
    # and the marker substring must survive intact.
    d = _d(5, "fixed-elsewhere", "fixed <!-- sneaky --> here", verified_gone_at="abc1234 --> x")
    c = ad.decision_comment(d, "run123abc")
    if c.count("<!--") != 1 or c.count("-->") != 1:
        failures.append(f"marker hygiene: want one <!-- and one -->, got {c.count('<!--')}/{c.count('-->')}")
    if ad.DECISION_MARKER.format(run="run123abc", issue=5) not in c:
        failures.append("marker hygiene: decision marker substring must survive sanitization")


def run_revert_tests(failures):
    real = cli.DNC_PATH
    saved = {k: getattr(cli, k) for k in
             ("gh_api", "issue_with_comments", "post_comment", "add_label", "MUTATION_SLEEP_S")}
    cli.MUTATION_SLEEP_S = 0  # gh is mocked; skip the real throttle
    saved_find = report.find_tracking_issue
    try:
        with tempfile.TemporaryDirectory() as td:
            cli.DNC_PATH = pathlib.Path(td) / "do-not-close.txt"
            cli.DNC_PATH.write_text("999\n", encoding="utf-8")
            run_id = "abc123def456"
            ledger_body = (f"### Tracker decision ledger — run `{run_id}`\n\n"
                           f"- #70 — obsolete → not_planned\n- #71 — duplicate → not_planned\n"
                           f"- #72 — obsolete → not_planned\n\n"
                           f"<!-- yuzu-tracker-ledger: run={run_id} -->")
            report.find_tracking_issue = lambda: {"number": 9000}
            patches = []

            def fake_gh(path, *args, method="GET", paginate=False):
                if path == f"repos/{cli.REPO}/issues/9000/comments":
                    return [{"user": {"login": "operator"}, "author_association": "COLLABORATOR",
                             "body": ledger_body}]
                if re.fullmatch(rf"repos/{re.escape(cli.REPO)}/issues/\d+", path) and method == "PATCH":
                    patches.append(int(path.rsplit("/", 1)[1]))
                    return {}
                raise AssertionError(f"unexpected gh path {path} {method}")

            # #70 closed with a trusted decision marker (revertible);
            # #71 closed but marker absent (not ours); #72 already open.
            blobs = {
                70: (_issue(70, state="closed"),
                     f"<!-- yuzu-tracker-decision: run={run_id} issue=70 -->"),
                71: (_issue(71, state="closed"), "no marker here"),
                72: (_issue(72, state="open"),
                     f"<!-- yuzu-tracker-decision: run={run_id} issue=72 -->"),
            }
            cli.gh_api = fake_gh
            cli.issue_with_comments = lambda n: blobs[n]
            cli.post_comment = lambda n, body, execute: None
            cli.add_label = lambda n, label, execute: None

            # QE-4: revert DRY-RUN reopens nothing but reports the would-reopen.
            dout = io.StringIO()
            with contextlib.redirect_stdout(dout):
                drc = ad.mode_revert(run_id, execute=False)
            dtext = dout.getvalue()
            if drc != 0 or patches:
                failures.append(f"revert dry-run: rc={drc} patches={patches} want 0 / no PATCH")
            if "would reopen #70" not in dtext or "DRY-RUN" not in dtext:
                failures.append(f"revert dry-run: must report would-reopen #70 + DRY-RUN banner; got {dtext!r}")

            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = ad.mode_revert(run_id, execute=True)
            text = out.getvalue()
            if rc != 0:
                failures.append(f"revert: rc={rc} want 0")
            if patches != [70]:
                failures.append(f"revert: reopened {patches} want [70] (marker-verified only)")
            if "not ours" not in text:
                failures.append("revert: #71 (no marker) must be reported as not-ours")

            # an unknown run id -> GhError
            try:
                ad.mode_revert("nosuchrun", execute=False)
                failures.append("revert: unknown run id must raise")
            except cli.GhError:
                pass
    finally:
        cli.DNC_PATH = real
        for k, v in saved.items():
            setattr(cli, k, v)
        report.find_tracking_issue = saved_find


# ==========================================================================
# 4. Governance-round coverage (SG-1 ReDoS, CA-1 hygiene exempt, QE-2/4/5, SRE render)

def run_redos_test(failures):
    # SG-1: a pathological no-terminal-extension body must complete fast and
    # yield no paths (the old lazy/greedy regex backtracked cubically here).
    body = "a/" * 8000  # 16 KB of slash segments, no `name.ext`
    t0 = time.time()
    paths = report._cited_paths(body)
    dt = time.time() - t0
    if dt > 2.0:
        failures.append(f"ReDoS: _cited_paths took {dt:.2f}s on a pathological body (want < 2s)")
    if paths:
        failures.append(f"ReDoS: no-extension body must yield no paths, got {sorted(paths)[:3]}")
    if report._cited_paths("see src/core/auth.cpp:42 here") != {"src/core/auth.cpp"}:
        failures.append("ReDoS fix regressed real path extraction")


def run_hygiene_exempt_test(failures):
    # CA-1: the workflow's own bookkeeping issues (triage-sweep tracking issue,
    # automation-broken alert) must be exempt from hygiene, not self-flagged.
    if any(n == 9000 for n, _p in report.label_hygiene([_issue(9000, labels=["triage-sweep"])], set())):
        failures.append("hygiene: triage-sweep tracking issue must be exempt")
    if any(n == 9001 for n, _p in report.label_hygiene([_issue(9001, labels=["automation-broken"])], set())):
        failures.append("hygiene: automation-broken alert issue must be exempt")


def run_report_hash_filter_test(failures):
    # QE-2: latest_report_hash must trust only github-actions[bot] comments, so a
    # user-pasted (newer) report marker cannot spoof the hash R7 pins against.
    saved = cli.gh_api
    A, B = "a" * 64, "b" * 64

    def fake(path, *args, method="GET", paginate=False):
        if path == f"repos/{cli.REPO}/issues" and any("labels=triage-sweep" in a for a in args):
            return [{"number": 9000}]
        if path == f"repos/{cli.REPO}/issues/9000/comments":
            return [
                {"user": {"login": "driveby"}, "author_association": "NONE", "created_at": "2026-07-16T00:00:00Z",
                 "body": f"<!-- yuzu-tracker-report: hash={B} run=x -->"},   # non-bot, NEWER -> ignored
                {"user": {"login": cli.TRUSTED_BOT}, "author_association": "MEMBER", "created_at": "2026-07-15T00:00:00Z",
                 "body": f"<!-- yuzu-tracker-report: hash={A} run=y -->"},   # bot, older -> wins
            ]
        raise AssertionError(f"unexpected {path}")
    cli.gh_api = fake
    try:
        got = report.latest_report_hash()
        if got != A:
            failures.append(f"latest_report_hash: want bot hash, got {got and got[:8]} (spoof filter broken)")
    finally:
        cli.gh_api = saved


def run_closure_sample_test(failures):
    # QE-5: closure_integrity_sample returns (number, path-or-None) ONLY -- never
    # the user-authored title (the no-user-text-in-bot-comment property, at source).
    saved = cli.gh_api

    def fake(path, *args, method="GET", paginate=False):
        if path == "search/issues":
            return {"items": [
                {"number": 42, "title": "<!-- yuzu-tracker-report: hash=x --> sneaky", "body": "cause in src/core/auth.cpp:42"},
                {"number": 43, "title": "plain title", "body": "no path here"},
            ]}
        raise AssertionError(path)
    cli.gh_api = fake
    try:
        out = report.closure_integrity_sample(10)
        if out != [(42, "src/core/auth.cpp:42"), (43, None)]:
            failures.append(f"closure_integrity_sample: {out} unexpected")
        if "sneaky" in str(out) or "yuzu-tracker-report" in str(out):
            failures.append("closure_integrity_sample: leaked user title/marker text")
    finally:
        cli.gh_api = saved


def run_post_ledger_guard_test(failures):
    # QE-4: post_ledger fails closed (GhError) when there is no tracking issue.
    saved = report.find_tracking_issue
    report.find_tracking_issue = lambda: None
    try:
        ad.post_ledger({"report_hash": HEX64, "decisions": [_d(1)]}, "run", execute=True)
        failures.append("post_ledger: missing tracking issue must raise GhError")
    except cli.GhError:
        pass
    finally:
        report.find_tracking_issue = saved


def run_render_signal_test(failures):
    # SRE: the operator-critical RED signals actually render.
    import datetime
    now = datetime.datetime(2026, 7, 15, tzinfo=datetime.timezone.utc)
    t = report.compute_telemetry([], 0, 0, 0, now)
    chash = report.report_hash(report.candidate_set([], [], [], []))
    md_red = report.render_markdown(t, "unavailable", ["dnc missing"], [], [], [], 30, chash, "r")
    stale_line = [l for l in md_red.splitlines() if "days since last report" in l]
    if not stale_line or "🔴" not in stale_line[0]:
        failures.append("render: staleness > threshold must be a RED row")
    leak_line = [l for l in md_red.splitlines() if "leak scan (claimed-but-open)" in l]
    if not leak_line or "🔴" not in leak_line[0]:
        failures.append("render: unavailable leak scan must be a RED telemetry row")
    if "UNAVAILABLE" not in md_red:
        failures.append("render: unavailable leak scan must render UNAVAILABLE")
    md_first = report.render_markdown(t, "ok", [], [], [], [], None, chash, "r")
    if "first run" not in md_first:
        failures.append("render: staleness None must show 'first run'")


# ==========================================================================

def main() -> int:
    failures = []
    run_telemetry_tests(failures)
    run_hygiene_tests(failures)
    run_duplicate_tests(failures)
    run_report_hash_tests(failures)
    run_leak_scan_tests(failures)
    run_schema_tests(failures)
    run_hash_tests(failures)
    run_validate_tests(failures)
    run_apply_flow_tests(failures)
    run_marker_hygiene_tests(failures)
    run_revert_tests(failures)
    run_redos_test(failures)
    run_hygiene_exempt_test(failures)
    run_report_hash_filter_test(failures)
    run_closure_sample_test(failures)
    run_post_ledger_guard_test(failures)
    run_render_signal_test(failures)
    if failures:
        print(f"tracker checks FAILED ({len(failures)}):")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("tracker checks OK (telemetry, hygiene, duplicates, report-hash, leak-scan, "
          "schema, decisions-hash, validate R1-R7 + PR-refusal, apply dry-run/execute/drift/"
          "malformed-snapshot/TOCTOU x4/bot-context/empty, marker-hygiene, revert dry+exec, "
          "ReDoS, hygiene-exempt, bot-hash-filter, closure-no-title, ledger-guard, render-signals)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
