#!/usr/bin/env python3
"""Frozen regression corpus for the tracker close automation (ADR-3001 A1 §11-§12).

Two surfaces, no network:

1. The parser (scripts/tracker/closing_refs.py) against a fixture corpus of
   REAL merged-PR body fragments -- including PR #1711, the canonical negated
   case ("does **not** close #1634"): the single most load-bearing line in
   this file. The grammar was acceptance-tested once against GitHub's own
   oracle (closingIssuesReferences on all 72 merged main-base PRs: zero false
   negatives; supersets limited to one chain + one already-closed ref); this
   corpus keeps it from regressing without the network.

2. The decision ladder (close_linked_issues.classify + load_do_not_close):
   never-close signals, idempotency markers, the fail-closed contract on a
   missing/broken do-not-close.txt, and the per-PR cap boundary.

Wired into tests/meson.build (suite: docs). Meson coverage is structurally
sufficient here: everything this test guards lives under scripts/, which is
code-side for the CI docs-only gate, so any PR that can break the parser also
runs the heavy platform jobs. Run locally as
`python tests/test_close_automation.py`.
"""

import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts" / "tracker"))

import closing_refs  # noqa: E402
import close_linked_issues as cli  # noqa: E402

# --------------------------------------------------------------------------
# 1. Parser corpus: (name, body fragment, expected same-repo closing numbers)

PARSER_CORPUS = [
    # -- real bodies (verbatim fragments from merged Tr3kkR/Yuzu PRs) --------
    ("PR #1711 negated (MANDATORY negative)",
     "Hardening for the response/execution read surface (#1634, **partial** — does **not** close #1634).",
     []),
    ("PR #1711 second negation",
     "**So this does NOT bound a normal operator's responses to their management groups and does NOT close the cross-operator read #1634 describes.**",
     []),
    ("PR #795 two-ref chain", "Closes #520, #630.", [520, 630]),
    ("PR #736 keyword chain (GitHub honoured only #618)",
     "- **Auth persistence** — SQLite-backed AuthDB (fixes #618, #388, #527)",
     [618, 388, 527]),
    ("PR #373 parenthetical", "erlang ci-gateway 27 → 28 (closes #334)", [334]),
    ("PR #2074 explicit-partial (ladder protects, parser matches)",
     "Closes #2011 (lock half).", [2011]),
    ("PR #2051 resolves-by-policy (ladder protects, parser matches)",
     "Guardian Stage-2 enforce on the **queued** tier (resolves #2014 by policy)", [2014]),
    ("keyword without adjacent ref does not fire",
     "closes roadmap 8.1; #253, #587, #589", []),
    # -- grammar edges -------------------------------------------------------
    ("chain with and", "fixes #1, #2 and #3", [1, 2, 3]),
    ("colon form", "Resolves: #41", [41]),
    ("GH- form", "closed GH-77", [77]),
    ("URL form", "Fixes https://github.com/Tr3kkR/Yuzu/issues/612", [612]),
    ("same-repo qualified", "Closes Tr3kkR/Yuzu#99", [99]),
    ("cross-repo excluded", "Closes octo/kit#5 and fixes other/repo#6", []),
    ("newline between keyword and ref", "Closes\n#61", [61]),
    ("negation stops at contrast", "This does not fix #12, but closes #13", [13]),
    ("negation stops at sentence", "Won't fix #31. Closes #32", [32]),
    ("fenced code suppressed", "```\nCloses #55\n```", []),
    ("inline code suppressed", "run `git commit -m 'closes #56'`", []),
    ("blockquote suppressed", "> the old PR said closes #57", []),
    ("html comment suppressed", "<!-- closes #58 -->", []),
    ("relates-to never fires", "Relates to #99. Part of #98.", []),
    ("no leading zeros / no #0", "Fixed #0 and #012", []),
    ("dedupe preserves order", "Closes #5, #4, #5", [5, 4]),
]


def run_parser_corpus(failures):
    for name, body, want in PARSER_CORPUS:
        got = closing_refs.closing_numbers(body)
        if got != want:
            failures.append(f"parser: {name}: want {want}, got {got}")


# --------------------------------------------------------------------------
# 2. Decision-ladder unit tests (pure, no network)

def _issue(n, state="open", labels=(), assignees=(), is_pr=False):
    d = {
        "number": n,
        "state": state,
        "title": f"issue {n}",
        "labels": [{"name": l} for l in labels],
        "assignees": [{"login": a} for a in assignees],
    }
    if is_pr:
        d["pull_request"] = {}
    return d


def run_ladder_tests(failures):
    dnc = {318, 1634}
    cases = [
        # (name, issue, pr, comments_blob, expected action)
        ("404", None, 100, "", cli.SKIP),
        ("self-ref", _issue(100), 100, "", cli.SKIP),
        ("is a PR", _issue(7, is_pr=True), 100, "", cli.SKIP),
        ("already closed", _issue(7, state="closed"), 100, "", cli.SKIP),
        ("close marker idempotent", _issue(7), 100,
         "<!-- yuzu-close-linked: pr=100 issue=7 -->", cli.SKIP),
        ("security label -> advisory", _issue(7, labels=["bug", "security"]), 100, "", cli.ADVISORY),
        ("do-not-close label -> advisory", _issue(7, labels=["do-not-close"]), 100, "", cli.ADVISORY),
        ("in dnc file -> advisory", _issue(1634), 100, "", cli.ADVISORY),
        ("advisory marker idempotent", _issue(1634), 100,
         "<!-- yuzu-close-linked-advisory: pr=100 issue=1634 -->", cli.SKIP),
        ("assigned -> advisory", _issue(7, assignees=["alice"]), 100, "", cli.ADVISORY),
        ("plain open issue -> close", _issue(7, labels=["bug", "P2"]), 100, "", cli.CLOSE),
    ]
    for name, issue, pr, blob, want in cases:
        got, _reason = cli.classify(issue, pr, dnc, blob)
        if got != want:
            failures.append(f"ladder: {name}: want {want}, got {got}")


def run_dnc_failclosed_tests(failures):
    real = cli.DNC_PATH
    try:
        with tempfile.TemporaryDirectory() as td:
            # missing file
            cli.DNC_PATH = pathlib.Path(td) / "do-not-close.txt"
            for content, label in [
                (None, "missing file"),
                ("garbage-line\n", "unparseable line"),
                ("# comments only\n", "empty set"),
                ("0318\n", "leading zero"),
            ]:
                if content is not None:
                    cli.DNC_PATH.write_text(content, encoding="utf-8")
                try:
                    cli.load_do_not_close()
                    failures.append(f"fail-closed: {label}: expected GhError, got success")
                except cli.GhError:
                    pass
                if content is None:
                    cli.DNC_PATH = pathlib.Path(td) / "do-not-close.txt"  # still missing
            # happy path
            cli.DNC_PATH.write_text("318  # live vuln\n1634 # partial\n", encoding="utf-8")
            got = cli.load_do_not_close()
            if got != {318, 1634}:
                failures.append(f"fail-closed: happy path parsed {got}")
    finally:
        cli.DNC_PATH = real


def run_cap_tests(failures):
    six = " ".join(f"closes #{n}" for n in range(1, 7))
    seven = " ".join(f"closes #{n}" for n in range(1, 8))
    if len(closing_refs.closing_numbers(six)) > cli.PER_PR_CAP:
        failures.append("cap: 6 refs must be within the cap")
    if not len(closing_refs.closing_numbers(seven)) > cli.PER_PR_CAP:
        failures.append("cap: 7 refs must exceed the cap")


def main() -> int:
    failures = []
    run_parser_corpus(failures)
    run_ladder_tests(failures)
    run_dnc_failclosed_tests(failures)
    run_cap_tests(failures)
    if failures:
        print(f"close-automation checks FAILED ({len(failures)}):")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(
        f"close-automation checks OK "
        f"({len(PARSER_CORPUS)} parser cases, 11 ladder cases, fail-closed + cap)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
