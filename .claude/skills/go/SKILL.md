---
name: go
description: Full autonomous PR review pipeline for Yuzu. Sets up an isolated worktree at the PR head with the shared vcpkg toolchain symlinked, runs static analysis (clang-tidy, dialyzer), builds and tests locally, runs an adversarial Kimi-vs-Codex review, posts the verdict (APPROVE or REQUEST_CHANGES) to GitHub with findings as inline comments, then monitors the PR in the background and re-reviews new commits until resolved. Use when the user types "go PR<number>", "go <number>", or "/go PR<number>".
---

# go — full PR review pipeline

`go PR<n>` = worktree + toolchain + static analysis + build/test + adversarial review (Kimi vs
Codex) + posted GitHub review with inline comments + background monitor/re-review loop. You are the
orchestrator. The adversarial-review skill's "read-and-report only" guardrail is **lifted here by
design**: posting the review IS this pipeline's deliverable (Stage 5) — the operator authorized it
by invoking the alias. Reviewers themselves still never post; only you do, at Stage 5.

## Stage 0 — Resolve & preflight (inline, fast)

1. Parse `<n>` from the args (`PR1871`, `1871`, `#1871` all valid).
2. `gh pr view <n> --json title,headRefOid,baseRefName,state,isCrossRepository,author,url` — abort
   politely if not OPEN.
3. **Fork PR?** If `isCrossRepository: true`, the CI matrix never ran — the review body MUST lead
   with "re-open in-repo" and never claim CI green (standing rule).
4. **Own PR?** `gh api user -q .login` — GitHub rejects APPROVE/REQUEST_CHANGES on your own PR; if
   author == you, Stage 5 degrades to `event=COMMENT` with the verdict in the body. Say so up front.
5. CLIs: `codex login status` says "Logged in"; `command -v kimi`. If either is missing/unauthed,
   tell the operator (interactive login — they must run it) and offer the Claude-vs-Codex fallback.
6. **ANCHORS:** pick from the CLAUDE.md routing table per the PR's changed files (everything gets
   `CLAUDE.md` + `docs/agentic-first-principle.md`). If genuinely ambiguous, proceed with the routing
   table's picks and list them in the posted review so the operator can contest.

## Stage 1 — Worktree + toolchain

```bash
git -C /Users/nathan/Yuzu fetch origin pull/<n>/head
WT=/Users/nathan/Yuzu-wt-pr<n>
git -C /Users/nathan/Yuzu worktree add --detach "$WT" FETCH_HEAD
ln -s /Users/nathan/Yuzu/vcpkg_installed "$WT/vcpkg_installed"   # NEVER run setup.sh in a worktree
echo vcpkg_installed >> "$(git -C "$WT" rev-parse --git-path info/exclude)"
```

Fresh `meson setup "$WT/build-macos"` **in the worktree** (never reuse/symlink the main build dir —
recorded absolute source path breaks it). Mirror the main checkout's options via
`meson introspect /Users/nathan/Yuzu/build-macos --buildoptions` (same `cmake_prefix_path`, ensure
`-Dbuild_tests=true`). ccache makes the compile minutes, not hours.

## Stage 2 — Static analysis

- Merge base: `MB=$(git -C "$WT" merge-base origin/<baseRefName> HEAD)`.
- Materialize the diff for the reviewers: `git -C "$WT" diff "$MB"..HEAD > "$REVIEW_DIR/DIFF.patch"`.
- **clang-tidy** on changed `*.cpp` via the worktree's `compile_commands.json`
  (`clang-tidy -p "$WT/build-macos" <files>`); changed headers are covered through their including
  TUs. Triage output yourself — only real findings feed the review, not style noise.
- Gateway (`gateway/` or `*.erl` changed): read `docs/erlang-gateway-build.md`, run `/gateway-dialyzer`.
- Workflows changed: run `zizmor` if installed.

## Stage 3 — Dynamic analysis (BEFORE launching reviewers — both then get to be empirical)

- `meson compile -C "$WT/build-macos"` — a broken compile is an immediate REQUEST_CHANGES; skip to Stage 5.
- Targeted suites by changed dirs (`server/core`→server, `agents/`+`sdk/`→agent, TAR→tar; unclear →
  all three): `meson test -C "$WT/build-macos" --suite <s> --print-errorlogs`. Gateway → `/gateway-eunit`.
- Optional skip-gap closure: throwaway `postgres:18` container + `YUZU_TEST_POSTGRES_DSN` for
  PG-gated server tests; `gh pr checks <n>` for the cross-platform legs.

## Stage 4 — Adversarial review: Kimi vs Codex

Follow the **protocol in `.claude/skills/adversarial-review/SKILL.md`** (Step 0 REVIEW_DIR/TARGET
conventions, phase barriers, Step 3 synthesis weighting) with these substitutions:

- Reviewer A = **Kimi**: `run-kimi-reviewer.sh --self kimi --peer codex --dynamic --repo "$WT" ...`
- Reviewer B = **Codex**: `run-codex-reviewer.sh --self codex --peer kimi --repo "$WT" ...`
- Both phases: launch both scripts concurrently via Bash `run_in_background: true`. TARGET string
  points at the worktree and `$REVIEW_DIR/DIFF.patch`.
- **Stall watchdog is output-heartbeat, not wall-clock**: healthy runs stream ~2.5–13 min; no
  summary-file growth for ~150 s while the process lives → kill + retry solo. Runners are
  idempotent — skip a phase whose file already exists.
- Known sandbox artifact: Codex `workspace-write` denies localhost binds — port-binding test
  failures (e.g. `bind_to_any_port`) are adjudicated by rerunning unsandboxed, not reported.

Synthesize per the skill's Step 3, folding Stage 2/3 results in as orchestrator evidence.
**Verdict:** any surviving CRITICAL/HIGH → `REQUEST_CHANGES`; else `APPROVED`.

## Stage 5 — Post the review

Anchor each actionable finding as an inline comment; findings that don't anchor to a diff line go
in the body (the API 422s otherwise). Build `review.json` and post in ONE call:

```json
{"commit_id": "<headRefOid>", "event": "REQUEST_CHANGES",
 "body": "<verdict, evidence summary: what compiled/ran, anchors used, coverage gaps>",
 "comments": [{"path": "server/core/src/foo.cpp", "line": 42, "side": "RIGHT",
               "body": "**HIGH** — <defect>. <minimal fix>."}]}
```

`gh api repos/Tr3kkR/Yuzu/pulls/<n>/reviews --input review.json`. Own-PR → `event=COMMENT`.
Save the machine-readable findings list to `$REVIEW_DIR/FINDINGS.md` — the re-review checks them off.

## Stage 6 — Monitor & re-review loop

- **APPROVED** → clean up (below) and finish.
- **REQUEST_CHANGES** → keep the worktree, start a background watcher (Bash `run_in_background: true`):

```bash
n=<n>; base=<reviewed headRefOid>
while sleep 180; do
  out=$(gh pr view "$n" --json headRefOid,state -q '.headRefOid+" "+.state') || continue
  [ "$out" != "$base OPEN" ] && { echo "$out"; exit 0; }
done
```

On wake: PR closed/merged → report + clean up. New head → in the worktree
`git fetch origin pull/<n>/head && git checkout FETCH_HEAD`, incremental recompile + affected
suites, re-run the Kimi/Codex pair on the **delta** (`<old-head>..<new-head>`) with
`$REVIEW_DIR/FINDINGS.md` in the TARGET framing ("verify each prior finding is addressed; review the
delta for new defects"). Post the follow-up review (APPROVE when everything is resolved, else
REQUEST_CHANGES with the remaining/new findings) and re-arm the watcher. Repeat until approved,
closed, or the operator stops it.

## Cleanup (mandatory pairing)

`rm "$WT/vcpkg_installed"` (the symlink!) **BEFORE** `git worktree remove "$WT"` — a leftover
symlink can let worktree removal recurse into the real shared deps. Then
`git -C /Users/nathan/Yuzu worktree prune`. Also remove `$REVIEW_DIR` only after the final report —
it is the audit trail while the loop runs.
