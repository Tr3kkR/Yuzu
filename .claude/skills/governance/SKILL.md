---
name: governance
description: Run the Yuzu full governance pipeline on a commit range. Produces Gate 1 Change Summary, then orchestrates Gates 2-6 as parallel agent fan-outs with pre-written prompt preambles. Use when the user says "/governance <range>" or "full governance" or asks to run the multi-gate review pipeline on a PR/commit set.
---

# governance

Runbook for the full Yuzu governance pipeline defined in CLAUDE.md. This skill is a prompt-writing shortcut — it does not fully automate the run because Claude still has to make judgment calls (which Gate 3 domain agents are triggered, whether Gate 5 runs, how to consolidate findings, when to iterate). What it does is cut the per-run prompt-writing overhead by pre-composing the preambles and output contracts each agent needs.

## Usage

```
/governance <commit-range>
```

Examples:
- `/governance HEAD~4..HEAD` — last four commits
- `/governance origin/main..HEAD` — everything ahead of main
- `/governance 82f7eb8..9c50bce` — a specific PR range
- `/governance HEAD` — single-commit review (shorthand, treated as `HEAD~1..HEAD`)

If no range is provided, default to `origin/main..HEAD`.

## Workflow summary

```
Gate 1 — Change Summary (YOU write this from git diff/log)
Gate 2 — security-guardian + docs-writer           (parallel, mandatory)
Gate 3 — domain-triggered agents                   (parallel, decision matrix below)
Gate 4 — happy-path + unhappy-path + consistency   (parallel, mandatory)
Gate 5 — chaos-injector                            (conditional on Gate 4)
Gate 6 — compliance + sre + enterprise-readiness   (parallel, mandatory)
Gate 7 — address BLOCKING findings, iterate until clean
```

Per CLAUDE.md: CRITICAL/HIGH are blocking, MEDIUM should be fixed, LOW addressed. Iterate until the team gives a clean bill. No commit until governance passes.

---

## Step 0 — Before you launch anything

Run these in parallel to size the change and pick domain agents:

```bash
git log --oneline <range>
git diff --stat <range>
git diff <range> -- '*.cpp' '*.hpp' '*.h' | wc -l
git diff <range> -- 'proto/' 'meson.build' '.github/workflows/' 'tests/' \
                     'gateway/' 'docs/' 'scripts/' | wc -l
```

Check existing memory that might apply — at minimum:
- `feedback_governance_run.md` — prior-run learnings
- `feedback_test_quality.md` — fixture leaks, test code standards
- `feedback_claude_md_scope.md` — which areas are cipher to you / still churning

---

## Gate 1 — Change Summary

You write this yourself, from `git show` and `git diff --stat`. Structure:

- **Commits in scope** — table with sha, subject, push state
- **Files touched** — table with path, delta description
- **Interfaces affected** — public API changes, store contracts, REST behavior, proto, plugin ABI, CI gates
- **Security surface** — what's closed, what's opened, net-neutral explanation
- **User-facing impact** — behavior changes, breaking changes, new flags
- **Prior validation performed** — compile, tests, script runs with exit codes
- **Governance domains triggered** — which Gate 3 agents apply (see matrix below)

Write this in your own response before invoking any agents. All downstream agents reference it, so skimping here wastes the whole run.

---

## Gate 2 — Mandatory security + docs review

Launch both agents in a **single message with two tool calls** so they run in parallel.

### security-guardian preamble template

```
Full governance Gate 2 review of <N> commits on branch <branch> at
/mnt/c/Users/natha/Yuzu: <sha1>, <sha2>, ...

Use `git show <sha>` to view each commit. The working tree is clean;
what you see in <range> is the full scope.

## Your job

You are the mandatory security reviewer for Gate 2. Read every
modified file top to bottom (CLAUDE.md requires it) and assess:

<finding-specific questions — fill in based on the actual change>

## Sibling-handler check (LOAD-BEARING)

This has caught 2/3 of the highest-severity findings in prior runs.
For every handler, endpoint, or store method this PR modifies, find
every OTHER handler/endpoint/store method in the codebase that
implements the same semantic (e.g. "revoke token", "update group",
"fetch inventory") and verify that:
  (a) it has the same authorization check, and
  (b) it has the same validation/ownership pattern.

Explicit "grep for sibling paths and compare" is the invariant — not
"trust that other paths are fine."

## New-error-branch audit

If this PR adds any new 4xx/5xx error-response branch in a handler,
audit every response-body construction in the branch for information
disclosure. A denied/not-found fragment that echoes the caller's
permitted view is NOT safe if the rendering function itself queries
unfiltered data — this is how UP-11 shipped in the #222 hardening
round.

## Output format

Findings table with severity (CRITICAL / HIGH / MEDIUM / LOW / INFO),
file:line, description, recommended fix. CRITICAL and HIGH block
merge. Also note any invariants the changes *strengthen* that should
be preserved against future regression.

Report in under 800 words.
```

### docs-writer preamble template

```
Full governance Gate 2 docs review of <N> commits on branch <branch>
at /mnt/c/Users/natha/Yuzu: <sha1>, <sha2>, ...

Use `git show <sha>` and `git diff <range>` to see the full scope.

## Your job

You are the mandatory docs reviewer for Gate 2. Read every modified
file and the related user-facing documentation. Per CLAUDE.md
"Documentation requirements": user-facing behavior changes without
doc updates are BLOCKING.

Specifically verify:
1. REST API docs (`docs/user-manual/rest-api.md`) — endpoint signature,
   request/response body, error paths, permissions
2. User manual feature sections (`docs/user-manual/*.md`) — operator
   workflow changes, new CLI flags, new env vars, upgrade notes
3. CHANGELOG.md — the `[Unreleased]` section for Fixed/Added/Changed/
   Breaking entries; reverse-chronological order invariant
4. CLAUDE.md — new architectural invariants, new stores, new ABI
   patterns, new release gates
5. Any audit action table, permission table, or error-code table
   that the REST/store/plugin API contract touches

## Output format

BLOCKING = user-facing behavior changed and no doc reflects it.
SHOULD-FIX = doc drift that would confuse an operator.
NICE-TO-HAVE = style/precision improvements.

For each, quote current doc text (or "missing from X") and propose
replacement. Report in under 600 words.
```

Launch:

```
Agent (security-guardian): [above preamble + change-specific questions]
Agent (docs-writer): [above preamble + change-specific questions]
```

---

## Gate 3 — Domain-triggered parallel review

Use the decision matrix below to pick agents. Launch **all picked agents in a single message** so they run in parallel. Always pass the Gate 2 preamble structure, plus the agent-specific focus.

### Decision matrix

| Files touched | Agents to launch |
|---|---|
| `proto/`, schema changes, plugin ABI headers | **architect** |
| `server/core/src/`, cross-module refactor | **architect** |
| `tests/`, new fixtures, coverage gaps | **quality-engineer** |
| `meson.build`, `vcpkg.json`, `.github/workflows/`, release tooling | **build-ci** |
| `agents/plugins/`, plugin YAML defs | **plugin-developer** |
| `gateway/` (Erlang) | **gateway-erlang** AND **erlang-dev** |
| CEL expressions, scope DSL, trigger templates, YAML DSL spec | **dsl-engineer** |
| Windows-only / macOS-only code, cross-platform helpers | **cross-platform** |
| SQLite query paths, BFS/graph, hot authz paths | **performance** |
| Packaging, systemd units, Dockerfiles, installer scripts | **release-deploy** |

**Always include architect** when any public store contract or REST API surface changes — the duplicate-validation and error-mapping drift patterns recur.

**Always include quality-engineer** when new features or fixes land — it's the only agent that flags fixture races, bad error-string substring asserts, and REST-handler-untested-through-store-tests, which are the three highest-ROI test gaps.

**Always include performance** for anything that touches `get_*_ids`, SQLite BFS, or per-authz hot paths.

### Gate 3 agent preamble

Each Gate 3 agent gets the same structural preamble, varying in the "Your job" stanza:

```
Full governance Gate 3 <agent-type> review of <N> commits on branch
<branch> at /mnt/c/Users/natha/Yuzu: <sha1>, <sha2>, ...

Read `git show <range>` for the full diff.

## Context

<paste Gate 1 Change Summary here verbatim so the agent doesn't
 re-derive what's in scope>

<paste any already-completed Gate 2 findings as "for your context only,
 do not duplicate">

## Your job — <agent-specific focus>

<agent-specific questions, 5-10 numbered items>

## Output format

Findings with severity (BLOCKING / SHOULD / NICE / INFO), file:line,
description, recommendation. Report in under <N> words.
```

**Pass prior gate findings as context** — the governance policy in CLAUDE.md requires this to avoid duplicated effort. Extract each prior finding ID (sec-H1, doc-B3, etc.) and summarize one line per finding.

---

## Gate 4 — Correctness & resilience (mandatory, parallel)

Always run all three: **happy-path**, **unhappy-path**, **consistency-auditor**. Launch in one message.

These three are the highest-value reviewers in the Yuzu pipeline. Prior runs confirm:
- **unhappy-path** catches compound failure modes that no single-agent review finds (concurrent + corrupt DB, TOCTOU + I/O error).
- **consistency-auditor** catches cross-component drift: REST+store duplicate-validation divergence, audit field-order regression, 404-vs-403 oracle mismatch between sibling handlers, test assertion substring laxness.
- **happy-path** catches the "my new fix breaks the no-op PUT" and "my retry returns 404 instead of idempotent 200" kinds of mundane correctness.

### happy-path preamble

```
Full governance Gate 4 happy-path review. <N> commits on branch <branch>
at /mnt/c/Users/natha/Yuzu: <sha1>..<shaN>.

`git show <range>` covers the full scope.

## Context — prior gate findings (for your context only, do not duplicate)

<one-line summary per Gate 2/3 finding>

## Your job — normal-path logic completeness

Trace every happy path through the changed code and verify the logic
is complete and correct:

1. For each new or modified endpoint, trace request -> auth -> perm ->
   store lookup -> store write -> audit -> response. Every step.
2. For each new store method, trace the non-error path end-to-end on
   representative inputs.
3. For new CLI flags / env vars, trace parse -> validate -> apply ->
   log-at-startup -> effect-on-runtime.
4. Compare the new success-path to the pre-commit success-path. What
   did the commit change that is visible to a normal-case caller?

Call out idempotency semantics explicitly — new error-handling that
changes a retry from 2xx-on-duplicate to 4xx-on-duplicate is a
breaking API contract even if the initial call still succeeds.

## Output format

Pass / Findings list. Severity: BLOCKING / SHOULD / NICE.
Under 600 words.
```

### unhappy-path preamble

```
Full governance Gate 4 unhappy-path review. <N> commits on branch
<branch>: <sha1>..<shaN>.

`git show <range>` for the full scope.

## Context

<Gate 1 Change Summary verbatim>
<Gate 2/3 findings as "already covered, do not duplicate">

## Your job — failure-mode interrogation

You are the unhappy-path reviewer. Your mandate is to imagine every
way these changes could fail in production and produce a risk register
for Gate 5 chaos-injector. Don't propose fixes for things that are
working — propose failure scenarios and the observable symptoms.

Focus on compound failures where two or more risks interact:
- concurrent writers + partial SQLite failure
- TOCTOU between get-then-check and the write
- empty/whitespace/NUL-byte input that bypasses validation
- pre-existing corrupt DB state that the fix assumes is clean
- retry storms / idempotency under connection reset
- storage-layer failure masked as "not found"
- audit detail unescaped -> stored XSS on dashboard render
- MCP token scope confusion vs principal match

## Output format

Risk register with entries shaped as:
- **ID** (UP-N)
- **Risk** — one-sentence description
- **Trigger** — how it happens
- **Symptom** — what the operator/user observes
- **Severity** — BLOCKING / SHOULD / NICE
- **Chaos scenario** — suggested chaos-injector test, or "N/A"

Aim for 12-20 entries. Under 900 words.
```

### consistency-auditor preamble

```
Full governance Gate 4 consistency review. <N> commits on branch
<branch>: <sha1>..<shaN>.

Read `git show <range>` for the full diff.

## Context

<Gate 1 Change Summary verbatim>
<Gate 2/3 findings as "already covered, do not duplicate">

## Your job — cross-component consistency

You are the consistency auditor. Your mandate is cross-component
state, schema, and contract consistency. Check:

1. **Sibling-handler parity** — if the PR modifies handler X, find
   every OTHER handler that performs the same semantic operation and
   verify they apply the same auth/validation/audit pattern.

2. **Error message string parity** — store-layer error strings vs REST
   error envelope vs docs vs test assertions. Any drift = a rename
   will silently break docs while tests still pass.

3. **Audit field order / naming parity** — any new `.log({...})`
   emission site must match the AuditEvent struct declaration order
   and the field names used elsewhere. `principal_role` must match
   the session's actual role, not a hardcoded string.

4. **Auth role constant parity** — `auth::Role::admin` vs RBAC vs
   `is_global_admin` — one convention across the codebase.

5. **Schema / protobuf / wire-contract untouched?** — if yes, verify
   no downstream consumer breaks; if no, flag for architect.

6. **Test fixture pattern parity** — new test files should match the
   existing `unique_temp_path` helper or equivalent; shared hardcoded
   paths are a parallel-test race.

7. **CHANGELOG reverse-chronological order invariant** preserved?

## Output format

Findings with severity (BLOCKING / SHOULD / NICE), file:line,
description, recommended action. Under 700 words.
```

---

## Gate 5 — Chaos analysis (conditional)

**Skip Gate 5 if neither unhappy-path nor consistency-auditor produced findings.** If either did, run chaos-injector with the full risk register as input.

Chaos is a test-design producer, not a runtime executor. It synthesizes the unhappy-path findings into prioritized chaos scenarios with success criteria and rollback procedures. Use the output to:
1. File P0 scenarios as issues with "must run before release" labels
2. File P1/P2 scenarios as tracked hardening backlog
3. Note any scenarios that are "verify by code read" — resolve them yourself without filing

### chaos-injector preamble

```
Gate 5 chaos analysis. <N> commits on branch <branch>: <sha1>..<shaN>.

Your input is the unhappy-path risk register and consistency-auditor
findings. Your job is to synthesize them into executable chaos
scenarios with success criteria and rollback procedures — NOT to run
the chaos yourself, but to produce the test design document that a
future chaos run would execute.

## Unhappy-path risk register

<paste all UP-N entries verbatim from Gate 4 unhappy-path output>

## Consistency-auditor findings

<paste all C-N entries verbatim>

## Superseded

<list any UP-N / C-N entries that are CLOSED in working tree fixes,
 so chaos doesn't author scenarios for things already resolved>

## Your job

Produce a chaos test design with these entries. For each scenario:
1. **ID** (CH-N)
2. **Hypothesis** — invariant we want to verify under fault injection
3. **Injection** — specific fault, tool, parameters (VFS shim, sqlite
   pragma, kill signal, breakpoint sleep)
4. **Setup** — pre-condition DB/fixture state
5. **Trigger** — the action(s) that expose the fault
6. **Success criteria** — observable post-conditions proving invariant
7. **Rollback** — how to restore safe state (git reset? DB restore?)
8. **Severity / phase** — P0 block-merge, P1 pre-release, P2 nightly

Focus on scenarios where two or more unhappy-path risks compound —
individual fault injection in isolation often misses the real
production failure mode.

Also produce a short "scope decision" recommendation: which of P0/P1
scenarios should block the current PR's push-to-origin, vs which to
file as follow-up issues for the next release gate.

Report under 1000 words. Do not run any code — this is a planning doc.
```

---

## Gate 6 — Operational review (mandatory, parallel)

Launch all three in one message: **compliance-officer**, **sre**, **enterprise-readiness**.

Each agent gets the same Gate 1-5 context and focuses on a different aspect:
- **compliance-officer** — SOC 2 control alignment, evidence chain, audit traceability
- **sre** — observability (metrics, alerts), recovery paths, health probes, capacity
- **enterprise-readiness** — customer-facing assurance, pilot-visible rough edges, upgrade notes, breaking changes doc coverage

Use the same structural preamble as Gate 4 agents, vary the "Your job" stanza to the agent's domain.

**Watch for:** sre routinely catches pre-existing readiness-probe gaps that become BLOCKING because the PR makes an existing store more load-bearing. The HC-1 pattern (store missing from `/readyz`) reappears — always verify the new store(s) in scope are in the probe conjunction.

**Watch for:** enterprise-readiness flags breaking-changes-without-upgrade-note more reliably than other agents. If the PR changes non-admin behavior, a CHANGELOG "Breaking" section + `docs/user-manual/server-admin.md` upgrade note is almost always required.

---

## Gate 7 — Iterate

**BLOCKING** = CRITICAL / HIGH security, BLOCKING from any Gate 4-6 agent, or any finding that explicitly says "blocks merge".

Strategy:
1. **Fold compatible fixes into one commit.** If sec flags H1, docs flags B3, QA flags B5, and they all touch related files, fix as a single "hardening round" commit rather than three small ones.
2. **Re-run Gate 2 security on the hardening round.** Prior runs have caught HIGH regressions introduced by the fix commit itself. Always re-review.
3. **After re-review passes**, proceed to Gate 4 + Gate 5 + Gate 6 on the final baseline (only re-run the gates whose findings would be affected by the fix — if the fix was docs-only, Gate 4 happy-path doesn't need a re-run).
4. **Don't commit until governance passes.** Per CLAUDE.md.

## Known patterns from prior runs

**Pattern A: sibling IDOR.** When fixing an authorization gap on endpoint X, grep for every other endpoint in the same file/semantic and verify they have the same check. #222 closed the REST path but left the HTMX dashboard path open. The governance security-guardian caught it only when explicitly told to look for siblings.

**Pattern B: cycle-safe here but not there.** When adding `visited` sets / cap checks to one traversal (`get_descendant_ids`), always check the sibling traversal (`get_ancestor_ids`) for the same class of bug. The fix pattern is symmetric; the bug pattern usually is too.

**Pattern C: pre-existing bug made worse by hardening round.** A latent bug that was dormant under previous call patterns can become hazardous when you add a new call site. UP-11 / C1: my #222 fix added a new denied-branch that called `render_api_tokens_fragment()`, which has always leaked all tokens via `list_tokens()`-with-no-filter — but no prior code path exercised that leak in a denied-response body sent to a non-owner. My "close the oracle" fix shipped a new info leak worse than the IDOR it closed. Watch for this pattern in every new error-branch.

**Pattern D: 404 vs 403 enumeration oracle.** When adding owner-check rejection to an endpoint, return the same status and same body as "not found" so non-owners cannot distinguish "doesn't exist" from "exists but not yours". Audit log server-side with the real reason.

**Pattern E: readiness probe coverage regression.** Gate 6 SRE reliably catches any new or newly-load-bearing store missing from `/readyz`. Verify `server.cpp`'s `stores_ok` conjunction covers every store the PR changed or newly relies on.

## Cost / ROI

One full governance run on a non-trivial commit range is ~6-9 parallel agent calls plus the consolidation writeup. On the #222/#224 hardening round (5 commits, 2 hardening rounds), it caught 3 BLOCKING items I introduced myself, 2 of which would have shipped a worse vulnerability than the one I was fixing. The run takes 30-60 min of wall clock and produces a permanent artifact trail in commit messages + CHANGELOG that satisfies SOC 2 Workstream F change-management evidence.

Skipping Gate 4 or Gate 5 to save time is rarely worth it. Skipping Gate 3 domain agents is sometimes fine if the change is genuinely small in scope (one file, no public API change); use the decision matrix to judge.

## Post-run follow-ups

After the run passes and the commits push, governance typically produces 8-15 deferred follow-up items that should be filed as GitHub issues (SHOULD findings that were scoped out of the PR). See prior examples in issues #340..#353. Group by domain (tech-debt, chaos, observability, devops) and include full-context bodies so a future session can pick them up cold.
