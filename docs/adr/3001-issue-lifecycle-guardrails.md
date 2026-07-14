---
status: proposed
date: 2026-07-14
owner: "@Doomgoose (Alex Young)"
related: issue #2139 (auto-close gap, 29 leaked issues); docs/agents/issue-tracker.md; docs/agents/triage-labels.md; .github/workflows/nightly.yml (issue-automation precedent)
---

# 3001 — Issue-lifecycle guardrails: closing the dev-branch tracker loop

> Records the remediation programme adopted after the July 2026 backlog audit. Over 2026-07-13/14 a
> full manual audit re-grouped the tracker and closed ~180 issues across two maintainer-run passes
> (28 closed as `completed` with linked evidence on 07-13; a 153-issue bulk reset closed as
> `not_planned` on 07-14), and filed #2139 quantifying the structural auto-close gap (29 issues
> left open despite merged PRs claiming to close them). Even after that effort, **1,024 issues
> remain open in a four-month-old repository**, and nothing prevents regrowth: the audit treated
> symptoms. The backlog is a direct bottleneck on development speed — 683 issues are marked
> `ready-for-agent` but their freshness cannot be trusted, so picking up work starts with
> re-verification; governance runs re-file findings that already exist; maintainers burn sessions
> on manual batch-close sweeps because `Closes #N` never fires on dev merges; and release scoping
> cannot trust open counts. This ADR adopts five automated guardrails so the tracker stays
> truthful without recurring heroics.

## Context

### Where we are

The repository works on a `dev` integration branch; `main` is release-only and is GitHub's default
branch. Four structural gaps let the backlog grow unchecked:

- **B1 — Fixed work stays open.** GitHub honours closing keywords only on default-branch merges,
  so every `Closes #N` in a dev PR is inert. Issue #2139 found 29 issues still open despite
  merged PRs explicitly claiming them; 26% of recent dev PRs carry closing keywords that do
  nothing. The current substitute is periodic manual batch-close sweeps by maintainers.
- **B2 — Unbounded batch inflow.** Agent skills file issues in volume (the governance pipeline
  alone produces 8–15 deferred-finding issues per run) with a prose-only convention and no
  mandatory duplicate search. Issue *content* quality is high; the failure modes are duplicates,
  multi-finding bundles, and decisions typed as code tasks.
- **B3 — Silent fixes.** Issues resolved incidentally by feature/refactor PRs that never
  reference them leak past any keyword-based automation.
- **B4 — No recurring triage.** Nothing sweeps for obsolete, duplicate, or unclear issues; 160
  open issues still carry `needs-triage` and 24 are unlabelled.
- **B5 — Taxonomy drift.** 66 labels with two parallel priority schemes (`P0/P1/P2` vs
  `priority-p*`) and two phase series make label-driven filtering and automation unreliable.
- **B6 — No telemetry.** Inflow/outflow and backlog age are invisible until the situation
  demands another multi-day audit.

### Why this is a dev-speed bottleneck

Every tracker-touching activity pays a tax. Selecting work requires re-verifying whether the
issue is still real; reviews and governance runs spend effort re-discovering known findings;
maintainer time goes to manual close sweeps; planning and release scoping work from inflated
numbers. The July audit itself — days of skilled effort — is the recurring cost of having no
guardrails, and without structural change it will need repeating within months.

## Decision

Adopt five guardrail pillars, delivered as five PRs (each subject to the standard review gates),
plus a scripted label migration and a recurring operational cadence:

1. **A written issue bar** (`docs/agents/issue-bar.md`) governing when an issue is warranted,
   required body sections (Context / Evidence / Acceptance criteria / Origin), mandatory labels
   (one type + one of `P0/P1/P2` + one triage state), one-actionable-outcome-per-issue,
   mandatory duplicate search before filing (no volume cap — dedupe is the filter), typing for
   decision/spike/hardening issues, and closing discipline (`Closes #N` required in any PR that
   resolves an issue; `completed` only with linked evidence; the security exception routing
   exploitable vulnerabilities to private advisories). Wired into every instruction surface:
   CLAUDE.md, AGENTS.md, CODEX.md, CONTRIBUTING.md, the governance and test skills, and the PR
   template.
2. **Close-on-dev-merge automation** (`close-linked-issues.yml`): on every PR merged into `dev`,
   resolve its linked issues via GraphQL `closingIssuesReferences` (GitHub's own grammar) and
   close them as `completed` with an evidence comment (PR + merge SHA) and a `fixed-on-dev`
   label. Revert PRs reopen what they closed. A daily reconcile pass (plus `workflow_dispatch`
   with a `since` input) covers fork merges, outages, and the one-time backfill of #2139's 29
   leaked issues.
3. **A PR "issue radar"** (`linked-issues.yml`, advisory-only): one sticky comment per PR that
   (a) flags `#N` mentions lacking a closing keyword and (b) matches the PR's changed file paths
   against open-issue bodies — issue bodies cite `file:line` uniformly — so authors are told
   "these open issues cite files you touched" and add `Closes #N` before merge.
4. **Mechanical enforcement at creation**: YAML issue forms with required fields +
   `blank_issues_enabled: false` + a private-advisory contact link for the web path; a committed
   blocking PreToolUse hook (`issue-bar-guard.py`, modelled on the proven changelog-fragment
   guard) that denies non-conformant `gh issue create` calls from agent sessions with a teaching
   message (fail-open, `YUZU_ISSUE_BAR_ACK=1` operator bypass).
5. **A recurring evidence-based triage sweep** (`/issue-triage` repo skill, run weekly from the
   maintainer's box): a five-category rubric — fixed-elsewhere / obsolete / too-trivial /
   unclear / duplicate — where every closure carries machine-parseable evidence (claiming PR
   **and** a grep of current `origin/dev` proving the defect gone). Machine-verifiable
   fixed-elsewhere closures execute autonomously from day one (capped 15/run); judgment
   categories produce a checkbox report for operator approval. Duplicate detection scales via a
   file-citation inverted index rather than pairwise comparison. The sweep also runs
   closure-integrity spot-checks (sampling recent `not_planned` closures against the current
   codebase so closure decisions stay durable as the architecture moves) and posts weekly
   telemetry to a rolling tracking issue.

Supporting decisions: merge `priority-p*` into `P0/P1/P2` and create the automation labels
(`fixed-on-dev`, `task`, `decision`, `triage-sweep`) via a one-time idempotent script;
`phase-*` labels left untouched (open issues on both series; nothing keys on them); the ad-hoc
`github-issues/` staging directory is retired (its one draft gets filed per the bar, then the
directory is deleted) — the tracker is the sole source of truth; CODEOWNERS gains a
`/.github/` entry so automation changes always get owner review.

## New artefacts

| # | Artefact (path) | PR | Value / output | Negates |
|---|---|---|---|---|
| 1 | `docs/agents/issue-bar.md` | PR 1 | Single canonical filing/labelling/closing standard for humans and agents; the document every other artefact cites | B2, B3, B5 |
| 2 | Pointer edits: `CLAUDE.md`, `AGENTS.md`, `CODEX.md`, `CONTRIBUTING.md`, `docs/agents/issue-tracker.md`, `docs/agents/triage-labels.md` | PR 1 | Every Claude/Codex session and human contributor is routed to the bar at the moment they touch the tracker | B2 |
| 3 | Governance + test skill rewrites (`.claude/skills/governance/SKILL.md`, `.claude/skills/test/SKILL.md`) | PR 1 | The largest inflow source dedupes against the open index before filing; run reports enumerate filed AND not-filed candidates, making inflow auditable | B2 |
| 4 | PR-template issue-linkage checklist line (`.github/pull_request_template.md`) | PR 1 | Authors declare `Closes #N` / `Relates to #N` on every PR as a matter of routine | B3 |
| 5 | `.github/workflows/close-linked-issues.yml` | PR 2 | Linked issues close automatically on dev merge with an evidence trail; reverts reopen; reconcile + backfill retire #2139's 29 leaked issues; manual batch-close sweeps end | B1 |
| 6 | `.github/workflows/linked-issues.yml` (issue radar) | PR 2 | Silent fixes surfaced pre-merge: "these open issues cite files you touched"; missing closing keywords flagged while the PR is still editable | B3 |
| 7 | `scripts/issues/migrate-labels.sh` | PR 2 | One priority scheme; automation labels exist before anything references them; idempotent and dry-run-first | B5 |
| 8 | Issue forms + `config.yml` (`.github/ISSUE_TEMPLATE/`) | PR 3 | Web-path issues arrive structured and `needs-triage`-labelled; blank issues off; vulnerability reports deflected to private advisories | B2, B5 |
| 9 | CODEOWNERS `/.github/` entry | PR 3 | Automation control plane always gets owner review — guards artefacts 5–8 themselves | (protects all) |
| 10 | `scripts/hooks/issue-bar-guard.py` + `.claude/settings.json` wiring | PR 4 | Non-conformant `gh issue create` denied at source with a teaching message, in every Claude session sharing the repo settings | B2, B5 |
| 11 | `.claude/skills/issue-triage/` (SKILL.md + `dump-issues.sh`, `leak-scan.sh`, `build-citation-index.py`, comment templates) | PR 5 | Weekly evidence-based sweep: autonomous two-probe closures for claim-verified fixes, checkbox report for judgment calls, duplicate clustering, closure-integrity spot-checks | B1, B3, B4 |
| 12 | `triage-sweep` rolling tracking issue + telemetry block | PR 5 (operational) | Weekly open/inflow/outflow/age/leak metrics with alert thresholds (leak >0 post-PR-2, needs-triage >100, net inflow >+50/wk×2) — drift visible in days, not months | B6 |

## Consequences

**Positive.** The tracker becomes trustworthy without recurring audits: fixed work closes itself
with evidence, inflow is deduplicated and auditable at the source, silent fixes are surfaced
pre-merge, and drift triggers alerts instead of crises. `ready-for-agent` regains meaning as a
work queue, directly recovering the dev-speed lost to re-verification.

**Costs / risks.**
- The close-on-dev-merge cron and the issue forms only activate once the files reach `main`
  (GitHub evaluates both from the default branch); until the next release the reconcile runs via
  manual `workflow_dispatch --ref dev` weekly, and forms gate nothing. Accepted — the
  `pull_request [closed]` trigger (the main path) is live from the moment PR 2 merges to dev.
- The blocking hook adds friction to legitimate rapid filing; mitigated by fail-open behaviour,
  the `--web` escape, and the explicit `YUZU_ISSUE_BAR_ACK=1` bypass. Codex sessions do not run
  Claude hooks and rely on the AGENTS.md pointer + the sweep as backstop.
- Autonomous sweep closures could mis-fire; bounded by the two-probe evidence requirement,
  the 15-per-run cap, hard guardrails (never touch `security`-labelled / assigned / recently
  active / open-linked-PR issues), append-only comments with idempotency markers, and a standing
  rule that any wrongly-closed reopen freezes the autonomous tier until the operator re-enables
  it.
- The radar comment is heuristic and could annoy; it is advisory-only, single-sticky-comment,
  and per-PR opt-out (`<!-- radar:off -->`).

## Alternatives considered

- **Change the default branch to `dev`** so native auto-close works: rejected — touches release
  tooling, requires admin, and inverts the repo's release model for one feature we can replicate
  with a 10-permission-line workflow.
- **`pull_request_target` trigger** for fork coverage: rejected — adds a dangerous-trigger
  workflow to a zero-suppression zizmor repo; plain `pull_request` + daily reconcile covers the
  same ground.
- **Regex keyword parsing**: rejected in favour of GraphQL `closingIssuesReferences` — GitHub's
  own resolution, structurally immune to grammar drift, PR-vs-issue confusion, and cross-repo
  references.
- **GitHub Actions-hosted LLM triage**: rejected — the sweep's core operation is grepping the
  current checkout, and an API-key secret would require admin provisioning; a repo skill run
  from the maintainer's box needs zero new credentials.
- **Volume caps on batch filing**: considered and dropped in favour of dedupe-only — a cap
  discards legitimate findings; deduplication plus enumeration-in-report achieves auditability
  without loss.

## Rollout

PR 1 (policy) → PR 2 (workflows + label migration, then scratch-PR verification matrix, then
backfill + close #2139) → PR 3 (forms + CODEOWNERS) → PR 4 (hook) → PR 5 (sweep skill), followed
by a four-week operational burn-down: leaked-issue closure and closure-integrity spot-checks
first, then the 184 `needs-triage`/unlabelled in tranches, then a full duplicate pass, then
bundling splits for P0/P1 — landing at a steady-state weekly sweep cadence. Full verification
steps per artefact are recorded in the programme's working implementation plan.
