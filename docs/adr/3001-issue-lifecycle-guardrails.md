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
> left open despite merged PRs claiming to close them). Even after that effort, **over a thousand
> issues remain open in a four-month-old repository** (1,024 at the 2026-07-14 audit snapshot),
> and nothing prevents regrowth: the audit treated
> symptoms. The backlog is a direct bottleneck on development speed — 683 issues are marked
> `ready-for-agent` but their freshness cannot be trusted, so picking up work starts with
> re-verification; governance runs re-file findings that already exist; maintainers burn sessions
> on manual batch-close sweeps because `Closes #N` never fires on dev merges; and release scoping
> cannot trust open counts. This ADR adopts five automated guardrails so the tracker stays
> truthful without recurring heroics.

## Context

### Where we are

The repository works on a `dev` integration branch; `main` is release-only and is GitHub's default
branch. Counts below are the 2026-07-14 audit snapshot — the tracker moves daily. Six structural
gaps let the backlog grow unchecked:

- **B1 — Fixed work stays open.** GitHub honours closing keywords only on default-branch merges,
  so every `Closes #N` in a dev PR is inert. Issue #2139 found 29 issues still open despite
  merged PRs explicitly claiming them; roughly one in four of the 50 most recently merged dev PRs
  (≈18% of the last 300, by strict closing-keyword grammar) carry closing keywords that do
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

Adopt five guardrail pillars, delivered across five PRs (each subject to the standard review
gates) — the mapping is not one-to-one: pillars 2 and 3 share PR 2, and pillar 4 splits its
forms into PR 3 and its hook into PR 4 — plus a scripted label migration and a recurring
operational cadence:

1. **A written issue standard** (`docs/agents/issue-standard.md`) governing when an issue is warranted,
   required body sections (Context / Evidence / Acceptance criteria / Origin), mandatory labels
   (one type + one of `P0/P1/P2` + one triage state), one-actionable-outcome-per-issue,
   mandatory duplicate search before filing (no volume cap — dedupe is the filter), typing for
   decision/spike/hardening issues, and closing discipline (`Closes #N` required in any PR that
   resolves an issue; `completed` only with linked evidence; the security exception routing
   exploitable vulnerabilities to private advisories). Wired into every instruction surface:
   CLAUDE.md, AGENTS.md, CODEX.md, CONTRIBUTING.md, the governance and test skills, and the PR
   template.
2. **Close-on-dev-merge automation** (`close-linked-issues.yml`): on every PR merged into `dev`,
   parse the PR body with GitHub's documented closing-keyword grammar (chain-aware:
   `Closes #1, #2, #3` / `Fixes` / `Resolves` and variants; the parser strips code fences and
   blockquotes and ignores negated context so quoted or discussed keywords don't fire), validate
   each reference via the REST API (same-repo, an issue not a PR, current state), and close the
   survivors as `completed` with an evidence comment and a `fixed-on-dev` label. The evidence
   comment self-identifies: it names the workflow and links the run, states the close was
   performed by automation, cites the PR + merge SHA, names the authorizing human (the PR's
   merger), and carries an idempotency marker. Residual accepted: REST validation proves a
   reference exists and is an issue, not that it is *related* — a typo'd `#N` can close the
   wrong issue, which the evidence comment makes visible and reversible. Revert PRs reopen what
   this automation closed, deriving the reopen set from its own close markers on the reverted
   PR's issues (reopen drops `fixed-on-dev` and re-adds `needs-triage`). A daily reconcile pass
   covers fork merges, outages, and races; the same parsing logic ships as a local script —
   bound to the identical evidence-comment schema and caps, and required to print a dry-run
   diff before executing — that performs the one-time backfill of #2139's 29 leaked issues and
   any pre-release reconciles (see Costs/risks: a dev-only workflow file accepts neither cron
   nor `workflow_dispatch` until it reaches `main`). A per-PR sanity cap bounds blast radius:
   if a single PR's body resolves more than 10 issues, the workflow skips the batch and posts
   it to the automation-broken tracking issue so the skip is actionable, never just logged.
   **Failure is loud:** an `if: failure()` alert job opens or updates an `automation-broken`
   issue (the `nightly-broken` pattern from `nightly.yml`) — this, not the weekly sweep's
   leak count, is the primary liveness signal; leak-count>0 is the correctness backstop.
3. **A PR "issue radar"** (`linked-issues.yml`, advisory-only): one sticky comment per PR that
   (a) flags `#N` mentions lacking a closing keyword and (b) matches the PR's changed file paths
   against open-issue bodies — `file:line` citations are common in the agent-drafted bodies and
   the issue standard makes them mandatory going forward, so matching is best-effort where
   citations exist — so authors are told "these open issues cite files you touched" and add
   `Closes #N` before merge. Fork PRs run with a read-only token, so radar output surfaces in
   the workflow step summary rather than a PR comment.
4. **Mechanical enforcement at creation**: YAML issue forms (replacing the two legacy Markdown
   templates) + `blank_issues_enabled: false` + a private-advisory contact link for the web
   path — with a deliberate asymmetry: the human web forms require only a minimal subset
   (description plus reproduction/environment for bugs), keeping Acceptance-criteria/Origin as
   optional prompts so a drive-by report is never lost; the full four-section standard binds
   the agent-side `gh` path; a committed blocking PreToolUse hook (`issue-standard-guard.py`,
   reusing the changelog-fragment guard's proven fail-open JSON-deny pattern — the new hook
   needs its own `Bash`/`PowerShell` matcher and command-string parsing, since the changelog
   guard matches file-edit tools) that denies non-conformant `gh issue create` calls from agent
   sessions with a teaching message (fail-open, `YUZU_ISSUE_STANDARD_ACK=1` operator bypass).
5. **A recurring evidence-based triage sweep** (`/issue-triage` repo skill, run weekly from the
   maintainer's box; the `triage-sweep` label names its rolling tracking issue — the skill and
   the label are distinct identifiers): a five-category rubric — fixed-elsewhere / obsolete /
   too-trivial / unclear / duplicate — where every closure carries machine-parseable evidence
   (claiming PR **and** a grep of current `origin/dev` proving the defect gone). Both probes
   re-run against a freshly fetched `origin/dev` at execution time, never against the report
   snapshot. Machine-verifiable fixed-elsewhere closures execute autonomously from day one
   (capped 15/run; overflow carries to the next run); judgment categories produce a checkbox
   report for operator approval. Every closure comment records its authority tier —
   `sweep-auto` or `operator-approved` — and each executed sweep posts the approved per-issue
   decision list (or the report's hash plus summary) to the tracking issue, so batch
   authorization is durably reconstructable. Duplicate detection scales via a file-citation
   inverted index rather than pairwise comparison; index completeness (full pagination of the
   open set, never a truncated cap) is an acceptance criterion, since dedupe is the only
   inflow filter. The sweep also runs closure-integrity spot-checks (sampling recent
   `not_planned` closures against the current codebase so closure decisions stay durable as
   the architecture moves) and posts weekly telemetry to the rolling tracking issue. The
   `stateReason` taxonomy this programme adopts (`completed` = evidence-linked;
   `not_planned` = wontfix/obsolete/duplicate/below-standard) is **forward-looking**: closures
   predating this ADR must not be re-read through it. Work that is genuinely complete but has
   no machine-checkable trail still closes `completed`, with the human attestation recorded in
   the closing comment.

Both new workflows follow the repo's least-privilege convention: workflow-level
`permissions: contents: read`, with `issues: write` scoped per-job to the close job only and
`pull-requests: write` scoped per-job to the radar's comment job only (the `ci.yml`/`nightly.yml`
pattern — job-level permissions replace the workflow default). The advisory radar uses
per-PR `concurrency` with `cancel-in-progress: true` (newest run wins); the close job never
cancels mid-run; the sweep and the label migration throttle mutations with inter-call backoff
to stay clear of GitHub's secondary rate limits. The issue standard and the `config.yml`
contact link reference `SECURITY.md`'s private-advisory URL directly rather than paraphrasing
it, and state a hardening-only convention for public `security`-labelled issues (PR 1 adds the
one-line rule to `SECURITY.md` itself — an addition, not a restatement). `fixed-on-dev` has a
defined lifecycle: applied at dev-close, stripped when the fix ships to `main` (wired into the
release workflow as a follow-up; purely informational until then). The label migration must
complete before PR 2 merges — its `pull_request [closed]` trigger is live immediately — and
the workflow additionally tolerates a missing label so an early merge cannot fail a close.

Supporting decisions: merge `priority-p*` into `P0/P1/P2` and create the automation labels
(`fixed-on-dev`, `task`, `decision`, `triage-sweep`) via a one-time idempotent script;
`phase-*` labels left untouched (open issues on both series; nothing keys on them); the ad-hoc
`github-issues/` staging directory is retired (its one draft gets filed per the standard, then the
directory is deleted) — the tracker is the sole source of truth; CODEOWNERS gains a
`/.github/` entry so automation changes always get owner review.

## New artefacts

| # | Artefact (path) | PR | Value / output | Negates |
|---|---|---|---|---|
| 1 | `docs/agents/issue-standard.md` | PR 1 | Single canonical filing/labelling/closing standard for humans and agents; the document every other artefact cites | B2, B3, B5 |
| 2 | Pointer edits: `CLAUDE.md`, `AGENTS.md`, `CODEX.md`, `CONTRIBUTING.md`, `docs/agents/issue-tracker.md`, `docs/agents/triage-labels.md` | PR 1 | Every Claude/Codex session and human contributor is routed to the standard at the moment they touch the tracker | B2 |
| 3 | Governance + test skill rewrites (`.claude/skills/governance/SKILL.md`, `.claude/skills/test/SKILL.md`) | PR 1 | The largest inflow source dedupes against the open index before filing; run reports enumerate filed AND not-filed candidates, making inflow auditable | B2 |
| 4 | PR-template issue-linkage checklist line (`.github/pull_request_template.md`) | PR 1 | Authors declare `Closes #N` / `Relates to #N` on every PR as a matter of routine | B3 |
| 5 | `.github/workflows/close-linked-issues.yml` + local reconcile/backfill script | PR 2 | Linked issues close automatically on dev merge with an evidence trail; reverts reopen; the script backfills #2139's 29 leaked issues and covers pre-release reconciles; manual batch-close sweeps end | B1 |
| 6 | `.github/workflows/linked-issues.yml` (issue radar) | PR 2 | Silent fixes surfaced pre-merge: "these open issues cite files you touched"; missing closing keywords flagged while the PR is still editable | B3 |
| 7 | `scripts/issues/migrate-labels.sh` | PR 2 | One priority scheme; automation labels exist before anything references them; idempotent and dry-run-first | B5 |
| 8 | Issue forms + `config.yml` (`.github/ISSUE_TEMPLATE/`, legacy `.md` templates deleted) | PR 3 | Web-path issues arrive structured and `needs-triage`-labelled; blank issues off; vulnerability reports deflected to private advisories | B2, B5 |
| 9 | CODEOWNERS `/.github/` entry | PR 3 | Automation control plane always gets owner review — guards artefacts 5–8 themselves | (protects all) |
| 10 | `scripts/hooks/issue-standard-guard.py` + `.claude/settings.json` wiring | PR 4 | Non-conformant `gh issue create` denied at source with a teaching message, in every Claude session sharing the repo settings | B2, B5 |
| 11 | `.claude/skills/issue-triage/` (SKILL.md + `dump-issues.sh`, `leak-scan.sh`, `build-citation-index.py`, comment templates) | PR 5 | Weekly evidence-based sweep: autonomous two-probe closures for claim-verified fixes, checkbox report for judgment calls, duplicate clustering, closure-integrity spot-checks | B1, B3, B4 |
| 12 | `triage-sweep` rolling tracking issue + telemetry block | PR 5 (operational) | Weekly open/inflow/outflow/age/leak metrics plus operational gauges (telemetry staleness >10 days = dead-man's-switch, workflow failure-run count, issue-standard conformance count so hook-bypass drift is visible); threshold breaches (leak >0 post-PR-2, needs-triage >100, net inflow >+50/wk×2) open or update a P1 issue assigned to the maintainer rather than only commenting — drift visible in days, not months | B6 |

## Consequences

**Positive.** The tracker becomes trustworthy without multi-day audit heroics: fixed work closes
itself with evidence, inflow is deduplicated and auditable at the source, silent fixes are
surfaced pre-merge, and drift triggers alerts instead of crises. `ready-for-agent` regains
meaning as a work queue, directly recovering the dev-speed lost to re-verification. Value
accrues per PR (see the Negates column) — but the end-state claims are staged: alert-driven
drift detection exists only once PR 5's telemetry lands, which is why PR 2 carries its own
fail-loud alert job in the same PR rather than depending on the sweep for liveness. Because
every automated closure carries an idempotency marker, the closures of any given run are
bulk-reversible by querying that run's markers — bad batches have a defined recovery path.
Operator absence degrades gracefully: the merge-triggered close path runs unattended; only the
sweep, its telemetry, and leak detection pause until the next run.

**Costs / risks.**
- The close-on-dev-merge cron and the issue forms only activate once the files reach `main`
  (GitHub evaluates both from the default branch), and a dev-only workflow file accepts neither
  cron **nor** `workflow_dispatch` — new workflows on `dev` are fully dormant until the next
  release promotes them (the repo's documented CI invariant; verified empirically: a dev-only
  workflow is invisible to the Actions API). Accepted — the `pull_request [closed]` trigger (the
  main path) is live from the moment PR 2 merges to dev, and the bundled local script covers
  reconciles and the #2139 backfill from a maintainer checkout until the release.
- `CLAUDE.md` is currently ~300 characters **over** its own self-imposed 40k cap, so PR 1's
  pointer edit cannot be additive: it must rewrite the existing issue-tracker routing line
  net-negative (routing detail out to `docs/agents/`), with an explicit acceptance criterion
  that the committed file returns under 40,000 characters.
- The blocking hook adds friction to legitimate rapid filing; mitigated by fail-open behaviour,
  the `--web` escape, and the explicit `YUZU_ISSUE_STANDARD_ACK=1` bypass. Codex sessions do not run
  Claude hooks and rely on the AGENTS.md pointer + the sweep as backstop. Being fail-open and
  bypassable, the hook is an enforcement/teaching layer, never a security control — the
  vulnerability-routing guarantee rests on SECURITY.md, the `config.yml` contact link, and
  `blank_issues_enabled: false`, none of which sit on a fail-open path.
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
- **GraphQL `closingIssuesReferences` as the resolution source**: rejected on empirical grounds —
  GitHub only creates closing-issue references for PRs targeting the default branch, so the
  field returns an empty set for exactly the dev-based PRs this automation exists to handle
  (verified read-only on merged dev PRs #2125, #2126 and #1983, whose bodies carry explicit
  `Closes`/`Fixes` lines yet all return zero nodes). Body parsing with the documented
  closing-keyword grammar is therefore the only viable source — #2139's proposed fix already
  prescribes it — hardened by validating every parsed reference via the REST API (same-repo,
  issue-not-PR) before any close, and acceptance-tested against those known PRs before the
  backfill runs.
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
bundling splits for P0/P1 — landing at a steady-state weekly sweep cadence. Each implementing
PR carries its own verification section with the acceptance tests for its artefacts.

**Ratification.** No acceptance gates beyond the standing convention (`docs/agents/domain.md`):
a reviewed-PR merge to `dev` confers acceptance; `status:` flips to `accepted` in the final
pre-merge commit of the PR that lands this document.
