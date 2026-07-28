# Tuning `/governance` for signal density

**Status:** proposal for team discussion
**Date:** 2026-07-28
**Adversarial review:** `enterprise-architect` (fable) and `gpt-5.6-sol` (codex), independently. **Both returned BLOCK on the first draft.** Their objections are recorded in §5 and have been folded in — the change set below is materially smaller than what was first proposed.

---

## 1. The complaint

`/governance` is reported to be **overly sensitive on prose**. That is real, but it is one symptom of three separable costs. Evidence from PR #2580 (KEK rotation hardening, ADR-0010 secrets seam), which ran 12 agents at Gates 2/3/4/6 and 4 more at Gate 8:

| cost | observed |
|---|---|
| **Prose sensitivity, mis-targeted** | `docs-writer` — the *dedicated* prose reviewer — returned **completely clean**, while five code agents flagged wording. One factually-wrong `-Wswitch` rationale comment was reported by **three separate agents**. |
| **Volume without triage** | ~45 non-blocking findings on one PR, each in full prose. All triage fell on the operator. `workflow-orchestrator` exists to synthesise; the skill never invokes it. |
| **Duplication at full length** | 4 of 6 round-1 BLOCKINGs were reported by 2–3 agents each, independently, in full. |

The third is also the pipeline's **best feature** — independent convergence is the strongest confidence signal it produces. The goal is to keep the signal and drop the re-reading.

## 2. What the gate is earning (why this proposal is narrow)

On #2580 the pipeline found **9 BLOCKING across two rounds**, roughly seven of them substantive behaviour defects. Three would have caused production incidents:

- **`pg_locks` observer query missing a `database` predicate.** `pg_try_advisory_lock` is database-scoped; the observer was not. A lock in another database read as ours, and the shipped runbook then walked a DBA toward terminating **another tenant's backend**. Found by an agent running a real query against a live Postgres.
- **A 15s sampler running an unbatched full-column scan** the PR had explicitly deferred as out of scope, on the serial thread shared with agent-revocation teardown.
- **A parity test that could not observe the field it asserted on**, so a regression straight back to the original BLOCKING passed green.

**Gate 8 found 3 BLOCKING introduced by the fix round itself.** Fix rounds are written fast, on the assumption the hard thinking is done. Nothing here touches Gate 8.

## 3. Accepted changes

### 3.1 Calibrate severity at the source

The skill asks every agent for BLOCKING/SHOULD/NICE and **never defines them**. Twelve agents invent twelve bars; the operator normalises by hand.

Add one shared definition block, injected into every preamble:

> **BLOCKING** — would cause incorrect behaviour, data loss, a security regression, or misleading operator guidance in production. You must be able to name the failing input or state.
> **SHOULD** — a real defect with bounded blast radius, or a missing test for a behaviour that has one.
> **NICE** — everything else.

### 3.2 Cap wording-only findings at NICE — do not prohibit them

*Changed after review.* The first draft said non-docs agents must **not report** wording. Both reviewers rejected that as inoperable: an agent must first classify text as descriptive or normative, and that classification is the disputed question. Sol produced two genuinely ambiguous examples from #2580's own code — a comment calling saturation the "safe failure direction" (explanatory, but it also states the clamp's safety property) and one describing a "fixed Prometheus outcome vocabulary" (descriptive-looking, but it defines cross-surface audit/metric parity).

Revised rule, added to every non-`docs-writer` preamble:

> `docs-writer` owns prose. Report a comment or doc **only** when it contradicts the code, and say which one is wrong. A wording-only observation is capped at **NICE** — report it if you think it matters, never above NICE.
>
> Exception: a factually false comment adjacent to a security or control-flow branch **is** a contradiction, not wording. #2202 shipped a comment asserting the opposite of what its function did, next to an authz branch.

Capping rather than prohibiting means a mis-classification costs a line of noise instead of a lost finding.

### 3.3 Fix the Gate 8 re-review roster

The skill says re-run *"only the gates whose findings would be affected by the fix"*. Wrong axis.

On #2580, Gate 8 ran the four agents whose findings had been fixed. `cpp-expert` — the **portability** reviewer — had only ever seen commit 1. `std::jthread` was introduced in commit 3 *as a fix for a Gate 8 finding*, and broke the macOS leg (`de2f7bfa`). Apple Clang's libc++ has no `std::jthread`; every other use in this codebase sits behind `#ifdef __cpp_lib_jthread`. No agent was ever asked whether the fix was portable.

Replace with:

> Re-run every gate whose **domain the fix diff touches**, not only those whose findings prompted it. Run the Gate 3 decision matrix against the *fix diff* exactly as you ran it against the original. A fix that adds a language feature, dependency, thread, or platform-specific call re-triggers the corresponding agent even if that agent raised nothing in round 1.

### 3.4 Present duplicates once — without letting a synthesiser adjudicate

*Substantially rewritten after review.* Both reviewers flagged that automatic collapsing destroys signal. Sol's counterexample is drawn from this very run: #2580's B1 (REST classifier incomplete) and B2 (MCP retry hint hardcoded) summarise almost identically, and needed **separate fixes and separate tests**. A synthesiser that merged them would have hidden one.

> After the fan-out, run `workflow-orchestrator` as a **presentation** pass producing a severity-ordered table, with every source report preserved verbatim as an appendix.
>
> It may cluster only findings sharing the same `file:line` **and** the same defect; anything else stays separate. Each cluster shows its reporters, takes the **maximum** severity of its members, and never re-adjudicates severity. Clusters are **provisional** — the operator confirms equivalence before anything is treated as one finding. The synthesiser is not the authority on equivalence.

### 3.5 Reward empiricism — read-only

The highest-value finding of the run came from an agent **running a query** rather than reasoning. The best test in the PR proves the bug is observable against an unfiltered predicate *before* asserting the fix, so it cannot pass vacuously.

> Where a claim can be tested cheaply — a query, a compile, a one-case test — test it and report the output. An empirically verified finding outranks a reasoned one; a reasoned finding about observable behaviour should say it was not verified.
>
> **Read-only, against disposable state only.** Never mutate a live store, and never run a destructive statement to raise a finding's standing.

The read-only clause is a review addition: "verified outranks reasoned" otherwise creates an incentive to run mutating queries to win rank.

### 3.6 Instrument governance findings *(new — the precondition for everything else)*

Sol's central point, and the one that reframes this proposal: **the "overly sensitive" complaint is currently unfalsifiable.** There is no record of what governance finds. CI outcomes, durations, retries and flakes are persisted per runner and queryable (`docs/ci-architecture.md`); governance findings are not recorded at all.

> Each `/governance` run appends a row per finding to a local ledger: run id, commit range, agent, severity, `file:line`, one-line summary, and disposition (fixed / deferred-to-issue / rejected-with-reason).

That is a few lines in the skill's Gate 8 step and it makes every remaining question answerable: false-positive rate by agent, which agents produce findings nobody acts on, whether prose findings cluster in specific agents, and whether roster size correlates with post-merge CI failures.

## 4. Withdrawn after review

### 4.1 Tiering the fan-out — WITHDRAWN

The first draft proposed a "core four" (`security-guardian`, `cpp-safety`, `consistency-auditor`, `unhappy-path`) always, with everything else gated on the decision matrix **and** a materiality threshold (>200 non-test lines, or a public-surface delta).

**Both reviewers independently produced kill shapes, and they are convincing:**

- **`gateway/config/sys.config`, 10 lines, weakening management-listener client-cert verification.** Below every threshold, so `gateway-erlang` is dropped — and `cpp-safety` is useless on Erlang config. routed-concerns assigns gateway TLS to that reviewer and calls a plaintext gateway a fleet-RCE edge. *(sol)*
- **A retention/prune tweak.** routed-concerns mandates `cpp-safety` + **`sre`** + **`compliance-officer`** on any modified reaper pass (the clock-guard row, #2360/#2361). The core four drops two of three. *(fable)*
- **A one-line `.github/workflows` `if:` guard.** The CLAUDE.md standing invariant about failure-path guards went silently dead for two months (#1038); that is `build-ci`'s domain, and the core four contains no CI reviewer. *(fable)*
- **The core four contain no portability reviewer at all** — so a `jthread`-class defect in a *small initial* diff sails through. §3.3 fixes at Gate 8 precisely the gap tiering would institutionalise at Gate 3. The two sections fight each other. *(both)*
- **`docs-writer`'s trigger was inverted.** I proposed gating it on "any `docs/` change". Its BLOCKING definition is *"user-facing behaviour changed and **no** doc reflects it"* — so in the exact case it exists to catch, it would never be summoned. *(fable)*

The measurement flaw underneath: "the core four found 8 of 9 BLOCKING" measures recall on **one defect distribution**, not recall across Yuzu's invariant domains. The dropped agents may be preventing defects that never become BLOCKING *because they run*.

**Standing rule going forward:** routed-concern triggers and the skill's existing "always include" rules are **unconditional**. Any future tiering may only choose among agents those rules did not already select.

**What would unblock it:** the §3.6 ledger, plus a replay across ≥10 prior merged runs showing zero findings from dropped agents on small-tier PRs that touched no routed-concerns file.

### 4.2 Retiring Gate 5 (chaos-injector) — WITHDRAWN

The draft argued `unhappy-path` already emits a chaos scenario per entry, making `chaos-injector` a reformatter. One skipped invocation is not evidence, and both reviewers identified output that has no home in `unhappy-path`'s contract: **compound-fault synthesis** (sol) and the **scope decision** — which P0 scenarios block the push versus become follow-up issues (fable). Gate 5 stays conditional as written.

## 5. Review record

| section | fable | sol | outcome |
|---|---|---|---|
| Severity definitions | sound | sound | **accepted** (§3.1) |
| Prose exclusivity | workable w/ carve-out | **not operable** | **revised** to cap-at-NICE (§3.2) |
| Tiering | **BLOCK** | **BLOCK** | **withdrawn** (§4.1) |
| Gate 8 roster | sound, right axis | sound | **accepted** (§3.3) |
| Dedupe | needs strict merge rule | mechanism unsafe | **revised**, operator adjudicates (§3.4) |
| Empiricism | sound, read-only | sound, sandboxed | **accepted** w/ read-only (§3.5) |
| Retire Gate 5 | one skip ≠ evidence | structurally different output | **withdrawn** (§4.2) |
| Methodology | n=1, self-assessed | unfalsifiable; instrument first | **new** §3.6 |

Both reviewers noted the first draft's evidence base was a single PR, on an atypically security-sensitive surface, assessed by the same person who wrote the PR, the fixes, and the proposal. That criticism is accepted and is why the expensive change is now gated behind measurement rather than shipped on one datapoint.

## 6. Expected effect

On a #2580-shaped PR: same agent count, ~45 non-blocking findings presented as a deduplicated table with sources preserved, wording capped at NICE, `cpp-expert` re-run at Gate 8 (which would have caught the macOS break before CI), and every finding recorded for the first time.

On an ordinary PR: unchanged roster, quieter output — and after a few weeks, the data to argue about roster size from evidence instead of impressions.

## 7. Open questions

1. Should the §3.6 ledger live in the existing `~/.local/share/yuzu/test-runs.db` schema, or its own store?
2. Is `workflow-orchestrator` the right home for the §3.4 presentation pass, or does it belong in the harness?
3. How long a sampling window before we revisit §4.1 — a fixed number of runs, or a calendar period?
