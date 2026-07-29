# Tuning `/governance` for signal density

**Status:** proposal for team discussion
**Date:** 2026-07-28
**Adversarial review:** `enterprise-architect` (fable) and `gpt-5.6-sol` (codex), independently. **Both returned BLOCK on the first draft.** Their objections are recorded in §5 and have been folded in — the change set below is materially smaller than what was first proposed.

**Second round (2026-07-28):** a colleague responded with a larger proposal (termination protocol, finding classification, triage, record design) plus a five-item amendment list for this PR. Four amendments were accepted, one refuted; both reviewers re-ran at maximum rigour to verify before anything was changed. §7 records that exchange. Three further defects **in this PR** were found during it and fixed.

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

Add one shared block, injected into every preamble. **Revised in round 2** (see §7): agents
keep their **native** vocabulary and the block calibrates the **threshold**, because telling
every agent to use BLOCKING/SHOULD/NICE "exactly" contradicted `security-guardian`'s
CRITICAL/HIGH/… brief and `docs-writer`'s BLOCKING/SHOULD-FIX/… brief.

> **GATING** — would cause incorrect behaviour, data loss, a security regression, or misleading operator guidance in production. You must be able to name the failing input or state. *Maps from: CRITICAL, HIGH, BLOCKING.*
> **SHOULD** — a real defect with bounded blast radius, or a missing test for a behaviour that has one. *Maps from: MEDIUM, SHOULD, SHOULD-FIX.*
> **NICE** — everything else. *Maps from: LOW, INFO, NICE, NICE-TO-HAVE.*
>
> Where a vocabulary does not map cleanly, say so and treat it as GATING — an unmappable finding must never be silently downgraded.

### 3.2 Cap wording-only findings at NICE — do not prohibit them

*Changed after review.* The first draft said non-docs agents must **not report** wording. Both reviewers rejected that as inoperable: an agent must first classify text as descriptive or normative, and that classification is the disputed question. Sol produced two genuinely ambiguous examples from #2580's own code — a comment calling saturation the "safe failure direction" (explanatory, but it also states the clamp's safety property) and one describing a "fixed Prometheus outcome vocabulary" (descriptive-looking, but it defines cross-surface audit/metric parity).

Revised rule. **Round 2 split this further** (see §7): routing prose to `docs-writer` alone
created an ownership gap, because its brief has no mandate over in-code text at all. Two
questions, two owners:

> - Is this text **well written**? -> `docs-writer`, now including in-code comments and log/error strings.
> - Is this text **true**? -> the **domain agent**: `cpp-expert` for ordinary C++ comments, `cpp-safety` for lifetime/ownership/thread claims, `security-guardian` for auth/authz/crypto, `gateway-erlang` for Erlang, `build-ci`/`release-deploy` for CI, `architect` for normative architecture text (ADRs, invariants, routed-concern rows).
>
> So a contradiction is a **truth** finding at your own native severity, raiseable by any agent. A **wording-only** observation is capped at **NICE**.
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

---

## 7. Second-round amendments (2026-07-28)

A colleague reviewed this PR and returned a larger proposal plus a five-item amendment
list. Both adversarial reviewers re-ran at maximum rigour to verify every claim from the
repo before anything was changed. Four amendments accepted, one refuted.

### Accepted

| # | amendment | what changed |
|---|---|---|
| 1+2 | Add round ordinal and seven more fields to the ledger row | Ledger is now a specified JSONL schema with `pass_ordinal`, `finding_id`, `provenance`, `caused_by`, `adjudicated_by`, `waiver_rationale`, native **and** mapped severity. **Explicitly does not adopt** the signed-waiver merge contract — the columns exist so a future decision has somewhere to write. |
| 3 | `docs-writer` has no mandate over in-code prose | Confirmed: its brief has zero references to comments or in-code text. The original routing created an ownership gap. Now split — **`docs-writer` owns WORDING** (extended to in-code comments and log/error strings), **the domain agent owns TRUTH**, with an explicit routing table. Normative architecture text routes to `architect`. |
| 5 | Changelog fragment carries an unrelated issue's number | Confirmed — **#2596 is a real, open, unrelated issue** (macOS sqlite linking). Renamed to `2604-…`. |
| §8 | Reviewer briefs that are wrong today | Three stale `CHANGELOG.md` `[Unreleased]` instructions rewritten to the fragment convention (the breaking-change *coverage* check was retargeted, not deleted). Four `/mnt/c/Users/natha/Yuzu` paths replaced with `<repo-root>`. |

### Refuted — amendment 4

The claim was that the routed-concern floor "keys on a file that is absent", that no row
covers retention or reaper passes, and that "retention work is unfloored today".

`.claude/routed-concerns.md` is tracked on `origin/dev` and in this branch, and its
clock-guarded-retention row routes any retention/reaper/prune pass to
`cpp-safety` + `sre` + `compliance-officer` — exactly the roster the kill shape cites.

The description is, however, a precise account of `CLAUDE.md` **before 2026-07-11**, when
the inline table's only retention mention was a TAR row about retention-*paused sources*:

| commit | date | change |
|---|---|---|
| `10ad4bb5` | 07-11 | removed that phrasing |
| `bbd2c175` | 07-18 | created `.claude/routed-concerns.md` (#2147) |
| `1a2366ba` | 07-26 | added the clock-guard row (#2360) |

So the amendment appears to have been checked against a stale working copy. Two
consequences: no floor change is needed, and §9's "that floor does not currently exist"
inverts into a *further* argument for its own conclusion — the floor exists, which is a
better reason not to tier than its absence would be.

One genuinely constructive thing sat inside it: the skill asserted the floor without ever
instructing anyone to *load and match* the table. Step 0 and Gate 8 now do, by reading the
file rather than from recall.

### Defects in this PR found during the round

Neither the colleague nor the first review caught these; the maximum-rigour re-run did.

1. **Self-contradiction on severity.** The shared preamble told every agent to use
   BLOCKING/SHOULD/NICE "exactly", while `security-guardian` is briefed on
   CRITICAL/HIGH/MEDIUM/LOW/INFO and `docs-writer` on BLOCKING/SHOULD-FIX/NICE-TO-HAVE.
   Rewritten: agents keep their **native** vocabulary, and the block now calibrates the
   **threshold** with an explicit normalisation map. An unmappable severity defaults to
   gating.
2. **Self-contradiction on the floor.** The cost section still said Gate 3 domain agents
   may be skipped when a change is "genuinely small in scope" — which the new
   unconditional routed-trigger floor forbids. Rewritten.
3. **The ledger overclaimed.** It named a database that does not exist, with no schema and
   no writer, while the changelog fragment said findings are "now recorded". Now a
   specified per-run JSONL file, described as exactly that, with durable shared storage
   named as separate work.

### Deferred, by their own sequencing

Their termination protocol, finding classification and triage design are not in this PR.
Their §6 gates those behind the record, and the record is what this PR builds. Note their
§4 record design *is* amendments 1–2 — it is adopted here, not deferred.

### On "no terminal state"

Accepted in substance, corrected in wording. The pipeline does have PASS/FAIL labels and a
three-iteration escalation convention (`workflow-orchestrator.md`). What it lacks is an
**enforced bounded closure** — "escalate" names no adjudicator and no required outcome, so
the practical exit is fatigue. Their own text says exactly this. What should not be
conceded is that every subsequent finding is churn: on #2580, re-review of the fix rounds
found three genuine BLOCKING defects introduced *by the fixes*, which is why Gate 8 is
retained and strengthened here.

---

## 8. Severity derivation (follow-up, PR #2623)

§3.1 calibrated the merge **threshold** — one gating tier, with native labels mapping onto
it. That fixed the gate and left the bands undefined: CRITICAL and HIGH both mapped to the
gating tier with no criterion separating them, LOW and INFO both to the bottom tier.
Exactly one clause was falsifiable — *"you must be able to name the failing input or
state"* — and the rest were adjectives.

It matters because the pipeline both **records** the native band (`severity_native`) and
**acts** on it, and because FortitudeEtc's deferred triage design keys on *"the reviewer's
own severity, exactly as today"*, naming §3.1 as what makes that mapping reliable.

### The model

Four **independent** fields per finding — TRIGGER, IMPACT (`I1`–`I9`, base band), EXPOSURE
(**all** applicable `E1`–`E6`, strongest modifier wins), EPISTEMIC STATUS — plus a separate
set of **policy floors** that gate as contract violations without running through the
derivation. `BLOCKING` = derived band CRITICAL or HIGH.

### What the first draft got wrong, and why it is recorded here

The first cut of this PR used a single-choice `CONSEQUENCE` + `REACHABILITY` pair. Two
independent adversarial reviews (Fable, Sol, both at maximum effort) returned BLOCK, and
between them established that the shape — not the wording — was the defect:

- **A single reachability enum forced four independent dimensions into one choice** — actor
  privilege, configuration, rarity, production liveness. A race-based authorisation escape
  under a non-default flag truthfully satisfied three values that derived different bands.
  Severity was still being chosen, just with more ceremony. Hence independent fields and
  "list all that apply".
- **`R6` said "floor at LOW" where a cap was meant** — mechanically it *raised* an
  unreachable INFO to LOW and left a dead-code HIGH gating. Both reviewers also found that
  the obvious one-word fix was wrong too: "no production caller" is not "no production
  consequence". That distinction is now `I6` (shipped-incomplete) versus `E6` (the wrong
  outcome provably cannot occur).
- **The closed list was not closed.** Classes the pipeline blocks on today derived to INFO:
  Resource Ledger omission, a direct `CHANGELOG.md` edit, a broken platform build leg,
  non-RAII manual cleanup in new C++, and — found in re-review — violation of any explicit
  MUST / catastrophic-if-violated invariant in CLAUDE.md, the routed-concern table or an
  accepted ADR (a second copy of a single-chokepoint rule has no wrong outcome *today*,
  which is exactly why the derivation cannot see it). They have no production trigger and
  no wrong outcome, so an honest derivation floors them. All are contract violations and
  are now **policy floors**. A missing test is NOT a floor — it is SHOULD, restoring
  §3.1's clause.
- **The unknown-exposure default was inverted** against this document's own stated
  principle. Defaulting to "no change" silently downgrades a possible `E1`. Unresolved
  exposure now gates pending adjudication.
- **Weak evidence was being expressed as low impact**, which meant recording something
  false — observed corruption with an unisolated trigger became "no observable
  consequence". Confidence is now its own field. (`happy-path.md` already carried an
  `epistemic_status`; this aligns with it rather than inventing it.)

### Calibration against the corpus

Applied to findings whose bands the team already agreed on. Counted honestly, after two
rounds of re-review forced the count down twice:

- **Three reproduce unaided:** #2202 B2, #2202 B3, the `std::jthread` macOS break.
- **One matches on band with incomplete facts:** the `pg_locks` runbook (`I3` and `I4` both
  apply, and `E5` — a rare multi-database collision — belongs in the record).
- **Three are CALIBRATED, not validated** — the model was changed after seeing them derive
  the wrong band: #2202 B4 (`I6` escalator), the #2580 parity test (false-green floor), the
  #2580 sampler (`I5` shared-path escalator). Each is marked in the table.
- **One acknowledged mismatch remains:** #2202 B1.

A calibrated row is not evidence the rule works; it is the rule being taught. The three of
them are principled rather than ad hoc — each names a class, not an instance — but the
distinction has to stay visible or the corpus becomes a mirror.

| finding | derives | historical | |
|---|---|---|---|
| #2202 B2 — namespace scan boots clean on corrupt `rbac.db` | I1 + E5 → HIGH | HIGH | match |
| #2202 B3 — engine actions stamped `principal_class=agent` | I1 + E3 → HIGH | HIGH | match |
| #2202 B4 — RBAC resolver with no production grant author | I6→HIGH + E3 | HIGH | match **(calibrated: the escalator was added for this class after observing it derive MEDIUM)** |
| #2580 — `pg_locks` runbook terminates another tenant's backend | I4 + E3 → HIGH | BLOCKING | match |
| #2580 — parity test cannot observe the field it asserts on | policy floor (false-green closure evidence) | BLOCKING | match **(calibrated: floor added for this class)** |
| #2580 — `std::jthread` breaks the macOS leg | policy floor | BLOCKING | match |
| #2202 B1 — engine credential gains fleet-wide Read, RBAC off | I1 + E2 → **CRITICAL** | HIGH | **promotion, gate-neutral** |
| #2580 — 15s sampler unbatched full-column scan | I5→HIGH via the shared-path escalator | BLOCKING | match **(calibrated: escalator added for this class)** |

The B4 escalator is the one place the model was changed to fit the corpus. Re-review
established that its first wording was also wrong — it claimed the absent capability was an
under-enforced control, but that resolver fails CLOSED, so nothing was under-enforced. The
escalator now names two distinct prongs, and B4 is the reference case for the second
(dormant authorisation code that goes live later without re-review), not the first.

**The remaining mismatch is left in rather than tuned away.** Fitting the table to the corpus
after seeing it would be overfitting, and the disagreements are the useful output:

1. **#2202 B1.** A credential holding zero grants reads the whole fleet in the default
   configuration. Fable holds the promotion survives on merit and the historical HIGH was
   under-banded; Sol holds that read-only privilege expansion is not admin/RCE and HIGH was
   right. Gate-identical either way, so this is reporting signal, not merge control — but
   the team should decide, because it sets whether every cross-scope read is CRITICAL.
2. **#2202 B4 — the two reviewers do not agree, and the disagreement is recorded rather
   than resolved.** Fable holds that the `I6` escalator's second prong is principled:
   dormant authorisation code ships and goes live later without re-review, which is a real
   forward risk independent of today's behaviour. Sol holds that B4's missing route failed
   *closed* — a denial of capability, not a bypass — so it derives `I6`/MEDIUM and should
   be recorded as a third mismatch rather than escalated. Both agree the first wording was
   wrong (it claimed an under-enforced control, and that resolver over-enforces). The
   escalator ships with Fable's prong (b) and Sol's dissent noted here; if the team sides
   with Sol, delete prong (b) and restore the row to a mismatch.

### One deliberate gate change, named

`I7` demotes the documentation gate. `docs-writer`'s standing rule — any user-visible
change with no doc BLOCKS — becomes SHOULD unless the omission conceals a breaking change,
security-relevant behaviour, a data-loss risk, a migration step or an irreversible
operation. Since the derived band governs the gate, that is a real narrowing of a whole
reviewer's mandate, and it is the intended answer to the original "governance is too noisy
about prose" complaint. It is recorded here rather than left to be discovered. The
`docs-writer` Gate 2 template previously asserted its blanket BLOCKING on the authority of
a CLAUDE.md section that no longer exists (routed out in `c2e0b1c7`); that false citation
is corrected in the same commit.

### What this does and does not claim

It does not make an LLM's assignment deterministic. It makes the assignment **auditable**:
the facts are recorded next to the label, so a wrong band is a visible mismatch. That claim
is weaker than "derived rather than chosen" and is the honest one — judgement moved into
field *selection* (I5-vs-I2 for a corrupting crash, I8-vs-I3 for stale-served-as-fresh)
rather than disappearing.
