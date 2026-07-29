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

§3.1 calibrated the merge **threshold** — GATING / SHOULD / NICE, with native labels
mapping onto it. That fixed the gate and left the bands undefined. CRITICAL and HIGH
both map to GATING with no criterion separating them; LOW and INFO both map to NICE.
Exactly one clause in the shipped block is falsifiable — *"you must be able to name the
failing input or state"* — and the rest are adjectives: "misleading operator guidance",
"bounded blast radius", "everything else".

That matters because the pipeline both **records** the native band (`severity_native` in
the ledger) and **acts** on it (CLAUDE.md: "CRITICAL/HIGH are blocking, MEDIUM should be
fixed, LOW addressed"). It is also the input FortitudeEtc's deferred triage design assumes
— his table keys on *"the reviewer's own severity, exactly as today"*, and his own text
says #2604's shared severity definitions are what make that mapping reliable rather than
reconstructed per run.

### The change

Severity becomes a **function of three stated facts** rather than a label a reviewer
picks: a TRIGGER, a CONSEQUENCE from a closed list of seven, and a REACHABILITY from a
closed list of six. Consequence gives a base band; reachability modifies it; `BLOCKING`
is defined as a derived band of CRITICAL or HIGH. The three facts are recorded in the
ledger next to `severity_native`.

Three decisions worth arguing rather than assuming:

- **`R4` (non-default configuration) is not a downgrade.** In Yuzu the default is
  frequently the *less* hardened setting — RBAC off is the default, `--auth-mode=sso-only`
  is opt-in — so "only with the flag on" often means "only for the customers who care
  most". Importing a CVSS-shaped assumption here would invert the intended posture.
- **`C4` folds "absent" in with "misleading".** A shipped behaviour change documented
  nowhere is a truth finding, not a wording one. This resolves the unclassified
  missing-doc case (#2620) inside the severity rule rather than beside it.
- **Two absences point in opposite directions on purpose.** An unnameable trigger is
  the *reviewer's* evidence failing, so it is not gating. An unmappable vocabulary is the
  *schema* failing, so it gates. They look contradictory sitting next to each other and
  are not.

### What makes it testable, and what does not

No prose makes an LLM's severity assignment deterministic, and this does not claim to.
What the three fields buy is **auditability**: a wrong band becomes a visible mismatch
between the stated facts and the assigned label, checkable after the fact. Today a wrong
band is indistinguishable from a right one because nothing is stated.

The validation step, not yet built: a calibration corpus of findings whose bands the team
already agrees on — #2202's four HIGH auth findings, #2580's nine BLOCKING plus the three
Gate 8 fix-round defects, #222's UP-11 round, #2360's clock-guard rounds. The rule is
validated iff applying it reproduces the agreed bands.

**One result to expect, flagged rather than absorbed:** this table appears to promote
parts of #2202 from HIGH to CRITICAL (`C1` security-control bypass + `R2` lower-privilege
actor). Either the table is too aggressive or those findings were under-labelled. That
disagreement is the useful output and should be argued.

### Open for the team

1. Is `C4` at base HIGH right? It makes a wrong runbook line gate. The #2580 `pg_locks`
   case says yes — the shipped runbook walked a DBA toward terminating another tenant's
   backend. A stale flag name in a doc says no. The trigger requirement may already be
   doing that work.
2. Should `R5` (race / rare condition) raise rather than hold? The worst recent defects —
   the clock-guard family, the swallowed anomaly — are all `R5`.
3. Does CRITICAL earn its existence? It is reachable only via `C1`/`C2` + `R1`/`R2`, and
   the gate is identical to HIGH. Fine if it is reporting signal rather than control flow,
   but worth saying out loud.
