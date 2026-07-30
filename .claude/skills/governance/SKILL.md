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
- `/governance dev..HEAD` — everything on this branch not yet in dev (feature branch workflow)
- `/governance origin/dev..HEAD` — commits on local dev not yet pushed (direct-to-dev workflow)
- `/governance 82f7eb8..9c50bce` — a specific PR range
- `/governance HEAD` — single-commit review (shorthand, treated as `HEAD~1..HEAD`)

If no range is provided, default to `dev..HEAD`. Yuzu's main working branch is `dev` (not `main`), so governance runs normally review "what's new on this branch relative to dev" before merging or pushing. If the current branch IS `dev`, `dev..HEAD` is empty — in that case prompt the operator with `origin/dev..HEAD` (commits ahead of the remote) as the likely intent, or ask them to specify.

## Workflow summary

```
Gate 1 — Change Summary (YOU write this from git diff/log)
Gate 2 — security-guardian + docs-writer           (parallel, mandatory)
Gate 3 — domain-triggered agents                   (parallel, decision matrix below)
Gate 4 — happy-path + unhappy-path + consistency   (parallel, mandatory)
Gate 5 — chaos-injector                            (conditional on Gate 4)
Gate 6 — compliance + sre + enterprise-readiness   (parallel, mandatory)
Gate 6b — synthesis pass (presentation only, workflow-orchestrator)
Gate 7 — address BLOCKING findings
Gate 8 — re-review gates whose DOMAIN THE FIX TOUCHED, ledger, final decision
```

Per CLAUDE.md standing rule 2: a finding BLOCKS when its **derived** band is CRITICAL or HIGH (see the shared preamble below), plus the policy floors listed there. Iterate until the team gives a clean bill. No commit until governance passes.

---

## Step 0 — Before you launch anything

### First: confirm you are running the current pipeline

This skill and the routed-concern table are read **from your working tree**, so a branch
that predates a change to either silently runs the old pipeline. At the time #2604
merged, 81 of 81 local branches predated it.

```bash
git fetch origin dev -q || echo "WARNING: fetch failed - origin/dev may itself be stale"
for f in .claude/skills/governance/SKILL.md .claude/routed-concerns.md CLAUDE.md; do
  git diff --quiet origin/dev -- "$f" \
    && echo "  ok       $f" \
    || echo "  DIFFERS  $f   ($(git diff --shortstat origin/dev -- "$f" | sed 's/^ *//'))"
done
```

Three things about that loop are load-bearing.

**It compares the WORKING TREE, because that is what gets read.** The skill is loaded from
your checkout, not from a commit, so the commit is the wrong object to test. An earlier
version of this check compared `HEAD...origin/dev` - commit against commit - which reports
**current** for a tree whose branch is up to date but which has an older skill checked into
it (`git checkout <old-sha> -- .claude/skills/governance/`), and reports **stale** for a
tree like the one this paragraph was written from, whose branch is months behind but whose
files were copied across and are byte-identical to `origin/dev`. Both answers were wrong,
and the dangerous one was the first.

**It reports per path, and shows the size of the difference**, so the output is evidence
rather than a verdict. A bare boolean over three aggregated paths tells you nothing you can
act on.

**It does not try to tell you WHY a file differs.** Whether you edited it or checked out an
older copy is not knowable from git - both produce a working tree that differs from
`origin/dev` - so the check reports the fact and leaves the judgement to you. If you are
deliberately editing one of these files, `DIFFERS` on that path is expected and the diff it
names is your own. Claiming to distinguish the two would be asserting something unverifiable,
which is the failure mode a previous revision of this section shipped.

**The fetch guard.** A bare `git fetch` whose exit status is discarded fails silently
offline or on expired auth, and the comparison then runs against a stale cached
`origin/dev` and reports **current** while your tree holds the old pipeline. That is the
one direction this check exists to prevent.

**`CLAUDE.md` is included** because it is loaded into every session, so a stale summary
there outranks a correct skill in practice.

If a path you are not editing reports `DIFFERS`, reconcile before running: rebase or merge
`origin/dev`, or copy the current files across (`git checkout origin/dev -- <path>`), which
is enough on its own - the check passes on content, so the files do not have to be committed
to be current. Do not proceed on the assumption that your copy is current: the same failure
mode produces confident false claims about which agents a change routes to.

**The same rule applies to any claim that a file, row or invariant is ABSENT.** Check
`git show origin/dev:<path>`, never `ls` or a working-tree grep. Staleness inverts absence
claims, and an external reviewer pointed at your tree inherits the error rather than
catching it.

### Then: size the change and pick domain agents

Run these in parallel:

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

### Load and MATCH the routed-concern table — do not rely on memory

```bash
# Every changed path, against every routed-concern row.
git diff --name-only <range>
```

Open `.claude/routed-concerns.md` and walk it row by row against that path list.
Each row names the files/change-types it covers and the agents that MUST load on
them. Those agents are selected **unconditionally** — see the standing rule under
the Gate 3 decision matrix. Write the matched rows into your Gate 1 summary so the
selection is auditable, and repeat this match at **Gate 8** against the fix diff.

Do this by reading the table, not from recall: it is amended often, and a row you
remember may have been rewritten. (The clock-guarded-retention row alone has been
rewritten twice since it landed.) Rows are also the reason a one-line change can
require `sre` and `compliance-officer` — size never gates a routed concern.

---

## Shared preamble — inject this into EVERY agent prompt

Twelve agents asked for "BLOCKING / SHOULD / NICE" with no definition invent twelve
different bars, and the operator normalises by hand. #2604 calibrated the merge
THRESHOLD, which fixed the gate but left the bands undefined — CRITICAL and HIGH
both mapped to the same tier with no criterion separating them, while the ledger
records the native band and CLAUDE.md acts on it.

The block below closes that: the band is derived from stated facts, so a wrong
band shows up as a mismatch between the facts and the label rather than as an
unfalsifiable judgement. Two structural points, both learned the hard way in
review (#2623):

- **The facts are independent fields, not one choice.** An earlier draft collapsed
  actor privilege, configuration, rarity and production-reachability into a single
  enum. A race-based authorisation escape under a non-default flag truthfully
  satisfied three values that derived different bands, so severity was still being
  chosen. List every value that applies; the strongest modifier wins.
- **Contract violations are not operational severity.** A missing Resource Ledger
  or a broken platform build has no production trigger and no wrong outcome, so an
  honest derivation lands it at INFO. Those are policy floors and bypass the
  derivation entirely.

Paste this block verbatim into every Gate 2/3/4/6 prompt, in addition to that
agent's own focus.

```
## Severity — DERIVE it, do not choose it

Report in the severity vocabulary your own brief specifies. Do NOT switch
vocabularies — a renamed band loses information. But do NOT pick a band by feel
either. State the facts below; the band follows from them. Where your brief's own
severity criteria disagree with the derived band, **the derived band governs the
GATE**; record your brief's label as `severity_native` and say they disagreed.

Every finding MUST carry, as separate fields — they are independent, and collapsing
them into one choice is what let severity be chosen:

1. TRIGGER — the concrete input, state, or configuration that produces it. Name
   it. "Under load" and "in some cases" are not triggers. If you cannot isolate
   one, write `unresolved` — do NOT downgrade IMPACT to compensate.
2. IMPACT — what goes wrong if this ships. Closed list. **List EVERY value that
   applies**; the strongest gives the base band. A crash that also corrupts is
   `I2` AND `I5`, and it derives from `I2`. Recording only the weaker one is how
   severity gets chosen.
3. EXPOSURE — what is required for it to happen. Closed list. **List EVERY value
   that applies**; the strongest modifier is the one that counts.
4. EPISTEMIC STATUS — `verified` (you ran something and observed the outcome),
   `likely` (reasoned from code you actually read), or `speculative` (you can
   name neither the code path nor a candidate trigger — a hypothesis about code
   you have not read). `likely` is the normal case and gates normally. Only
   `speculative` is exempt, and it is the narrow case, not the humble one.

### IMPACT — gives the base band

  I1  security-control failure — an authn, authz, confinement, crypto, or
      audit control does not hold                                     base HIGH
  I2  data loss or corruption — data destroyed or wrong. A surfaced
      error does not lower this; silence is not a precondition                   base HIGH
  I3  wrong result presented as correct — the caller cannot tell      base HIGH
  I4  harmful operator guidance — a doc, runbook, or error message
      directs an operator to a NAMED action that causes damage, or
      that fails in a way which conceals the real state. Guidance
      that merely fails visibly and diagnosably is I7 or I8, not I4  base HIGH
                                                                      (caps at HIGH)
  I5  unavailability — crash, hang, deadlock, wedge, unbounded growth base MEDIUM
  I6  capability absent or unreachable — a deliverable the change
      presents is not actually reachable in production (shipped-
      incomplete), or a required call site is missing                 base MEDIUM
  I7  required documentation absent for a shipped behaviour change    base MEDIUM
                                                                      (caps at HIGH)
  I8  degraded but correct — slow, wasteful, noisy; output still right base LOW
  I9  no operational impact — latent, stylistic, defence-in-depth only base INFO

I6 raises to HIGH in exactly two cases:
  (a) FALSE ASSURANCE — the change advertises a security or data-integrity
      control as in force which is not in fact enforced; or
  (b) DORMANT AUTHORISATION CODE — a new authz or enforcement branch ships with
      no production caller or author, so it goes live later without re-review.
      #2202 Blocker 4 is the reference case for (b): an RBAC resolver consuming
      a grant no production route could author. It is (b), NOT (a) — that
      resolver fails CLOSED, so nothing was under-enforced.

I5 raises to HIGH in any of three cases:
  (a) it is REPRODUCIBLE unavailability of the server or agent process reached on
      an ordinary request path — a triggerable control-plane crash gates, and
      does not need an unauthenticated reporter to do so;
  (b) it is unbounded or persistent AND falls on a serialised path shared with a
      security or data-integrity operation (revocation, enforcement, audit,
      retention);
  (c) it wedges a state machine. Delaying a
security operation at scale is a security outcome, not a performance one. #2580's
15s unbatched sampler on the agent-revocation thread is the reference case, and
the class also covers #2284's state-machine wedges.

I7 raises to HIGH when the omission conceals a breaking change, a security-
relevant behaviour, a data-loss risk, a migration step, or an irreversible
operation. Otherwise it stays MEDIUM. I4 and I7 never exceed HIGH: a document
is not reached by an attacker, so EXPOSURE cannot promote it to CRITICAL.

### EXPOSURE — list all that apply; strongest modifier wins

  E1  unauthenticated, in the DEFAULT configuration                   raise one band
  E2  an actor operating BEYOND the privilege it starts with
      (escalation, confinement escape). Judge by the privilege
      REQUIRED to begin, never the privilege gained                   raise one band
  E0  no actor required — it fires unconditionally in production: a timer, a
      background thread, a boot path, a scheduled sweep                no change
  E3  any authenticated actor within its own privilege, default
      configuration — including the ordinary operator                 no change
  E4  requires a non-default configuration                            no change
  E5  requires a race or a rare environmental condition (clock skew,
      disk full, concurrent writer, partial failure)                  no change
  E6  the WRONG OUTCOME — not merely the code branch — is proven
      unable to occur in production                                   cap at LOW

Bands, ordered:  INFO < LOW < MEDIUM < HIGH < CRITICAL
Order of operations: apply the strongest RAISE first, then any CAP. `E6` is
applied LAST and dominates every raise — the same recorded facts must not derive
CRITICAL or LOW depending on the order they are read in.

E4 is deliberately NOT a downgrade. In Yuzu the default is frequently the LESS
hardened setting — RBAC off is the default, `--auth-mode=sso-only` is opt-in — so
"only with the flag on" often means "only for the customers who care most".

E6 is about the OUTCOME, not the branch. A branch with no production caller is
usually I6 (shipped-incomplete), not E6 — E6 requires proving the wrong outcome
cannot occur, which a missing caller does not establish. If both a security
control failed AND the actor ends up beyond its privilege, that is I1 with E2;
do not report the escalation as though it were the only fact.

### The gate

BLOCKING = the derived band is CRITICAL or HIGH.

Vocabulary map, derived from the bands above, not asserted alongside them:
  BLOCKING / SHOULD / NICE     → BLOCKING = CRITICAL|HIGH, SHOULD = MEDIUM,
                                  NICE = LOW|INFO
  BLOCKING / SHOULD-FIX / NICE-TO-HAVE  → the same three
  low / medium / high / critical        → already bands; INFO absent, use LOW

### Policy floors — gate regardless of the derived band

These are contract violations, not operational severity. They do not run through
IMPACT/EXPOSURE and they always gate:

  - a Resource Ledger omission on a C++ diff
  - a direct edit to `CHANGELOG.md`, or a missing mandated `changelog.d/` fragment
  - a broken build or test leg on any supported platform that this change
    INTRODUCED or newly exposed — not a pre-existing or environmental failure
  - manual resource cleanup in NEW C++ that is not RAII-wrapped. The
    "documented impossibility" exception is NOT self-granted: it must be
    adjudicated by an agent other than the one proposing it and recorded in the
    ledger with `adjudicated_by`. Pre-existing cleanup in a file this change
    merely touches is SHOULD, not a floor — a deliberate narrowing, see the
    tuning doc
  - a violation of an explicit MUST / never / catastrophic-if-violated invariant.
    CLOSED to three sources, so floor membership is not a judgement call: a
    catastrophic-if-violated clause in a `.claude/routed-concerns.md` row; a
    CLAUDE.md sentence inside a standing-rule or invariant block; an accepted
    ADR's normative requirements. NARRATIVE prose does not qualify — an ADR
    saying a thing "never landed" is history, not a contract. If you cannot
    point at one of those three, it is not a floor — a
    second copy of a single-chokepoint rule, a forked dangerous-op gate, an
    approval gate outside the core primitive, a new server SQLite store with no
    exception ADR. These have no wrong outcome TODAY, which is exactly why the
    derivation cannot see them
  - an ownership or lifetime defect of the kind `cpp-safety`'s blocking contract
    enumerates: a leak, a double-close/double-free, a use-after-free or
    borrowed-data escape, an unjoined or ambiguously-owned thread, unsafe shell
    string construction, or a cast resting on undocumented aliasing/lifetime.
    These derive `I5`/MEDIUM on an ordinary path and would otherwise stop gating
  - a FALSE-GREEN test offered as closure evidence for a blocking finding — a
    test that cannot observe what it asserts. Ordinary missing coverage stays
    SHOULD; this is a floor because it is evidence of resolution that is not
    evidence of anything (#2580 parity test)

A missing test for a behaviour that has a bounded blast radius is SHOULD, not a
floor.

### Absences — and which way each one points

- TRIGGER unresolved → keep IMPACT honest. It is `speculative` ONLY if you also
  have no code path — that is the definition above. If you READ the code and
  named the path but cannot yet isolate the input, it stays `likely` (so it
  gates) and is flagged for adjudication. Never record a lower IMPACT than you
  observed in order to express low confidence.

  EPISTEMIC STATUS is an operation on the GATE, not on the band. Derive and
  report the band normally; `speculative` then converts the finding into a
  MANDATORY INVESTIGATION rather than a merge blocker: it is recorded at its
  derived band, it must be resolved to `verified`, `likely`, or `refuted` before
  the gate passes, and resolving it may confirm the band and block. `refuted` is
  a resolution, not an escape: it is the disposition, it carries its evidence and
  an independent refuter, and it is how a speculative claim that turns out FALSE
  leaves the gate — without it, a correctly-killed finding either wedges the gate
  or gets relabelled `likely`, which falsifies the record. It is a deferral of
  the decision, never a dismissal of it. `verified` and `likely` gate normally.
  If a finding is BOTH speculative AND has unresolved EXPOSURE, it GATES
  outright: a schema failure outranks weak evidence, because the unknown may
  be `E1`.
- EXPOSURE undeterminable → record `unresolved`. It does NOT default to E3, and
  it GATES pending adjudication. Defaulting an unknown to "no change" is a silent
  downgrade of a possible E1. Narrow exception, stated under the prose rule: `I4`
  and `I7` take `E3` — a document is read by an ordinary operator, is not reached
  by an attacker, and both cap at HIGH, so there is no `E1` to conceal. That is a
  determination for a named IMPACT class, not a licence to default an unknown.
- Your vocabulary does not map → gate it, and say so.

Your evidence being weak points DOWN, via EPISTEMIC STATUS. The schema failing
points UP. Those are different things and they are deliberately not symmetric.

## Prose: docs-writer owns WORDING, the domain agent owns TRUTH

Two different questions, two different owners:

- Is this text WELL WRITTEN (clear, accurate to convention, not stale)? ->
  `docs-writer`, including in-code comments and log/error-message text.
- Is this text TRUE? -> the domain agent. Ordinary C++ comments: `cpp-expert`.
  Lifetime / ownership / thread / callback / syscall claims: `cpp-safety`.
  Auth, authz, crypto, control claims: `security-guardian`. Erlang:
  `gateway-erlang`. CI / build / release: `build-ci` or `release-deploy`.
  Normative architecture text — ADRs, invariants documents, routed-concern rows:
  `architect`, plus `security-guardian` where the text states a security posture.

So: report a comment or doc when it CONTRADICTS the code — that is a truth finding,
at your own native severity, and it is yours to raise whatever agent you are. A
WORDING-ONLY observation belongs to `docs-writer`: if you are any other agent, do
not file it at all. That is the half that makes this a consolidation rather than a
sixth opinion — routing prose to one reviewer only works if the other five stop.
`docs-writer` files wording at NICE, capped.

Exception, and it is load-bearing: a factually false comment adjacent to a security
or control-flow branch IS a contradiction, not wording. #2202 shipped a comment
asserting the opposite of what its function did, next to an authz branch.

**Absence is a third category, and it is NOT wording.** A behaviour change with no
doc at all contradicts nothing, so the cap does not reach it: a missing required doc
is a TRUTH finding, derived per standing rule 2 as `I7` (SHOULD by default, BLOCKING
where the omission conceals a breaking change, security-relevant behaviour, a
data-loss risk, a migration step, or an irreversible operation). Never file a
missing-doc finding as NICE on the grounds that it is "documentation".

**"Required" is defined, not judged.** A doc is required when it is one of these,
and nothing else:

  1. the REST API reference, for a changed endpoint signature, body, error path or
     permission
  2. a `docs/user-manual/` section, for a changed operator workflow, CLI flag, env
     var or upgrade step
  3. a `changelog.d/` fragment, for an operator-visible change
  4. `CLAUDE.md` or a routed-concern row, for a new architectural invariant, store,
     ABI pattern or release gate
  5. an audit-action, permission or error-code table the change's contract touches
  6. a doc a `.claude/routed-concerns.md` row names as an **update obligation for
     the changed surface** — whether operator-facing (a user-manual page for a
     changed feature) or author-facing (a migration ladder, a capability registry,
     a per-surface invariants doc that records each change as it lands). What it is
     NOT is the row's **reading list**: `docs/cpp-conventions.md` is named for *any*
     C++ change so the reviewing agent LOADS it, and reading "names the doc"
     literally would make every C++ PR that does not edit it a missing-doc finding.
     The test is whether the doc accrues an entry per change, not who reads it.

**In-code prose never qualifies.** An uncommented function is not a missing required
doc. Without that boundary the rule becomes a laundering route: any wording nit
restates as "the doc does not state X" and walks from NICE to SHOULD, re-creating
the noise this whole line of work exists to reduce.

An absence finding must cite which of the six it rests on. If you cannot, it is a
wording finding or nothing.

For `I4` and `I7` findings, EXPOSURE is `E3` unless you can name a specific reason
otherwise. A document that isn't there is read by an ordinary operator; it is not a
timer and not an escalation. Recording `unresolved` here instead would gate every
missing doc, contradicting the `I7`-is-SHOULD-by-default rule two paragraphs up.

(Capping wording rather than banning it is deliberate: deciding whether prose is
descriptive or normative is exactly the disputed question, so a mis-classification
should cost a line of noise, not a lost finding.)

## Verify what you can, read-only

Verify the reviewer read what you think it read. A finding derived from corrupted
input is confident and wrong, and reads exactly like a finding derived from clean
input — a shell `patsub_replacement` setting silently rewrote every `&` in a review
payload on #2622, and the corruption was invisible in the output. Echo back a
distinctive line of the source before trusting a review of it.

Where a claim can be tested cheaply — a query, a compile, a one-case test — TEST IT
and report the output. An empirically verified finding outranks a reasoned one, and
a reasoned finding about observable behaviour should say it was not verified. The
highest-value finding of the #2580 run came from an agent running a real query
against a live Postgres rather than reasoning about the SQL.

READ-ONLY, against disposable state only. Never mutate a live store, and never run a
destructive statement to raise a finding's standing.
```

---

## Gate 1 — Change Summary

You write this yourself, from `git show` and `git diff --stat`. Structure:

- **Commits in scope** — table with sha, subject, push state
- **Files touched** — table with path, delta description
- **Interfaces affected** — public API changes, store contracts, REST behavior, proto, plugin ABI, CI gates
- **Security surface** — what's closed, what's opened, net-neutral explanation
- **User-facing impact** — behavior changes, breaking changes, new flags
- **Resource Ledger** — for C++ changes, list every new or modified fd,
  HANDLE, SOCKET, `FILE*`, `sqlite3_stmt*`, `sqlite3*`, OpenSSL object,
  BCrypt handle, allocated C string, mapped library, temp path,
  subprocess, callback context, and thread. For each, name owner type,
  acquisition point, release point, transfer behavior, and failure
  cleanup.
- **Prior validation performed** — compile, tests, script runs with exit codes
- **Governance domains triggered** — which Gate 3 agents apply (see matrix below)

Write this in your own response before invoking any agents. All downstream agents reference it, so skimping here wastes the whole run.

---

## Gate 2 — Mandatory security + docs review

Launch both agents in a **single message with two tool calls** so they run in parallel.

### security-guardian preamble template

```
Full governance Gate 2 review of <N> commits on branch <branch> at
<repo-root>: <sha1>, <sha2>, ...

Use `git show <sha>` to view each commit. The working tree is clean;
what you see in <range> is the full scope.

## Your job

You are the mandatory security reviewer for Gate 2. Read every
modified file top to bottom (CLAUDE.md requires it) and assess:

<finding-specific questions — fill in based on the actual change>

## C++ safety ownership proof

For any C++ diff, verify the Resource Ledger and independently prove
ownership for every fd, HANDLE, SOCKET, `FILE*`, `sqlite3_stmt*`,
`sqlite3*`, OpenSSL object, BCrypt handle, allocated C string, thread,
callback context, subprocess, mapped library, and temp path. Each
resource must have exactly one owner, one release path, explicit
transfer behavior, and checked failure cleanup.

Manual cleanup in NEW C++ code is a policy floor (see the shared preamble)
unless it is wrapped in a small RAII owner/scope guard or the exception is
documented as impossible to express safely. Pre-existing cleanup in a file
this change merely touches is SHOULD, not a floor. Check every early return between
acquire and release.

Shell-command surfaces are high risk: new `system()`, `popen()`, shell
strings, `fork`/`exec`, or `CreateProcess` usage must prefer argv-style
execution unless a documented exception explains why a shell is required.

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

## New authz surface / principal class check (LOAD-BEARING)

Added after PR #2202: a rebase of already-gated engine-principal code
shipped **4 HIGH** auth findings (fleet-wide-read-when-RBAC-off,
boots-clean-on-corrupt-rbac.db, engine-audit-mislabelled, resolver
branch with no production caller) through a 14-agent `/governance` run
AND two Hermes passes. An external panel caught all four on first
contact. The gap: reviewers checked the *new routes* and the surface a
recently-added deny-belt already covered, and never traced the
capability's authority across the whole authz layer.

When a diff adds or changes a **principal class**, an `auth_source`, an
authorization **entry point**, or any capability reachable by a new kind
of actor, do ALL of the following — do not sample:

1. **Chokepoint coverage, not file coverage.** Enumerate *every*
   authorization chokepoint an actor of that class can reach —
   `require_permission`, `require_scoped_permission`, `require_admin`,
   every inline `check_permission`/`check_scoped_permission`,
   `authorize_list_read` (`AuthRoutes::require_list_read` + its MCP /
   dashboard wrappers), the MCP tier gate, any service-scoped/elevation/
   legacy fallback — and prove the intended posture (allow/deny/step-up)
   at EACH. **List/fan-out reads of per-agent data are a DISTINCT
   chokepoint from per-object permission checks**: they MUST go through
   the admit-then-filter `authorize_list_read` (World A, ADR-0017 —
   `docs/adr/0017-management-group-confinement-list-reads.md`), never a
   bare global `require_permission` (which is inert for a confined
   operator and fails *open* on a corrupt `rbac.db`). A carve-out that
   gets every single-target check right but leaks a fleet-wide list is
   the same failure mode as #2202. A carve-out that sits only on the new
   routes, or only where a sibling guard happens to already sit, is the
   #2202 gap. Grep for the chokepoint functions (incl.
   `authorize_list_read`/`require_list_read`); do not reason from "the
   new code looks right."

2. **Test the DEFAULT deployment config, not the hardened one.** Re-run
   the authorization reasoning with the security-relevant toggle in its
   **default** state (e.g. RBAC *off* — the default — not RBAC on). The
   #2202 fleet-wide-read only triggered with RBAC off, which is exactly
   what nobody exercised. Ask: "what does this grant/deny when the admin
   has configured nothing?"

3. **Reachability of every new branch.** For each new authorization or
   resolution branch (a new `principal_type` arm, a new store method, a
   new grant path), grep for a **production caller**. A branch reachable
   only from tests is either dead code or a shipped-incomplete
   deliverable — say which. (#2202 Blocker 4: the engine RBAC resolver
   had no route that could author the grant it consumed.)

4. **Fail-closed on infra failure.** For any authoritative read in the
   authz/identity path — a *new* read, OR an existing resolver that this
   change makes newly load-bearing for the new actor type (a resolver can
   become security-critical for a new principal without a line in it
   changing) — confirm a store/DB failure denies or refuses boot, never
   reads as an empty/absent result that silently allows. Check the
   engaged-empty-vs-`nullopt` / `std::expected` distinction.

5. **Comment-vs-code diff.** Read each comment near a new authz branch
   against the code it describes. #2202 Blocker 2 shipped a comment that
   asserted the *opposite* of what the function did (`nullopt` on
   failure) — a lying comment is a strong signal, not decoration.

6. **Audit attribution survives to the row.** Trace the new actor through
   EVERY audit helper it can reach (`make_audit_event`,
   `emit_behavioral_audit`, any inline `audit_log`/`.log({...})`) and
   prove the persisted row carries the stable authorization principal,
   the correct `principal_class`, the correct `auth_source`, the
   effective role, AND correct attribution on the *denied* path — never
   the creating human, a presentation-only default, or a half-set field.
   #2202 Blocker 3 stamped engine actions as `principal_class=agent`
   because `make_audit_event` set the class before session resolution and
   never re-stamped. "Audit events are emitted" is NOT enough — the
   fields must be *correct* for the new actor.

## Design-contract & state-machine tracing (LOAD-BEARING)

Added after PR #2284: an external reviewer reading the design doc
line-by-line found real defects across THREE rounds that a 14-agent
`/governance` + Hermes ×2 had passed — because our gates reviewed the
*diff mechanics* (does the merge compile, is the carve-out present) but
never traced the PR's own *published contracts* and *state-machine
semantics* against the code. Fold that depth in here.

When a PR (a) touches a **state machine** (rotation, lifecycle CRUD,
deployment, enrollment — anything with ordered transitions or
paired/linked rows), (b) makes a **published-contract** claim (a
normative statement in docs / OpenAPI / changelog / a design doc — "a
second mint errors", "rejected outright, never truncated", "revocation
resolves the rotation state", "idempotent — does not re-emit"), or (c)
adds/changes a **classifier** (a substring allowlist, an enum switch, an
error→status map), do ALL of the following:

1. **Trace every normative claim to code.** For each "always / never /
   must / rejects / idempotent" statement in the docs / OpenAPI /
   changelog / design doc this PR touches, find the line that enforces it
   and confirm it actually does. A claim is a CONTRACT, not a
   description. #2284 shipped "a second mint errors" (no ceiling check),
   "rejected outright, never truncated" (the MCP twin silently clamped),
   and an OpenAPI `{id}` description that 404'd every real principal. If
   doc and code disagree, ONE is a bug — say which; never assume the doc.

2. **Enumerate mutation × state for the machine.** List every mutating
   operation the actor can invoke AND every state a linked/paired row can
   be in, then walk the cross-product: does any combination wedge the
   machine, orphan a partner, or drop to an unsafe terminal? Trace the
   OUT-OF-BAND paths — a single manual revoke mid-rotation, a retry after
   a lost response, a delete of a linked row — not just the happy
   transitions. #2284 §7: a manual successor-revoke let the sweep
   auto-revoke the principal's ONLY credential to zero; a manual
   predecessor-revoke wedged the pair classifier.

3. **Prove classifier / allowlist completeness.** For a substring
   allowlist or enum map: enumerate EVERY value it must handle — every
   distinct `unexpected(...)` / error string the callee can emit, every
   enum case — and confirm each is classified. A shared classifier must
   be complete for BOTH transports (REST + MCP). A missed value defaults
   silently to the wrong class: #2284 mapped a permanent "not found" to a
   *retryable* error twice, on strings the allowlist missed. Require a
   unit test that locks the mapping (grep the callee's error strings;
   assert each maps to the intended class).

4. **Fail-visibility of a sole-enforcement path.** If a background /
   periodic task is the ONLY thing enforcing an invariant (an auto-revoke
   sweep, a reconcile loop), confirm its failures are observable — a
   swallowed error that returns empty must still bump a counter / log, or
   the invariant silently lapses with the alert at zero (#2284 M6).

## New-error-branch audit

If this PR adds any new 4xx/5xx error-response branch in a handler,
audit every response-body construction in the branch for information
disclosure. A denied/not-found fragment that echoes the caller's
permitted view is NOT safe if the rendering function itself queries
unfiltered data — this is how UP-11 shipped in the #222 hardening
round.

## Output format

Findings table with severity (CRITICAL / HIGH / MEDIUM / LOW / INFO),
file:line, description, recommended fix, and the four derivation facts.
Blocking is decided by the derived band per the shared preamble — do not
assert it from your own label. Also note any invariants the changes
*strengthen* that should
be preserved against future regression.

Report in under 800 words.
```

### docs-writer preamble template

```
Full governance Gate 2 docs review of <N> commits on branch <branch>
at <repo-root>: <sha1>, <sha2>, ...

Use `git show <sha>` and `git diff <range>` to see the full scope.

## Your job

You are the mandatory docs reviewer for Gate 2. Read every modified
file and the related user-facing documentation. Per standing rule 2:
a user-facing behaviour change with no doc is `I7` — SHOULD by default,
BLOCKING when the omission conceals a breaking change, security-relevant
behaviour, data-loss risk, migration step, or an irreversible operation.
Do not assert a blanket BLOCKING.

You own WORDING everywhere prose appears, not only in documentation
FILES: in-code comments and log/error-message text are yours too
(standing rule 3), and you are the ONLY agent who files wording —
the others are told not to. The DOMAIN agent owns whether that prose
is TRUE: a comment that contradicts the code is theirs to raise, at
native severity. When you spot one, report it and say which agent owns
the truth call rather than sizing it yourself — Gate 3 and Gate 8
prompts carry your findings forward, so naming the owner is what
transfers it.

A required doc that is MISSING is a third category, not wording:
absence contradicts nothing, so it is a truth finding derived as `I7`
above, never capped at NICE (the `I7` cap at HIGH still applies).
"Required" is the six-item list in the shared preamble — checks 1–5
below correspond to items 1–5, and item 6 is a routed-concern row that
names a doc as the operator-facing reference for the changed surface,
not merely as reading for the reviewer. Check 6 (in-code prose) can
never produce an absence finding.

Specifically verify:
1. REST API docs (`docs/user-manual/rest-api.md`) — endpoint signature,
   request/response body, error paths, permissions
2. User manual feature sections (`docs/user-manual/*.md`) — operator
   workflow changes, new CLI flags, new env vars, upgrade notes
3. Changelog — a `changelog.d/<PR#>-<slug>.<section>.md` FRAGMENT.
   `CHANGELOG.md` itself is FROZEN: never edited directly, enforced by a
   hook and the `Changelog fragments` CI job. Flag any direct edit to
   `CHANGELOG.md` as BLOCKING. (See `changelog.d/README.md`.)
4. CLAUDE.md — new architectural invariants, new stores, new ABI
   patterns, new release gates
5. Any audit action table, permission table, or error-code table
   that the REST/store/plugin API contract touches
6. In-code prose the diff ADDS OR MODIFIES — comments, log lines,
   error and user-facing strings: clarity, staleness, spelling, house
   convention. Scoped to changed lines, NOT to every comment in a
   touched file; on a large C++ diff the whole-file reading would
   crowd out checks 1–5, which are the ones that produce the `I7`
   findings that actually gate. Wording is capped at NICE. If the text
   asserts something the code does not do, that is a contradiction:
   report it and name the owning domain agent, who sizes it. Check 6
   can never produce an absence finding

## Output format

Severity is DERIVED, per the shared preamble — state TRIGGER, IMPACT
(every `I` that applies), EXPOSURE (every `E`), and EPISTEMIC STATUS
for each finding, then the derived band and your own label. A missing
required doc is `I7`, sized there; do not restate the rule, apply it.
SHOULD-FIX = doc drift that would confuse an operator.
NICE-TO-HAVE = style/precision improvements, and all wording findings.

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
| Any C++ file (`*.cpp`, `*.hpp`, `*.h`) | **cpp-expert**, **cpp-safety** |
| `tests/`, new fixtures, coverage gaps | **quality-engineer** |
| `meson.build`, `vcpkg.json`, `.github/workflows/`, release tooling | **build-ci** |
| `agents/plugins/`, plugin YAML defs | **plugin-developer** |
| `gateway/` (Erlang) | **gateway-erlang** |
| CEL expressions, scope DSL, trigger templates, YAML DSL spec | **dsl-engineer** |
| Windows-only / macOS-only code, cross-platform helpers | **cross-platform** |
| SQLite query paths, BFS/graph, hot authz paths | **performance** |
| Raw resource/process/cast APIs in C++ (`popen`, `system`, `fork`/`exec`, `CreateProcess`, `dlopen`, `LoadLibrary`, `open`, `socket`, `sqlite3_prepare`, `EVP_*`, `BCrypt*`, `LocalAlloc`, `yuzu_ctx_*`, `raw()`, `release()`, `reinterpret_cast`, `const_cast`) | **cpp-safety** |
| Background thread or callback storing pointer/reference | **cpp-safety**, **sre** |
| Packaging, systemd units, Dockerfiles, installer scripts | **release-deploy** |
| New/changed REST route, MCP tool, dashboard fragment/page, or any other capability-adding operator surface | **architect**, **security-guardian** — both apply the ADR-1005 standing question (below) |

### Standing rule — routed triggers are UNCONDITIONAL

Do not gate any routed-concern trigger, or any "always include" rule below, on diff
size or a materiality threshold. `.claude/routed-concerns.md` keys on **file identity
and change type**, because those files carry catastrophic-if-violated invariants
regardless of line count. Any roster trimming may only choose among agents those rules
did **not** already select.

A 2026-07 proposal to run a "core four" on small diffs was BLOCKed by two independent
adversarial reviews, which produced these kill shapes — all "single-file, small, no
public surface":

- **10 lines of `gateway/config/sys.config`** weakening management-listener client-cert
  verification. `gateway-erlang` dropped; `cpp-safety` is useless on Erlang config; the
  PKI route calls a plaintext gateway a fleet-RCE edge.
- **A retention/prune tweak.** The clock-guard row mandates `cpp-safety` + `sre` +
  `compliance-officer` (#2360/#2361) — two of the three would have been dropped.
- **A one-line `.github/workflows` `if:` guard.** The failure-path-guard invariant went
  silently dead for two months (#1038); that is `build-ci`'s domain.
- **Any small C++ diff**, because a "core four" contains no portability reviewer — the
  exact gap that shipped #2580's macOS break.

Rationale and the full review record: `docs/governance-skill-tuning-2026-07.md`.

**Always include architect** when any public store contract or REST API surface changes — the duplicate-validation and error-mapping drift patterns recur.

**Always apply the ADR-1005 standing question** on any capability-adding diff: is every behavior of this capability reachable by an authenticated external principal via versioned REST *and* MCP, or a recorded exception in ADR-1005's exception ledger; is it discoverable (A2/A3 — enumerable via `/api/v1/openapi.json` / MCP `tools/list`); does it carry the A4 error envelope; is there no in-process-only behavior; are RBAC and audit enforced at the API layer (not only in the UI)? A dashboard fragment is not an API twin. (Policy: `docs/adr/1005-headless-platform-use-case-engines.md`; current phase status: `docs/adr-1005-execution-plan.md` — both land with PRs #1918/#1926; do not merge this wiring before them.)

**Always include quality-engineer** when new features or fixes land — it's the only agent that flags fixture races, bad error-string substring asserts, and REST-handler-untested-through-store-tests, which are the three highest-ROI test gaps.

**Always include performance** for anything that touches `get_*_ids`, SQLite BFS, or per-authz hot paths.

**Always include cpp-expert and cpp-safety** when C++ files change.
The roles are separate: `cpp-expert` reviews language idiom and compiler
portability; `cpp-safety` reviews ownership, lifetime, C ABI borrowed
data, syscall/process boundaries, casts, thread teardown, and sanitizer
coverage.

For C++ safety-sensitive diffs, ask **quality-engineer** to require
tests for cleanup paths, partial failure, short read/write, EINTR,
failed `pclose`, failed `CloseHandle`, failed `sqlite3_prepare`, and
concurrent teardown where relevant. New RAII wrappers should have a
test or compile-time assertion covering move-only/non-copyable behavior
when feasible.

### Gate 3 agent preamble

Each Gate 3 agent gets the same structural preamble, varying in the "Your job" stanza:

```
Full governance Gate 3 <agent-type> review of <N> commits on branch
<branch> at <repo-root>: <sha1>, <sha2>, ...

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
at <repo-root>: <sha1>..<shaN>.

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

If this PR touches a STATE MACHINE (rotation, lifecycle CRUD,
deployment, enrollment — ordered transitions or paired/linked rows),
also enumerate **mutation × state**: every mutating op × every state a
linked/paired row can be in, and walk the cross-product for a
combination that wedges the machine, orphans a partner, or drops to an
unsafe terminal (e.g. zero credentials). Prioritise OUT-OF-BAND paths —
a single manual revoke/delete of one linked row mid-transition, a retry
after a lost response — over the happy transitions (see the security
preamble's "Design-contract & state-machine tracing" check; this is how
#2284's §7 auto-revoke-to-zero and pair-wedge defects shipped past an
earlier /governance run).

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

7. **Changelog fragment** present and well-formed — `changelog.d/<PR#>-<slug>.<section>.md`,
   valid section, `CHANGELOG.md` untouched. (The old `[Unreleased]`/reverse-chronological
   invariant is ABOLISHED — the file is assembled at release from fragments.)

8. **ADR-1005 headless-platform parity** — for any capability this PR
   adds or changes: is every behavior reachable by an authenticated
   external principal via versioned REST *and* MCP, or a recorded
   exception in ADR-1005's exception ledger; is it discoverable
   (A2/A3 — enumerable via `/api/v1/openapi.json` / MCP `tools/list`);
   does it carry the A4 error envelope; is there no in-process-only
   behavior; are RBAC and audit enforced at the API layer (not only
   in the UI)? A dashboard fragment is not an API twin.

9. **A5 agentic context contract** (exec-plan Decision 16) — for any
   new or materially changed MCP tool ("material" = any change to
   tier, securable/operation, dispatch behavior, side-effect set, or
   spec-visible `tools/list`/`initialize` output — per-se, not
   arguable): standard spec annotations (`title`/`readOnlyHint`/
   `destructiveHint`/`idempotentHint`/`openWorldHint`; destructive/
   idempotent semantics machine-readable, never prose-only),
   decision-grade description (when to use, workflow chaining,
   empty-result meaning), bounded documented input schema, typed
   output schema for stable shapes, honest `retry_after_ms` on
   retryable errors; if the PR adds a tool family or reshapes the
   operating model, the `initialize.instructions` blob is updated in
   the same PR. Contract text: `docs/agentic-first-principle.md` §A5.
   security-guardian co-checks `readOnlyHint`/`destructiveHint`/
   `idempotentHint` truthfulness against tier + dispatch behavior —
   a false safe-direction hint derives `I4` (harmful operator guidance).

10. **Published-contract vs code, and classifier completeness** (see the
   security preamble's "Design-contract & state-machine tracing" check).
   For every normative claim this PR touches in docs / OpenAPI /
   changelog / a design doc ("a second X errors", "rejected outright,
   never truncated", "idempotent — does not re-emit", a `{id}`/param
   format), trace the enforcing line and confirm the code actually does
   it — a claim is a CONTRACT; if doc and code disagree, ONE is a bug,
   name which. For any substring allowlist / enum→status map this PR adds
   or changes, enumerate EVERY value the callee can emit (grep its
   `unexpected(...)` strings / enum cases) and confirm each is classified
   the same on BOTH transports — a missed value silently defaults to the
   wrong class (#2284 mapped a permanent "not found" to a retryable error
   twice). A shared classifier of this kind must have a unit test locking
   the mapping.

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
8. **Severity / phase** — P0 block-merge, P1 pre-release, P2 nightly. P0 is a
   scenario-planning label, NOT a gate: a chaos scenario blocks only if the
   underlying finding derives CRITICAL/HIGH or hits a policy floor.

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
- **enterprise-readiness** — customer-facing assurance, pilot-visible rough edges, upgrade notes, breaking changes doc coverage; also reviews the A5 exception ledger (`docs/agentic-first-principle.md` §A5 Exceptions) — every entry must carry an issue number + revisit-by date; stale or undated entries are findings

Use the same structural preamble as Gate 4 agents, vary the "Your job" stanza to the agent's domain.

**Watch for:** sre routinely catches pre-existing readiness-probe gaps that become gating because the PR makes an existing store more load-bearing (they derive `I5`/`I1` once the store is on a live path). The HC-1 pattern (store missing from `/readyz`) reappears — always verify the new store(s) in scope are in the probe conjunction.

**Watch for:** enterprise-readiness flags breaking-changes-without-upgrade-note more reliably than other agents. If the PR changes non-admin behavior, a changelog FRAGMENT carrying the Breaking entry (`changelog.d/<PR#>-<slug>.changed.md` or `.security.md`, body led with `**Breaking —**`) plus a `docs/user-manual/server-admin.md` upgrade note is almost always required. Do NOT ask for a `CHANGELOG.md` section — that file is frozen and edited only at release.

---

## Gate 6b — Synthesis pass (presentation only)

A full run produces on the order of 45 non-blocking findings, each as its own block of
prose, with the same defect frequently reported by two or three agents at full length.
On #2580, four of six round-1 BLOCKINGs arrived 2–3 times over. All of the triage
landed on the operator, and `workflow-orchestrator` — which exists for exactly this —
was never invoked.

Run it now, over the raw reports:

```
Agent (workflow-orchestrator): Synthesise the attached Gate 2/3/4/6 reports into a
single severity-ordered table for the operator. Preserve EVERY source report verbatim
as an appendix — you are changing presentation, not content.

Cluster two findings ONLY when they share the same file:line AND the same defect.
Anything else stays separate. For each cluster: list its reporting agents, take the
MAXIMUM **derived** severity of its members (record the native labels alongside),
and do NOT re-adjudicate severity or dismiss a
finding. Mark every cluster PROVISIONAL.
```

Three rules, all load-bearing:

- **Same `file:line` AND same defect.** Never "same theme". On #2580, the BLOCKING for
  the incomplete REST classifier and the BLOCKING for the hardcoded MCP retry hint
  summarise almost identically and needed **separate fixes and separate tests** — a
  synthesiser merging on theme would have hidden one of them.
- **Max severity, never re-adjudicated.** The synthesiser has not read the code.
- **Clusters are provisional; the operator confirms equivalence.** The synthesiser is
  not the authority on whether two findings are the same finding.

Convergence is the strongest confidence signal this pipeline produces — "found
independently by three agents" is why a finding gets acted on without re-derivation.
This pass keeps that signal and drops the re-reading; it must not launder it.

**But count only INDEPENDENT reporters.** This pipeline manufactures correlation on
purpose: Gate 3 is handed Gate 2's findings and Gate 4 is handed Gate 2's and Gate
3's, all "for your context only, do not duplicate". An agent that was SHOWN a
finding and agrees is an echo, not a confirmation. The test is **not having been
shown it**: agents in the SAME parallel wave qualify, because they could not see
one another, and so does any reporter of any `source` who was not shown it — a
collaborator or an external model reviewing the change cold is in no wave at all,
and counting them zero inverts the signal for the strongest evidence available.

So the attribution line reads `independently: 2 of 4 (Gate 4 wave); echoed: 1
downstream`, never a bare count. A finding echoed by five downstream agents and
raised independently by one is a ONE-agent finding. Record `independent_reporters`
in the ledger, not just `reporter`.

This cuts both ways and neither direction is safe to assume: correlated reviewers
overstate confidence, and a reviewer that defers to a peer's partial conclusion can
withdraw a finding that was correct. Both have happened here inside a month — three
reviewers confirming a false claim because they shared one stale working tree
(#2604), and a reviewer dropping a true finding on a peer's incomplete evidence
while that peer was independently confirming it (#2622). Neither is visible from
the output. When it matters, measure the claim yourself rather than counting who
agreed.

---

## Gate 7 — Findings Resolution

**BLOCKING** = the derived band is CRITICAL or HIGH (shared preamble), or a policy floor was hit. Resolve against the derived band, not the reporting agent's native label — record both. An agent brief that says its own CRITICAL/HIGH "blocks merge" does NOT self-certify: that text predates standing rule 2 and is superseded by the derived band. The only non-derived blocker is a policy floor or an explicit operator instruction.

Strategy:
1. **Fold compatible fixes into one commit.** If sec flags H1, docs flags B3, QA flags B5, and they all touch related files, fix as a single "hardening round" commit rather than three small ones.
2. **Re-run Gate 2 security on the hardening round.** Prior runs have caught HIGH regressions introduced by the fix commit itself. Always re-review.

## Gate 8 — Iterate And Ledger

1. **Re-run every gate whose DOMAIN THE FIX DIFF TOUCHES** — not only those whose
   findings prompted the fix. A fix that adds a language feature, a dependency, a
   thread, or a platform-specific call re-triggers the corresponding agent **even if
   that agent raised nothing in round 1**.

   Concretely, against the **fix diff** (not the original):
   - **Gate 3** — re-run the decision matrix, including the routed-concern table.
   - **Gate 2** — `security-guardian` always; `docs-writer` whenever the fix touches
     a doc, a changelog fragment, a user-facing string, or in-code prose.
   - **Gates 4 and 6** — re-run an agent when the fix changes behaviour in its
     domain: `happy-path`/`unhappy-path` on any logic or error-path change,
     `consistency-auditor` on any cross-surface or contract change, `sre` on any
     metric, alert, probe or thread change, `compliance-officer` on any audit or
     evidence change, `enterprise-readiness` on any operator-visible behaviour or
     upgrade-note change.
   - When in doubt, re-run it. A skipped re-review is how the fix round ships its
     own defect.

   This rule exists because the old one ("only the gates whose findings would be
   affected") shipped a broken macOS leg on #2580. Gate 8 ran the four agents whose
   findings had been fixed; `cpp-expert`, the portability reviewer, had only ever seen
   commit 1. `std::jthread` was introduced in commit 3 **as a fix for a Gate 8
   finding** and broke Apple Clang, whose libc++ has no `std::jthread` — every other
   use in this codebase sits behind `#ifdef __cpp_lib_jthread`. No agent was ever
   asked whether the fix was portable.

2. **Don't commit until governance passes.** Per CLAUDE.md.

3. **Record every finding in the run ledger.** One JSONL object per finding, in a
   **repo-committed fragment** on the `changelog.d` model (#2618):

   ```bash
   # Default: a fragment in the repo, committed with the work it reviews.
   # Override to a scratch dir for a throwaway local run you will not commit.
   GOV_DIR="${YUZU_GOV_LOG_DIR:-governance.d}"
   mkdir -p "$GOV_DIR"

   # O_EXCL must protect the path that is actually COMMITTED. `mktemp` on a stem
   # followed by `mv "$X" "$X.jsonl"` does NOT: mv overwrites silently, so a
   # suffix collision destroys the earlier run's findings with no error at all.
   # `mktemp -u` supplies only the random stem; `noclobber` does the atomic create.
   LEDGER="$(mktemp -u "$GOV_DIR/<PR-or-issue-number>-<short-slug>.XXXXXX").jsonl"
   (set -o noclobber; : > "$LEDGER") \
     || { echo "ledger exists, refusing to overwrite: $LEDGER" >&2; exit 1; }
   ```

   **Do not "simplify" this to `mktemp "$GOV_DIR/….XXXXXX.jsonl"`.** GNU `mktemp`
   accepts `X`s mid-template; BSD/macOS `mktemp` requires them trailing, and this
   repo ships macOS. The two-step exists for portability — the bug was doing the
   second step with `mv` instead of an exclusive create.

   The `noclobber` redirect is what makes the guarantee: the committed `.jsonl`
   path is created `O_EXCL`, so a suffix collision FAILS LOUDLY instead of
   overwriting. Uniqueness is enforced by the filesystem rather than assumed from
   a timestamp. One file per RUN, not per PR: Gate 8 iterates, `pass_ordinal`
   distinguishes rounds inside a file, and a fresh run gets a fresh fragment.

   **Every write after the create is an APPEND. Never `>`.**

   ```bash
   printf '%s\n' "$ROW" >> "$LEDGER"     # the ONLY way to add a row
   ```

   `noclobber` above is scoped to its subshell and protects the CREATE only — it
   does nothing for a later write, and your interactive shell does not have it set.
   Measured: the create idiom copied one line later, outside that subshell,
   truncated a two-row ledger to one row with **exit 0 and no output**. That is the
   same silent-overwrite class the `mv` recipe was rejected for, re-entering through
   the write the next paragraph blesses, so the append idiom is stated here rather
   than left to be inferred from the nearest visible redirect.

   Concurrent `>>` appends measured safe on a local filesystem — 20 parallel
   appenders of 4 KB rows, and 12 of 90 KB rows, produced zero lost or torn lines
   under `O_APPEND`. That is a measurement, not a general guarantee: no network
   filesystem was tested. It is the read-modify-write that loses rows, which is why
   the supersede rule below forbids editing a row in place.

   **A row is SUPERSEDED, never edited.** A disposition that changes after the fact
   — a finding later fixed, deferred, or refuted — is a NEW row carrying the same
   `finding_id`.

   **The live view of a finding is FIELD-WISE last-write-wins across every row
   sharing its `finding_id`, ordered by `recorded_at`** — not the latest row alone.
   That distinction is load-bearing: a superseding row restates only what changed,
   so "the latest row is the live one" would make a floored, gating finding read as
   ungated and unclassified the moment a `fixed` row omitted `severity_mapped` and
   `policy_floor`. Merge; do not replace. Ties, which should not occur, break on the
   higher `pass_ordinal`.

   **List fields REPLACE wholesale, they do not union.** `impact` and `exposure` are
   the two. A supersession restating `impact: ["I8"]` over `["I2","I5"]` yields
   `["I8"]`, not all three. Two conforming readers, one unioning and one replacing,
   would otherwise produce different live views from the same bytes; the same "an
   unstated convention means no reader can be right" that settled the row rule
   settles this one.

   **ATTESTATION FIELDS ARE ROW-SCOPED AND EXEMPT FROM THE MERGE.** The four are
   `adjudicated_by`, `adjudication_rationale`, `refuted_by` and
   `refuted_by_reporter`. They are NOT properties of the finding, so merging them
   forward is a category error: an attestation attaches to the ACT it approves — this
   de-escalation, this refutation — and a reader binds each to the row that performed
   that act. They are never inherited by a later row and **never cleared by one**.

   Without that exemption the guard erases itself: append a row nulling
   `adjudicated_by`, and the live view shows a de-escalated finding with no
   attestation, while gate and band are unchanged — so the gate-or-band property does
   not fire. Measured on this change's own ledger, where the rows that withdrew two
   adjudications did exactly that, and the commit that wrote them called it a worked
   example. Every prior round of this defect was "a route that moves the band or the
   gate"; this one is a route that **removes the control** from a finding already
   moved, which is why naming the gate as the property did not reach it.

   To withdraw an attestation you supersede the ACT it approved — restate the facts
   or label it authorised, back to where they were. You cannot retract the signature
   and keep the effect. Unlike the routes above, this class is CLOSED by the schema:
   the attestation set is exactly those four fields.

   ### De-escalation — the guarded property is THE GATE, not a list of fields

   **READ THE MERGED VIEW AT THE STRONGER OF ITS FACTS AND ITS LABEL.** The label is
   3-valued and bands are 5-valued, so each label denotes a SET:
   `BLOCKING` = {CRITICAL, HIGH}, `SHOULD` = {MEDIUM}, `NICE` = {LOW, INFO}.

   - Derived band INSIDE the label's set → they agree; the derived band governs.
   - Derived band OUTSIDE it → they disagree. The finding is read at the stronger of
     the derived band and the label's FLOOR (HIGH / MEDIUM / LOW respectively), and
     the disagreement is itself reported.

   Comparing against the floor alone would be wrong, not merely conservative: an `I9`
   finding labelled `NICE` derives INFO, which is below LOW, so a floor comparison
   reports a disagreement on every correctly-recorded NICE row. Two rows in this
   change's own ledger did exactly that. `impact: []` or a null fact set derives INFO.
   A `policy_floor` present anywhere in a finding's history gates until explicitly and
   adjudicatedly cleared.

   Disagreement between facts and label is not resolved in the writer's favour — it
   resolves upward, and it is itself a finding about the ledger. For a CONFORMING
   writer the two can never disagree, because `severity_mapped` is defined as the
   derived value; this rule exists for the non-conforming writer, and that is exactly
   the case round 5 measured (a label restated unchanged beside weakened facts).
   So: when the facts change, restate the label. A stale label is read at the stronger
   value and is reported.

   **Any supersession that WEAKENS THE GATE OR THE BAND requires an `adjudicated_by`
   who is not the change's author, plus an `adjudication_rationale`.** The guarded
   property is "would this row make the finding less likely to stop the merge" — the
   band is the usual mechanism but it is NOT the only one, and the routes below
   include three that are band-NEUTRAL. Known routes, non-exhaustive:

   - `severity_mapped` restated downward
   - `impact` or `exposure` restated to weaker values — note `E6` caps at LOW and
     dominates every raise, so `exposure: ["E6"]` alone is a de-escalation
   - `severity_mapped` restated UNCHANGED beside weakened facts. Band-neutral under
     the stronger-of rule, and still a de-escalation attempt: it is the shape round 5
     shipped, and the requirement was never "restate the label"
   - `epistemic_status` flipped to `speculative` — band-neutral by design
     (EPISTEMIC STATUS operates on the GATE, not the band) and it converts a blocker
     into a deferred investigation, which is the whole point of guarding it
   - `provenance` flipped to `pre-existing` — band-neutral, and it demotes two
     policy floors
   - `policy_floor` cleared — band-neutral, and it is the floor
   - **a sentinel released**: `exposure` or `trigger` moved from `unresolved` to a
     concrete value. Band-neutral, and it lifts a gate — unresolved EXPOSURE "GATES
     pending adjudication", so supplying the resolution IS the adjudication and needs
     the same independence. Defaulting an unknown to `E3` unattended is precisely
     what the absences rule forbids
   - a terminal `disposition` of `rejected` or `deferred-to-issue #N` over a live
     gating row
   - **`commit_range` or `reviewed_at_sha` set to `unresolved` by the author** — it
     voids the only verifiable half of the adjudication guard below (the self-naming
     check reads git authors over the range), so it weakens the gate by disarming its
     own precondition

   **A new field, or a new route, must be tested against the PROPERTY** — does it
   weaken the gate or the band, OR remove an attestation from a finding that has
   already been de-escalated — and added to this list when it does. The list is
   openly incomplete; treating it as closed is what let round 5 ship.

   **What the adjudication requirement actually achieves — read this before relying
   on it.** It is an AUDIT TRAIL, not a verified control. It makes a de-escalation
   attributable and reasoned in writing, and a reader with the repo can detect literal
   self-naming by comparing `adjudicated_by` against `git log --format='%an'` over
   `commit_range`. It verifies nothing beyond that: the field is free text, and an
   `adjudicated_by` naming a governance agent never matches a git author, so the
   self-check passes vacuously. **A subagent of the authoring session is not
   independent** — it is the same actor under another name. Independence here is
   ASSERTED, and the assertion is worth recording; do not describe it as enforced.

   **Why the property and not another guarded field.** Rounds 2–5 each hardened one
   route and left the next open: round 2 hardened `refuted`, round 3 found
   supersession-by-`fixed`; round 3 fixed precedence, round 4 found de-gating by
   omission; round 4 forbade lowering by omission, round 5 found explicit lowering;
   round 5 guarded the label, round 6 found the facts route — and a rule-conforming
   reader reported ZERO violations on a fragment that de-gated a BLOCKING finding.
   Round 6 named the band as the property, which closed that whole class provably
   (weakening one leg is inert under stronger-of, so an attacker must weaken both, and
   the second step is itself a band drop — closed under composition). But round 6 also
   claimed the rule "enumerates no fields", and round 7 disproved it: three of round
   6's own routes are band-neutral, and a sentinel release lifts a gate the band
   cannot see. The property is the GATE. This is the same lesson the
   clock-guarded-retention row records — "the fix is the fact set rather than a fourth
   patch" — with the correction that naming a property does not excuse you from
   checking whether it covers every mechanism.

   A supersession MAY correct `reporter` — a factual correction of a mis-recorded
   finder, not a re-attribution. `reporter` is immutable as to WHOM it names, not as
   to whether the row got the name right. A correction that changes `source` such
   that `reporter_ref` stops being required is a re-attribution, not a correction,
   and needs the de-escalation bar: it deletes the row's only third-party-retrievable
   reference.

   Precedence is `recorded_at`, NOT `pass_ordinal`, and the difference is
   load-bearing: a post-run row carries `pass_ordinal: 0`, so under an
   ordinal-ordered rule it could never supersede an in-run row at round 1 — a
   collaborator refuting a finding the run had closed would sit in the file,
   visible to `cat`, and be silently outranked by the published read rule. That is
   the exact case post-run appends exist to serve. `pass_ordinal` records WHICH
   ROUND a row belongs to; it was never a precedence key, and using it as one
   inverts the feature.

   A superseding row states why it supersedes: a `fixed` row cites the commit or
   `file:line` that fixed it, a `deferred-to-issue #N` row cites the issue. A
   supersession to `refuted` or `rejected` carries the same independence
   requirement as the disposition itself — otherwise the cheap path (append
   `fixed`, no evidence, no independent reporter) produces the same artefact-level
   read as the hardened one, and routes around it.

   State the read rule wherever a fragment is counted. Measured on the two candidate
   conventions, rewrite-in-place and append-a-second-row give different answers to
   "how many findings did this run raise" (2 vs 3) and to whether a refuted BLOCKING
   still reads as open (no vs yes). Either is workable; an unstated one means no
   reader can be right. Rewriting also destroys the prior disposition at the artefact
   level — `cat` shows only the final state — so the append convention is chosen.

   Only the fields that CHANGE need restating on a superseding row, plus
   `schema_version`, `run_id`, `finding_id`, `recorded_by`, `recorded_at`,
   `pass_ordinal`, `reviewed_at_sha` and `disposition`. A supersession is not a
   re-derivation: the original row keeps the TRIGGER/IMPACT/EXPOSURE facts unless
   the supersession is what changed them.

   **A supersession carries `recorded_by`, NOT `reporter`.** `reporter` is who FOUND
   the finding and never changes once written; whoever appends a later row is the
   recorder, and conflating the two misattributes the finding. Getting this wrong
   also breaks `source`: the first supersession ever written labelled a human
   appender `source: "governance-agent"` with no `reporter_ref`, which is precisely
   the "small forgery" the derivation note below warns about, and it escaped the
   `reporter_ref` requirement by claiming to be a pipeline row. `source` describes
   the REPORTER. If a human appends the row, `recorded_by` is their handle and
   `reporter`/`source` stay as originally recorded, subject to the correction carve-out above.

   `recorded_at` is self-declared and nothing validates it, which matters more now
   that it is the precedence key: an author who dislikes a collaborator's post-run
   refutation can append a later-timestamped `fixed` row and outrank it. The commit
   carrying the row is the corroborating witness — a `recorded_at` inconsistent with
   its commit time is suspect, and git is the substrate that makes that checkable.
   `pass_ordinal` was no better: equally author-typed, and broken as well.

   **Why in the repo.** The record is evidence for whoever reviews the PR — which
   findings were raised, which fixed, which deferred and by whom. A path under
   `$HOME` is unreadable by the reviewer by construction, and SOC 2 CC8.1 evidence
   has to be retrievable by someone other than whoever produced it. The cost is
   accepted deliberately, and it is NOT the changelog fragment's cost: an
   uncommitted changelog fragment is an untracked NEW file, so `git clean` removes
   it conspicuously. A row appended to an already-committed fragment is a
   MODIFICATION to a tracked file — `git clean -xfd && git checkout -- .` reverts it
   silently and leaves a plausible-looking ledger behind. Commit an append on the
   same push that makes the claim it records; a rebase, squash, or branch tidy over
   that commit is the loss path, and nothing detects it.

   There is still **no database and no shared store**; this is a per-run file that
   happens to be version-controlled. Retention — whether old fragments are pruned,
   assembled, or kept indefinitely as the access-review campaigns are — is a
   separate decision and is NOT made here. Do not describe it as more than it is.

   Fields, all required unless marked — on the row that FIRST raises a finding. A
   superseding row carries only the minimum set above plus what changed; the live
   view merges them, so "required" is a property of the finding, not of every row:

   | field | why |
   |---|---|
   | `schema_version` | integer, currently `1`. Per ROW, never per file: appends are permitted, so one fragment can legitimately hold rows written under two versions of this table. A row without it predates #2619 |
   | `run_id` | which run. `basename "${LEDGER%.jsonl}"` — the fragment's filename without its extension, e.g. `2619-ledger-provenance.sW31cX`. Stated as a command because "the mktemp stem" reads three ways: the random suffix alone, the basename, and the full path passed to `mktemp -u` (which varies with `YUZU_GOV_LOG_DIR`) |
   | `commit_range` | which diff. On a row from an external reviewer who read a head rather than a range, the range they were shown, or `unresolved` |
   | `reporter` | WHO found it — a governance-agent name, a person's handle, or a model id. ONE value, never a joined list: convergence is `independent_reporters`, and a `+`-joined string is an encoding no reader parses. Immutable as to WHOM it names — a supersession may correct a mis-recorded finder, but may not re-attribute the finding to someone else. Named `agent` before #2619; renamed because `source` below admits reporters that are not agents, and a required field with no honest value for two of its three cases is a schema defect, not a naming quibble |
   | `recorded_by` (nullable on the row that first raises a finding, required on a supersession) | WHO wrote this row, as distinct from who found the finding. Null means reporter and recorder are the same |
   | `source` | `governance-agent` / `collaborator` / `external-model` — WHAT KIND of reporter, distinct from `reporter`'s who. Spelled `governance-agent`, not `agent`, per CLAUDE.md's three-meanings glossary. A Codex or Kimi run driven by `.codex/skills/governance` is a `governance-agent` row — `external-model` is for a model reviewing OUTSIDE this pipeline. A non-`governance-agent` row MUST carry `reporter_ref` |
   | `reporter_ref` (required iff `source` is not `governance-agent`) | a THIRD-PARTY-RETRIEVABLE reference: a PR review URL or id, a comment permalink, a transcript path. Not a bare name — a name is a string the author types freely, which is precisely the self-declared claim this field exists to replace. `source` is otherwise an assertion of independent review recorded by the party under review, and that is the one property this artefact most needs to be checkable |
   | `reviewed_at_sha` | the HEAD the reporter actually read, and its merge-base with `origin/dev` where that is knowable (`unresolved` for the merge-base half when it is not — a GitHub review records the reviewed SHA but not what it was branched from). This is the field that closes the failure `source` is justified by: reviewer KIND does not detect three reviewers sharing one stale checkout, the merge-base does |
   | `recorded_at` | ISO-8601, when the ROW was written — not when the run started. Mandatory because appending after the run is permitted: without it, a row added post-merge is indistinguishable from one written at the gate, and a squash-merge collapses the git history that would otherwise carry the ordering |
   | `pass_ordinal` | **which round.** Without it the final pass is indistinguishable from the first, and `caused_by` below presupposes a round identity the schema would otherwise lack. A row appended AFTER the run ends carries the `run_id` of the run it reviews and `pass_ordinal: 0` — round zero means "outside the run's rounds", and `recorded_at` says when |
   | `finding_id` | stable across rounds — `caused_by` is uncomputable without a join key |
   | `severity_native` | the REPORTER's own vocabulary, unmodified, or `null` if they gave none. A collaborator writing "nit" or nothing at all is normal; do not invent a band for them, and do not treat an unmapped human word as the "vocabulary does not map → gate it" case, which is addressed to reviewing agents |
   | `severity_mapped` | BLOCKING / SHOULD / NICE, derived per the severity rule — so for a conforming writer it always agrees with `impact`/`exposure`. Restate it whenever the facts change: a stale label is read at the stronger of the two and is itself reported |
   | `trigger` | the concrete input/state/config, or `unresolved` |
   | `impact` | every applicable `I1`…`I9` — a list; the strongest gives the band |
   | `exposure` | every applicable `E0`…`E6`, or `unresolved` — a list, not one value. `E6` is applied last and dominates every raise |
   | `epistemic_status` | `verified` / `likely` / `speculative`. Operates on the GATE, not the band — flipping it to `speculative` converts a blocker into a mandatory investigation without changing the derived band, which is why the de-escalation rule guards it |
   | `independent_reporters` | how many REPORTERS raised it WITHOUT having been shown it — downstream echoes are not confirmations. Counts reporters of every `source`, not agents only: a human colleague finding the same defect independently is the strongest confirmation available, and counting it zero inverts the signal |
   | `policy_floor` (nullable) | the floor hit, if the finding gates as a contract violation rather than by derivation. Null on an ordinary finding, which is most of them |
   | `provenance` | `introduced` / `newly-reachable` / `pre-existing`. **Adjudicated, not inferred from prose.** Default to `introduced` when contested |
   | `file`, `line`, `summary` | where and what. `line` takes `unresolved` when the finding is about a file as a whole or the reporter named none — the same sentinel `trigger` and `exposure` use. `file` takes `unresolved` for a run-level or process finding that is about no file. **`line` is relative to `reviewed_at_sha`, not to HEAD** — it drifts, so cite the sha when the citation matters |
   | `classification` + rationale | `truth-contradiction` / `wording` / `absence`, and why. `absence` is the third category the prose rule names — a required doc that is missing contradicts nothing, so forcing it into the other two is what the rule exists to stop |
   | `disposition` | `open` / `fixed` / `deferred-to-issue #N` / `rejected` / `refuted`. `open` is the value at the moment a finding is RAISED — the other four are terminal, and a schema whose only values are terminal cannot record a finding before it is resolved. `rejected` = we chose not to act. `refuted` = the claim was factually WRONG, and `refuted_by` carries the evidence — a different outcome with a different downstream use, so never collapse the two |
   | `refuted_by` (required iff `disposition` is `refuted`) | the evidence that killed the claim — the command run and its output, the `git show origin/dev:<path>` that disproved an absence, the file:line that contradicts it. A `refuted` row with no evidence is a `rejected` row wearing a stronger word. The refutation must defeat the DEFECT, not merely the citation: a real finding that names the wrong `file:line` is corrected, never refuted, or the recorded kill shape suppresses a true claim on the next run |
   | `refuted_by_reporter` (required iff `disposition` is `refuted`) | who refuted it, and that they were not the change's author. `adjudicated_by` already carries this requirement and the manual-cleanup floor exception states it outright — a self-authored refutation of one's own blocking finding is exactly the case both were written for, and `refuted` is the disposition that most reduces downstream scrutiny |
   | `adjudicated_by` (nullable; **required iff the row de-escalates** — see the de-escalation rule) | who approved a departure, and that they were not the change's author. Free text with no `*_ref` sibling: a reader with the repo can detect SELF-naming by comparing against `git log --format='%an'` over `commit_range`, and can verify nothing beyond that. Self-naming is caught; the adjudication itself is unverified, and `commit_range: unresolved` voids even the self-check |
   | `adjudication_rationale` (required iff `adjudicated_by` is set) | WHY the departure or de-escalation was approved. Distinct from `waiver_rationale`, which is specifically why an unresolved gating finding was allowed to pass |
   | `caused_by` (nullable) | did round N's fix create this round N+1 finding |
   | `waiver_rationale` (nullable) | *why* an unresolved gating finding was allowed to pass. A signature with no reasoning is content-free exception evidence |

   `caused_by`, `waiver_rationale` and the `refuted_by` pair exist so the schema is
   stable when the process that
   produces them lands. **Recording an `adjudicated_by`, `waiver_rationale`, or
   `refuted` disposition does NOT establish that a gating finding may be released** —
   no such merge contract is adopted here. Today's rule is unchanged: gating
   findings are resolved before the gate passes, and a refutation resolves one only
   if the refutation is itself correct and independently recorded. The columns are
   there so a future decision has somewhere to write, not because one has been made.

   **Who derives the facts on a non-agent row.** A collaborator does not file a
   TRIGGER/IMPACT/EXPOSURE derivation, and should not be asked to. Whoever RECORDS
   the row derives them from what the collaborator actually said, and
   `epistemic_status` is the recorder's confidence in their own reading of it, not
   the collaborator's confidence in the finding. `severity_native` stays the
   reporter's own words or `null`. Say in `summary` where the derivation is the
   recorder's rather than the reporter's — a row that silently attributes a derived
   band to a human who never stated one is a small forgery.

   **`open` is not a resting place.** A row recorded `open` must be superseded by a
   terminal row before the gate passes. That is the existing rule — gating findings
   are resolved before the gate passes — expressed in the schema; `open` exists so a
   finding can be recorded when it is RAISED rather than only once it is settled,
   not so a run can end with unresolved rows in the ledger.

   Nothing validates that, and nothing can: a `fixed` row is a CLAIM, not closure
   evidence. **The ledger records; Gate 8 tests.** Appending `fixed` to every open
   row costs nothing and proves nothing — what actually closes a finding is the
   re-review of the fix diff, and the ledger's value is that the claim is written
   down next to who made it and when.

   **Which sources a run is expected to record.** A `/governance` run records
   `source: "governance-agent"` rows only. Rows with `source: "collaborator"` or
   `"external-model"` are written when a PR review, an `/adversarial-review`, or an
   equivalent external pass actually happens — so **an absent `collaborator` row
   means nothing was recorded, NOT that no external review occurred**, and it must
   never be read as evidence that none was sought. Adding those rows to an existing
   fragment is a normal, expected append; a run does not own its file exclusively
   once it has finished. An append to a fragment that has already merged goes
   through a pull request like any other change to the repo — never an amend over
   the original commit, and never a direct push that alters an evidence record
   without review.

   **Why `source` is worth a column, and what it does NOT do.** Independent review
   is only independent if the WORKING COPIES are. On #2604 two external models
   independently confirmed a claim that was wrong — all three reviewers were reading
   one working copy whose merge-base predated the file in question by ten days, so
   the agreement measured the checkout, not the code. A colleague with a current
   checkout killed it in a single pass. `source` alone does NOT detect that: it
   records reviewer KIND, and all three of those reviewers would have been truthfully
   labelled. `reviewed_at_sha` is the field that detects it, which is why the two
   land together. `source` answers a different and narrower question — was this row
   produced inside the pipeline or outside it — and `independent_reporters` counts
   reporters who were not shown the finding.

   **Known gap, unsolved:** the absence of a finding row cannot distinguish "the
   reviewer passed" from "the reviewer never ran". A clean-result record needs its
   own design. `source` narrows the MISREADING risk for external review — an absent
   `collaborator` row is now explicitly uninformative rather than ambiguously so —
   but it adds no assertive power and does not close the gap. Nor does a PRESENT
   row assert much on its own: `reporter_ref` is what makes it checkable, and
   without one the field is a claim about the reviewer made by the reviewed.

   Why this exists at all: governance is the repo's largest issue-inflow source, and
   nothing has ever recorded what it found. CI outcomes, durations and flakes are
   persisted and queryable (`docs/ci-architecture.md`); governance findings are not.
   Without a record, "governance is too noisy" and "governance caught the thing that
   mattered" are both unfalsifiable, and no roster change can be argued from evidence.
   See `docs/governance-skill-tuning-2026-07.md`.

## Known patterns from prior runs

**Pattern A: sibling IDOR.** When fixing an authorization gap on endpoint X, grep for every other endpoint in the same file/semantic and verify they have the same check. #222 closed the REST path but left the HTMX dashboard path open. The governance security-guardian caught it only when explicitly told to look for siblings.

**Pattern B: cycle-safe here but not there.** When adding `visited` sets / cap checks to one traversal (`get_descendant_ids`), always check the sibling traversal (`get_ancestor_ids`) for the same class of bug. The fix pattern is symmetric; the bug pattern usually is too.

**Pattern C: pre-existing bug made worse by hardening round.** A latent bug that was dormant under previous call patterns can become hazardous when you add a new call site. UP-11 / C1: my #222 fix added a new denied-branch that called `render_api_tokens_fragment()`, which has always leaked all tokens via `list_tokens()`-with-no-filter — but no prior code path exercised that leak in a denied-response body sent to a non-owner. My "close the oracle" fix shipped a new info leak worse than the IDOR it closed. Watch for this pattern in every new error-branch.

**Pattern D: 404 vs 403 enumeration oracle.** When adding owner-check rejection to an endpoint, return the same status and same body as "not found" so non-owners cannot distinguish "doesn't exist" from "exists but not yours". Audit log server-side with the real reason.

**Pattern E: readiness probe coverage regression.** Gate 6 SRE reliably catches any new or newly-load-bearing store missing from `/readyz`. Verify `server.cpp`'s `stores_ok` conjunction covers every store the PR changed or newly relies on.

## Cost / ROI

One full governance run on a non-trivial commit range is ~6-9 parallel agent calls plus the consolidation writeup. On the #222/#224 hardening round (5 commits, 2 hardening rounds), it caught 3 BLOCKING items I introduced myself, 2 of which would have shipped a worse vulnerability than the one I was fixing. The run takes 30-60 min of wall clock and produces a permanent artifact trail in commit messages + CHANGELOG that satisfies SOC 2 Workstream F change-management evidence.

Skipping Gate 4 or Gate 5 to save time is rarely worth it. **Do NOT skip Gate 3 domain agents on the grounds that a change is small** — that guidance predates the unconditional routed-trigger floor above and contradicts it. Diff size does not gate a routed concern: `.claude/routed-concerns.md` keys on file identity and change type precisely because those files carry catastrophic-if-violated invariants at any line count. Use the decision matrix to decide WHICH agents, never WHETHER.

## Post-run follow-ups — file deferred findings per the issue standard

After the run passes and the commits push, governance typically produces 8-15 deferred follow-up items (SHOULD findings scoped out of the PR). Governance is the repo's largest issue-inflow source, so filing follows `docs/agents/issue-standard.md` exactly; the binding procedure:

1. **Draft the candidate list** — one actionable outcome per candidate; split multi-finding bundles; type each honestly (`bug` / `task` / `decision` / `spike` — a choice-to-be-made is a `decision`, not a code task).
2. **Dedupe every candidate (mandatory — dedupe is the only inflow filter):**
   ```bash
   gh issue list --repo Tr3kkR/Yuzu --state open --search "<file-or-symbol>" --json number,title
   gh search issues --repo Tr3kkR/Yuzu --state open "<title keywords>" --json number,title --limit 20
   ```
   An existing issue covers it → comment the new evidence there instead of filing. Related but a distinct outcome → file with `Relates to #N` in the body.
3. **File survivors** with the four body sections (Context / Evidence with `file:line` against current `origin/dev` / Acceptance criteria / Origin naming this governance run plus the dedupe probes and their results):
   ```bash
   gh issue create --repo Tr3kkR/Yuzu --title "..." \
     --label <type> --label governance-deferred --label <P1|P2> --label ready-for-agent \
     --body-file <candidate>.md
   ```
   (`<type>` and `<P1|P2>` are placeholders — pass exactly one real label each, e.g. `--label task --label P2`.
   `gh search issues` is rate-limited (~30/min): on a 403 mid-batch, wait 60 seconds and continue —
   never skip the probe.)
   **Every governance filing carries `governance-deferred`** (that label is how agent inflow is counted). Add facet labels as they genuinely apply (`tech-debt`, `reliability` for chaos findings, `observability`, `devops`, `security` for hardening — never for exploitable vulnerabilities, which go to private advisories per `SECURITY.md`).
4. **The run report enumerates BOTH lists** — filed (with issue numbers) and not-filed (with the duplicate verdict and the issue each deduped against) — so inflow is auditable run over run.

Prior examples: issues #340..#353 (pre-standard; the body format is now the standard's four sections).
