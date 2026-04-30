# Known Issues — PR 3 / AuthDB Governance Round (deferred follow-ups)

This document tracks the items that were **identified during the full
`/governance` review of `4433683..7ea7be6`** (the commit range that
brought in fjarvis's `AuthDB` SQLite-backed auth persistence and the
PR 3 SSE live-updates work) and **deliberately scoped out** of the
six-PR hardening ladder that landed the in-scope fixes.

These are not unknowns — they are accepted technical debt with a
documented owner, severity, and target. They live here so a future
operator, auditor, or contributor can grep one place and learn the
state of the world without re-reading the governance transcript.

The hardening-ladder PRs that fixed the in-scope items are:
- **PR 1** (#694) — AuthDB lifetime + 0600 perms + cleanup thread + portability
- **PR 2** (#695) — AuthDB MigrationRunner adoption
- **PR 3** — SSE backpressure + bus metrics + member-order static_assert
- **PR 4** — audit coverage + SSE dedup decision + tests
- **PR 4.5** (this doc) — tracking-only
- **PR 5** — `/readyz` AuthDB coverage + systemd limits + UAT script + auth-db recovery runbook
- **PR 6** — REST-API docs + server-admin.md + CHANGELOG + security-review record

---

## Deferred items

Each deferred item has a corresponding GitHub issue. The verbatim
governance-finding text is copied here so the rationale is durable
even if the issue is later closed or relabelled.

### Deferred-1 — perf-B3 / UP-A10: SSE ring buffer `kBufferCap=1000` undersized for fleet-scale executions

**Issue:** [#696](https://github.com/Tr3kkR/Yuzu/issues/696)
**Severity:** SHOULD (post-PR3-ladder; capacity-baseline first)
**Origin:** Gate 3 perf-B3 + Gate 4 unhappy-path UP-A10

`ExecutionEventBus::kBufferCap = 1000` is a compile-time constant. At
1000-agent fan-out a single execution produces ~2000 events
(agent-transition + execution-progress refreshes), already exceeding
the buffer. Events are dropped FIFO with no counter; a client
reconnecting after a brief network blip silently misses transitions.
The "~30 s window in practice" in the commit message assumes ~33
events/s; at fleet scale (1000+ agents), the window collapses to under
1 second.

**Why deferred:** The fix shape is open — either dynamic per-execution
sizing (`max(1000, 4 * targeted_agents)`) capped at 100K, OR an
operator-tunable `--sse-buffer-cap` flag with documented operational
guidance. The decision wants a capacity baseline (which depends on
PR 3's bus metrics from OBS-3 landing first) before the right number
emerges. Filing as a follow-up with a benchmark prerequisite is
cleaner than baking in the wrong knob now.

**Mitigation in the ladder:** PR 3 adds the
`yuzu_server_sse_events_dropped_total` counter so the gap is at least
observable in production; operators can pre-emptively scale the buffer
once the metric shows pressure.

---

### Deferred-2 — comp-H3: MFA / 4-eyes on `POST /api/settings/users/:username/role`

**Issue:** [#697](https://github.com/Tr3kkR/Yuzu/issues/697)
**Severity:** SHOULD (acceptable as documented gap)
**Origin:** Gate 6 compliance HIGH-3 + Gate 6 enterprise-readiness

The new privileged endpoint promotes a `user` to `admin`, granting
full management access. It is protected by single-factor admin session
auth. `docs/enterprise-readiness-soc2-first-customer.md` §3.2
explicitly requires "MFA/step-up auth for privileged approvals." The
roadmap places MFA implementation at Priority 1 (31-90 days), but the
endpoint landing before that control creates a window where admin
promotion is single-factor with no compensating control beyond
audit-logging the success branch.

**Why deferred:** MFA is a separate feature workstream, not a
hardening fix. Implementing it as part of this round would balloon
the scope.

**Mitigation in the ladder:** PR 6 adds a risk-register entry to
`docs/enterprise-readiness-soc2-first-customer.md` documenting the
gap with a target tied to the Priority 1 MFA milestone. SOC 2 audit
acceptance: a risk register entry IS the evidence artefact that
prevents this from becoming a finding.

---

### Deferred-3 — build-S1: fork-PR Windows compile gap

**Issue:** [#698](https://github.com/Tr3kkR/Yuzu/issues/698)
**Severity:** SHOULD (CI-architecture, post-PR3-ladder)
**Origin:** Gate 3 build-ci

PRs from forks (like fjarvis's #692 — the AuthDB feature PR) skip
self-hosted Linux + Windows because `Preflight` returns false without
the `RUNNER_INVENTORY_TOKEN` secret (fork PRs don't get repo secrets
per GitHub policy). Only `macos-15` runs. The `auth_db.cpp:131`
`path.c_str()` MSVC C2664 bug shipped past PR #692's CI for exactly
this reason and was caught only after merge to `dev` on run
25173852982.

**Recommendation:** add a GHA-hosted `windows-2022` compile-only leg
to the PR fast-path, gated `if: github.event.pull_request.head.repo.fork
== true`. Pure compile (no tests, no full vcpkg cache) finds C2664 /
C4743 / path-narrowing bugs without depending on self-hosted secrets.
Cost: ~15 min cold per fork PR.

**Why deferred:** CI-architecture change is a separate workflow PR
with its own review surface (caching strategy, where the GHA-hosted
job sits in the matrix, rollout to existing fork PRs). Out of scope
for the auth/SSE hardening round.

**Mitigation in the ladder:** None — fork PRs continue to ship past
self-hosted-skipped CI. Reviewers must be aware and explicitly
request a `dev`-side compile check on Windows-touching fork PRs
until this is fixed.

---

### Deferred-4 — UP-A17: Large-`auth.db` `integrity_check` SLO

**Issue:** [#699](https://github.com/Tr3kkR/Yuzu/issues/699)
**Severity:** SHOULD (post-PR3-ladder)
**Origin:** Gate 4 unhappy-path UP-A17

`PRAGMA integrity_check` is `O(DB size)`. 100k users + accumulated
sessions → 100MB+ `auth.db` → 5-15s startup delay → potential LB
health-check restart cascade if the LB probe fires before the listener
binds. Combined with `deploy-S3` (systemd `Restart=always` with no
`StartLimitBurst`), a corrupt-DB exit can race into an unbounded
restart loop.

**Why deferred:** The fix is a combination of (a) document the
operational SLO (this is observability), (b) add a Prometheus
startup-time histogram bucket, (c) set the LB health-check grace
period accordingly. None of these belong in the auth/SSE hardening
round — they're a separate observability / runbook pass.

**Mitigation in the ladder:**
- PR 1 wires `cleanup_expired_sessions()` to a `std::jthread` so the
  sessions table doesn't grow monotonically.
- PR 5 sets `StartLimitBurst=3 StartLimitIntervalSec=60` on the
  systemd unit so a corrupt-DB exit triggers `failed` state in <15s
  instead of looping forever.
- PR 5 ships `docs/ops-runbooks/auth-db-recovery.md` with the
  detection signal, `sqlite3 .backup` recovery, and reseed-from-config
  rollback path.

The remaining SLO + alert + bucket histogram are this issue.

---

### Deferred-5 — UP-A15: Audit dedup TOCTOU (latent)

**Issue:** [#700](https://github.com/Tr3kkR/Yuzu/issues/700)
**Severity:** NICE (latent — only relevant if dedup is later implemented)
**Origin:** Gate 4 unhappy-path UP-A15 + Gate 4 consistency ca-PR3-2

If `execution.live_subscribe` audit dedup is ever implemented (the
SSE handler comment in `workflow_routes.cpp` claimed it but PR 4
removes the false claim and commits to audit-every-connect), the
dedup `seen-set` would have a TOCTOU window: two near-simultaneous
SSE connects from the same session for the same execution would
both pass the seen-set check before either inserts → both audit.

**Why deferred:** PR 4 commits to audit-every-connect and removes
the dedup-claim comment. This issue is dormant unless the policy
reverses. It's recorded here so a future PR author who revisits
dedup doesn't re-introduce the gotcha.

**Mitigation in the ladder:** PR 4 closes the dedup-comment-vs-code
mismatch by deleting the false comment. No code change needed for
this issue today.

---

## Out-of-scope items NOT tracked here

Some governance findings were addressed in the ladder PRs and don't
need separate issues. For completeness, those were:

- **arch-B1** — AuthDB lifetime UAF → fixed in PR 1
- **arch-B2** — MigrationRunner adoption → fixed in PR 2
- **xp-B1 / cpp-SH-2** — missing includes → fixed in PR 1
- **xp-S1** — `gmtime` thread-safety → fixed in PR 1
- **cpp-SH-1** — `column_text` null-deref → fixed in PR 1
- **cpp-SH-3** — `AuthDBError` underlying type → fixed in PR 1
- **cpp-SH-4 / cpp-SH-5** — discarded `invalidate_all_sessions` → fixed in PR 1
- **comp-B2 / sec-H1** — `auth.db` 0600 perms → fixed in PR 1
- **comp-B3** — cleanup thread → fixed in PR 1
- **arch-S1** — dead session methods → documented in PR 1
- **sec-M1..M4 / ca-PR3-1..7 / qe-B1..2** — audit coverage + SSE dedup + tests → PR 4
- **OBS-1..4** — readyz / login latency / SSE bus / audit emit failures → PRs 3, 4, 5
- **DEPLOY-1..3 / REC-1** — systemd limits / UAT port / runbook → PR 5
- **doc-B1..B7 / ent-B1..B4** — all docs gaps → PR 6
- **UP-A1, A2, A4, A5, A6, A7, A8, A9, A11, A12, A13, A14, A16, A18, A19, A20** — covered by PRs 1-5 fixes or chaos-pr3 follow-ups
- **perf-B1, B2** — tracker mutex contention + GC throttle → PR 3
- **arch-N1, N2** — bus member-order static_assert + publish-under-mutex doc → PR 3
- **arch-S2, S3** — Deps move-from semantics + SSE versioning placement → PR 3 / PR 6 docs

---

## Maintenance

When one of the deferred items is fixed:
1. Update the issue with the fixing PR/commit.
2. Move the entry from "Deferred items" to "Resolved" (keep the verbatim text + add the resolution note).
3. Once the deferred-list is empty, archive this file under `docs/known-issues/archive/`.

When a NEW governance round identifies items to defer, append them to
"Deferred items" with the same shape — origin gate, severity,
rationale for deferral, mitigation in the ladder.
