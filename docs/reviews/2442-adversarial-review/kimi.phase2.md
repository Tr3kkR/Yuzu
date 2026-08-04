# Phase 2 — cross-examination + completion

Branch: `fix/2442-consume-side-origin-guard`
Head: `4b83f70be1a6ded48629f339f4c6065fd1fcca1d`
Reviewer: `kimi`

---

## Cross-examination of peer findings

| PEER-ID | label | evidence I checked | my severity |
|---|---|---|---|
| CDX-P1-001 | `confirmed-independently` (severity adjudicated) | `mcp_server.cpp:3228` reads ticket; `3241` returns for `pending`; `3252` returns for non-`approved`; `3318` is the only `kForeignOrigin` metric/audit branch; `docs/user-manual/metrics.md:168` describes the counter as "presented to the MCP recall"; `docs/observability-conventions.md:18` says security events route to SIEM via Prometheus. | `LOW` (peer: `MEDIUM`) |

**Adjudication on CDX-P1-001:** The gap is real. A foreign-origin ticket that is `pending`, `rejected`, or `expired` is turned away before `consume_ticket()`, so neither `yuzu_mcp_approval_forgery_total` nor the `refused: minted by a non-MCP surface` audit token fires. I grade it `LOW` rather than `MEDIUM` because the consume-side guard still refuses the only dangerous case (approved foreign tickets), no mutating command executes for pending/rejected tickets, and the attacker must already possess a valid approval id. It is an observability/forensics completeness gap, not a privilege-escalation or guard-bypass hole.

Peer's `[mcp]` run failed four `test_mcp_body_cap.cpp:110` listener-start cases; I did not reproduce those on the same tree after the documented restore. They appear environmental (port allocation), not material to this finding.

---

## Adoption/rebuttal of peer coverage

- **Metrics/audit behavior on the recall path:** Peer went deeper than I did on the early-return branches before `consume_ticket()`. I adopt the finding into my set as [K4] below, with independent verification and a lower severity.
- Other axes peer covered (security/privilege, mint sites, test mutation, `kUnspecified` exemption) were already covered in my Phase 1.

---

## Defence of own Phase-1 findings

- **[K1] `kUnspecified` residual redemption window:** unchanged. Codex did not contradict it. No new evidence narrows the documented temporary exemption.
- **[K2] `LIMIT 64` / `kMcpSubmitterPendingCap` uncoupled:** unchanged. Still a maintenance footgun, not an active vulnerability at the current cap of 25.
- **[K3] Two-argument `consume_ticket` overload flattens `ConsumeFailure`:** unchanged. Still no production caller; still a public-API trap.

---

## Revised full finding list

### [K1] LOW · CONFIDENCE:hi · PROVENANCE:test-run — `unchanged`
Residual redemption window remains for `kUnspecified`-origin tickets
- Location: `server/core/src/approval_manager.hpp:131-132`, `server/core/src/approval_manager.cpp:189-191`, `server/core/src/mcp_server.cpp:3207-3208`
- Claim: `declares_non_mcp_surface()` deliberately returns `false` for `kUnspecified`, so any ticket whose `origin` column is `''` is still redeemable through the MCP recall. This is the documented transitional state, but it means the #2442 guard is not fully closed.
- Evidence: `approval_manager.hpp:131-132` returns `false` for `kMcp` and `kUnspecified`; `approval_manager.cpp:189-191` adds the `origin` column with `DEFAULT ''`; `mcp_server.cpp:3207-3208` passes `ApprovalOrigin::kUnspecified` at the MCP mint.
- Scenario: An attacker who can cause a ticket to be stored with `origin=''` (other than the legitimate MCP mint or pre-v5 rows) gains a redeemable ticket without origin binding. Today the only production path that writes `''` is the MCP mint itself, because `submit()` has no default and the REST/scheduler mints pass explicit declared origins.
- Inference: The exemption is bounded by the 7-day approval expiry and is documented as temporary. It is a deliberate design trade-off, not an implementation bug.
- Anchor: `judgment` (documented design choice; ADR-1005's "one core-owned approval primitive" is satisfied and no new gate is added outside `ApprovalManager`).
- Precedent: none found.
- Mitigations: `submit()` has no default `ApprovalOrigin`, so any new mint surface must explicitly choose an origin at compile time; pre-v5 rows age out within 7 days of the next submit/expiry event.
- Fix: Once the MCP mint declares `kMcp` and blank-origin rows are drained, narrow `declares_non_mcp_surface()` to allow only `kMcp`.

### [K2] LOW · CONFIDENCE:med · PROVENANCE:static-read — `unchanged`
`find_pending` `LIMIT 64` and `kMcpSubmitterPendingCap` are uncoupled
- Location: `server/core/src/approval_manager.cpp:525-528`, `server/core/src/mcp_server.cpp:3184`
- Claim: The MCP dedup scan caps at 64 rows, while the per-submitter pending cap is 25. The code comment states the safety invariant `LIMIT > kMcpSubmitterPendingCap`, but the two constants live in different TUs with no shared constant or compile-time check.
- Evidence: `approval_manager.cpp:525-528` builds `... ORDER BY submitted_at DESC LIMIT 64`; `mcp_server.cpp:3184` defines `constexpr int kMcpSubmitterPendingCap = 25`; the comment at `approval_manager.cpp:511-524` explicitly calls out the invariant and the lack of coupling.
- Scenario: A future change raises `kMcpSubmitterPendingCap` above 64. A principal with more than 64 same-tuple foreign-origin pending rows hides a valid MCP-origin row behind position 64; `find_pending` returns `nullopt`, the mint proceeds, and an admin spends an approval on a ticket the recall will later refuse.
- Inference: This is a maintenance footgun, not an active vulnerability at the current cap of 25.
- Anchor: `judgment`.
- Precedent: none found.
- Mitigations: The current cap is 25, well below 64; `test_approval_manager.cpp:990-1023` verifies that one foreign row is skipped and a behind eligible row is found.
- Fix: Either share the constant so `LIMIT` derives from `kMcpSubmitterPendingCap`, or add a `static_assert` linking the two. Alternatively, push the origin predicate into SQL with an `IN` clause generated from `declares_non_mcp_surface` so `LIMIT 1` can be used safely.

### [K3] LOW · CONFIDENCE:hi · PROVENANCE:static-read — `unchanged`
Two-argument `consume_ticket` overload flattens `ConsumeFailure` kind
- Location: `server/core/src/approval_manager.cpp:554-569`
- Claim: The overload discards the typed `ConsumeFailure` kind and returns only the message string. It has no production caller today, but retaining it as public API creates a trap for future callers.
- Evidence: `approval_manager.cpp:568` returns `std::unexpected(r.error().message)`, dropping `r.error().kind`.
- Scenario: A future production caller added to the MCP recall (or another surface) uses the simpler overload and cannot branch audit/metrics/retry decisions on whether the denial was `kForeignOrigin`, `kPrecondition`, `kNotConsumable`, or `kStoreError`. This would reopen the very blurring #2442/#2443 fixed.
- Inference: No current production caller uses this overload; the MCP recall uses the three-argument form (`mcp_server.cpp:3268`).
- Anchor: `judgment`.
- Precedent: `mcp_server.cpp:3268` uses `consume_ticket(id, consumed_by, {})` and switches on the kind.
- Mitigations: The three-argument overload exists and is the only production caller; tests cover both overloads.
- Fix: Deprecate or remove the two-argument overload, or make it return `ConsumeError` instead of a bare string.

### [K4] LOW · CONFIDENCE:hi · PROVENANCE:static-read — `new-from-cross-exam`
Pending/rejected/expired foreign-origin recall attempts do not emit the #2442 SIEM counter or audit token
- Location: `server/core/src/mcp_server.cpp:3228`, `3241`, `3252`, `3318`; `docs/user-manual/metrics.md:168`; `docs/observability-conventions.md:18`
- Claim: The MCP recall returns early for `pending` and non-`approved` tickets before calling `consume_ticket()`, so a ticket minted by REST/scheduler that is presented to MCP but not yet approved (or already rejected/expired) never increments `yuzu_mcp_approval_forgery_total` and never emits the `refused: minted by a non-MCP surface (#2442)` audit detail.
- Evidence: `mcp_server.cpp:3241` returns for `appr->status == "pending"`; `mcp_server.cpp:3252` returns for `appr->status != "approved"`; the only `kForeignOrigin` metric/audit branch is at `mcp_server.cpp:3318`, reached only after `consume_ticket()` at `mcp_server.cpp:3268`. `docs/user-manual/metrics.md:168` defines the counter as "an approval minted by the REST instruction gate or the scheduler, presented to the MCP recall." `docs/observability-conventions.md:18` states security events route to the SIEM via Prometheus and pairs the metric with the audit row.
- Scenario: An operator or agentic worker with a leaked REST/scheduler approval id replays it through MCP before approval or after rejection. The caller gets a pending/rejected/expired answer, but the SIEM-facing forgery series stays flat and the audit detail that would evidence the cross-surface attempt is absent.
- Inference: This does not bypass the consume-side origin guard for approved tickets; it undercounts cross-surface probing. The response already leaks status (pending vs rejected) to any caller, so the missing signal is purely the server-side security event.
- Anchor: `contract` — `docs/observability-conventions.md:18` (security events route to SIEM via Prometheus) and `docs/user-manual/metrics.md:168` (counter description).
- Precedent: `mcp_server.cpp:3318-3330` correctly emits both `reason="foreign_origin"` and `event="security"` once `consume_ticket()` identifies `ConsumeFailure::kForeignOrigin` on an approved ticket.
- Mitigations: Requires a known approval id and matching MCP tool arguments; no mutating command executes; approved foreign-origin tickets are refused and counted.
- Fix: After `get()`/`definition_id`/`scope_expression` match and before the `pending`/`status` branches, if `declares_non_mcp_surface(appr->origin)` is true emit the same denied audit detail and both counters, return the same opaque permission-denied response, and do not consume the row.
- Falsifier: Show a code path that increments `yuzu_mcp_approval_forgery_total` or records the `minted by a non-MCP surface` audit token for a pending/rejected/expired foreign-origin ticket.

---

VERDICT: PASS — No CRITICAL/HIGH finding. The consume-side origin guard, the CAS consumption path, and the #2442 security counter for approved foreign tickets are correctly implemented and mutation-tested. The residual `kUnspecified` exemption is deliberate and bounded. The only material issue is an observability gap ([K4]) for non-approved foreign tickets, which I grade LOW; the peer graded it MEDIUM, but it does not bypass any security control.

COVERAGE:
- Security/privilege: deep — traced every `submit()` production call site, every `consume_ticket` call site, the origin predicate, the CAS, the metric increment, and the early-return branches on the MCP recall.
- Correctness/logic: deep — read `approval_manager.hpp/cpp`, `mcp_server.cpp` recall/mint paths, `workflow_routes.cpp`, `schedule_runner.cpp`, relevant tests.
- Resource & concurrency safety: medium — verified #1033 compliance (RETURNING, no `sqlite3_changes()`), mutex coverage, immutable origin read outside lock before CAS; did not build Windows/macOS.
- Cross-platform/portability: skimmed — code is SQLite/C++23 with no OS-specific paths in the changed code; build checked only Linux.
- Cross-component & schema/contract consistency: deep — checked migration v5/v6, enum round-trip, metric pre-seeding, audit envelope consistency, and the metric-vs-code mismatch in [K4].
- Test adequacy: deep — ran targeted tags, confirmed the [security] tests fail when the origin guard is mutated (Phase 1), and re-ran all targeted suites green.

RAN:
- `source scripts/ensure-erlang.sh && meson compile -C build-linux` — succeeded.
- `./build-linux/tests/yuzu_server_tests "[security]"` — passed.
- `./build-linux/tests/yuzu_server_tests "[approval]"` — passed.
- `./build-linux/tests/yuzu_server_tests "[mcp]"` — passed (376 passed, 41 skipped).
- `git grep -n 'count_security_event("yuzu_mcp_approval_forgery_total")'` — confirms exactly one increment site at `mcp_server.cpp:3330`.
- `git status --short` and `git diff --check origin/dev..HEAD` — clean.
- CI status on PR head: not checked; no GitHub/network query performed.

FILES:
- `server/core/src/approval_manager.hpp` (full)
- `server/core/src/approval_manager.cpp` (full)
- `server/core/src/mcp_server.cpp` (relevant sections: mint at ~3207, recall at ~3228-3365, counters at ~3318)
- `server/core/src/server.cpp` (metric describe/pre-seed at ~546-684)
- `server/core/src/workflow_routes.cpp` (submit call at ~1556)
- `server/core/src/schedule_runner.cpp` (submit call at ~153)
- `tests/unit/server/test_approval_manager.cpp` (full)
- `tests/unit/server/test_mcp_server.cpp` (relevant #2442 tests at ~7017-7129)
- `docs/observability-conventions.md`, `docs/user-manual/metrics.md`, `docs/user-manual/audit-log.md`, `docs/user-manual/upgrading.md`, `docs/mcp-server.md` (relevant passages)
- `CLAUDE.md`, `.claude/routed-concerns.md`, `docs/adr/1005-headless-platform-use-case-engines.md`, `docs/auth-architecture.md` (anchors)

---

## Delta since Phase 1

- Added [K4] from cross-examination: pending/rejected/expired foreign-origin MCP recall attempts do not emit the documented SIEM counter or audit token. I grade it `LOW` (contract); peer `codex` graded the same gap `MEDIUM`.
- [K1]–[K3] are unchanged; no peer contradiction.
- Verdict remains `PASS`; no CRITICAL/HIGH finding.
