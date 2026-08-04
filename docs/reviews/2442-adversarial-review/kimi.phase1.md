# Phase 1 — independent adversarial review

Branch: `fix/2442-consume-side-origin-guard`
Head: `4b83f70be1a6ded48629f339f4c6065fd1fcca1d`
Reviewer: `kimi`

---

## [K1] LOW · CONFIDENCE:hi · PROVENANCE:test-run
Residual redemption window remains for `kUnspecified`-origin tickets
- Location: `server/core/src/approval_manager.hpp:129-140`, `server/core/src/approval_manager.cpp:189-191`, `server/core/src/mcp_server.cpp:3207-3208`
- Claim: `declares_non_mcp_surface()` deliberately returns `false` for `kUnspecified`, so any ticket whose `origin` column is `''` is still redeemable through the MCP recall. This is the documented transitional state, but it means the #2442 guard is not fully closed.
- Evidence: `approval_manager.hpp:131-132` returns `false` for `kMcp` and `kUnspecified`; `approval_manager.cpp:189-191` adds the `origin` column with `DEFAULT ''`; `mcp_server.cpp:3207-3208` passes `ApprovalOrigin::kUnspecified` at the MCP mint.
- Scenario: An attacker who can cause a ticket to be stored with `origin=''` (other than the legitimate MCP mint or pre-v5 rows) gains a redeemable ticket without origin binding. Today the only production path that writes `''` is the MCP mint itself, because `submit()` has no default and the REST/scheduler mints pass explicit declared origins.
- Inference: The exemption is bounded by the 7-day approval expiry and is documented as temporary in the header, in `docs/user-manual/upgrading.md:30`, and in `docs/mcp-server.md:96-97`. It is a deliberate design trade-off, not an implementation bug.
- Anchor: `judgment` (documented design choice; ADR-1005's "one core-owned approval primitive" is satisfied and no new gate is added outside `ApprovalManager`).
- Precedent: none found.
- Mitigations: `submit()` has no default `ApprovalOrigin`, so any new mint surface must explicitly choose an origin at compile time; pre-v5 rows age out within 7 days of the next submit/expiry event.
- Fix: Once the MCP mint declares `kMcp` and blank-origin rows are drained, narrow `declares_non_mcp_surface()` to allow only `kMcp`.
- Falsifier: Identify a production code path that writes `kUnspecified`/`''` other than the MCP mint or pre-v5 migration rows.

---

## [K2] LOW · CONFIDENCE:med · PROVENANCE:static-read
`find_pending` `LIMIT 64` and `kMcpSubmitterPendingCap` are uncoupled
- Location: `server/core/src/approval_manager.cpp:525-528`, `server/core/src/mcp_server.cpp:3184`
- Claim: The MCP dedup scan caps at 64 rows, while the per-submitter pending cap is 25. The code comment states the safety invariant `LIMIT > kMcpSubmitterPendingCap`, but the two constants live in different TUs with no shared constant or compile-time check.
- Evidence: `approval_manager.cpp:525-528` builds `... ORDER BY submitted_at DESC LIMIT 64`; `mcp_server.cpp:3184` defines `constexpr int kMcpSubmitterPendingCap = 25`; the comment at `approval_manager.cpp:511-524` explicitly calls out the invariant and the lack of coupling.
- Scenario: A future change raises `kMcpSubmitterPendingCap` above 64. A principal with more than 64 same-tuple foreign-origin pending rows hides a valid MCP-origin row behind position 64; `find_pending` returns `nullopt`, the mint proceeds, and an admin spends an approval on a ticket the recall will later refuse.
- Inference: This is a maintenance footgun, not an active vulnerability at the current cap of 25.
- Anchor: `judgment`.
- Precedent: none found.
- Mitigations: The current cap is 25, well below 64; `test_approval_manager.cpp:990-1023` verifies that one foreign row is skipped and a behind eligible row is found.
- Fix: Either share the constant so `LIMIT` derives from `kMcpSubmitterPendingCap`, or add a `static_assert` linking the two. Alternatively, push the origin predicate into SQL with an `IN` clause generated from `declares_non_mcp_surface` so `LIMIT 1` can be used safely (rejected by the authors to keep the predicate single-source).
- Falsifier: Show that raising `kMcpSubmitterPendingCap` above 64 is impossible without a build failure, or that a test covers the >64 foreign-row case.

---

## [K3] LOW · CONFIDENCE:hi · PROVENANCE:static-read
Two-argument `consume_ticket` overload flattens `ConsumeFailure` kind
- Location: `server/core/src/approval_manager.cpp:554-569`
- Claim: The overload discards the typed `ConsumeFailure` kind and returns only the message string. It has no production caller today, but retaining it as public API creates a trap for future callers.
- Evidence: `approval_manager.cpp:568` returns `std::unexpected(r.error().message)`, dropping `r.error().kind`.
- Scenario: A future production caller added to the MCP recall (or another surface) uses the simpler overload and cannot branch audit/metrics/retry decisions on whether the denial was `kForeignOrigin`, `kPrecondition`, `kStoreError`, or `kNotConsumable`. This would reopen the very blurring #2442/#2443 fixed.
- Inference: No current production caller uses this overload; the MCP recall uses the three-argument form (`mcp_server.cpp:3268`).
- Anchor: `judgment`.
- Precedent: `mcp_server.cpp:3268` uses `consume_ticket(id, consumed_by, {})` and switches on the kind.
- Mitigations: The three-argument overload exists and is the only production caller; tests cover both overloads.
- Fix: Deprecate or remove the two-argument overload, or make it return `ConsumeError` instead of a bare string.
- Falsifier: Identify a production caller of the two-argument overload.

---

VERDICT: PASS — The #2442 origin guard is correctly implemented: the redemption predicate is single-sourced in `declares_non_mcp_surface`, the CAS leaves refused forgeries untouched, the dedup path filters foreign origins, all three mint sites pass the correct `ApprovalOrigin`, and the [security] tests fail when the guard is mutated. The residual `kUnspecified` exemption is deliberate, bounded, and documented; no contract violation was found.

COVERAGE:
- Security/privilege: deep — traced every `submit()` production call site, every `consume_ticket` call site, the origin predicate, the CAS, and the metric increment.
- Correctness/logic: deep — read `approval_manager.hpp/cpp`, `mcp_server.cpp` recall path, `workflow_routes.cpp`, `schedule_runner.cpp`, relevant tests.
- Resource & concurrency safety: medium — verified #1033 compliance (RETURNING, no `sqlite3_changes()`), mutex coverage, immutable origin read outside lock before CAS; did not build Windows/macOS.
- Cross-platform/portability: skimmed — code is SQLite/C++23 with no OS-specific paths in the changed code; build checked only Linux.
- Cross-component & schema/contract consistency: deep — checked migration v5/v6, enum round-trip, metric pre-seeding, audit envelope consistency.
- Test adequacy: deep — ran targeted tags, mutation-tested the guard.

RAN:
- `source scripts/ensure-erlang.sh && meson compile -C build-linux` — succeeded (warnings only, none new).
- `./build-linux/tests/yuzu_server_tests "[security]"` — 192 passed, 22 skipped.
- `./build-linux/tests/yuzu_server_tests "[approval]"` — 64 passed, 1 skipped.
- `./build-linux/tests/yuzu_server_tests "[mcp]"` — 376 passed, 41 skipped.
- Mutation test: edited `approval_manager.hpp` to make `kInstruction` return `false` in `declares_non_mcp_surface`; rebuilt; `[security]` failed (5 failed, including `ApprovalManager: a ticket minted by a declared non-MCP surface cannot be redeemed` and the MCP 2442 integration test). Reverted with `git checkout -- server/core/src/approval_manager.hpp`; rebuilt; `[security]` green again.
- `git status --short` — clean after revert.

FILES:
- `server/core/src/approval_manager.hpp` (full)
- `server/core/src/approval_manager.cpp` (full)
- `server/core/src/mcp_server.cpp` (relevant sections: mint at ~3207, recall at ~3250-3365, counters at ~3054-3080, tool list at ~2081)
- `server/core/src/server.cpp` (metric describe/pre-seed at ~546-684)
- `server/core/src/workflow_routes.cpp` (submit call at ~1556)
- `server/core/src/schedule_runner.cpp` (submit call at ~153)
- `tests/unit/server/test_approval_manager.cpp` (full)
- `tests/unit/server/test_mcp_server.cpp` (relevant #2442 tests at ~7017-7129)
- `docs/mcp-server.md`, `docs/user-manual/mcp.md`, `docs/user-manual/upgrading.md` (relevant #2442 passages)
- `CLAUDE.md`, `.claude/routed-concerns.md`, `docs/adr/1005-headless-platform-use-case-engines.md`, `docs/auth-architecture.md`, `docs/observability-conventions.md` (anchors)
