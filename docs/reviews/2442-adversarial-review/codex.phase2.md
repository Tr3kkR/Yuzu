# Phase 2 — codex cross-examination

## Peer Cross-Examination

| PEER-ID | label | evidence I checked (file:line / command) | my severity |
|---|---|---|---|
| K1 | disagrees | `server/core/src/approval_manager.hpp:68-97` explicitly allows `kUnspecified`; `server/core/src/mcp_server.cpp:3196-3208` still mints MCP tickets as `kUnspecified`; `docs/mcp-server.md:90-97` documents the transition. | no finding / accepted residual |
| K2 | confirmed-independently | `server/core/src/approval_manager.cpp:511-528` states `LIMIT 64` and says it is uncoupled from `kMcpSubmitterPendingCap`; `server/core/src/mcp_server.cpp:3179-3186` defines the cap as `25`. | LOW |
| K3 | confirmed-independently | `server/core/src/approval_manager.cpp:554-568` maps `ConsumeError` to `std::string`; `rg -n "consume_ticket\\(" server/core/src` shows the only production caller is `mcp_server.cpp:3268` using the typed overload. | LOW |

K1 is factually true as a residual, but I do not adopt it as a defect. The branch intentionally preserves blank-origin redemption for pre-v5 rows and the still-undeclared MCP mint; `submit()` has no default `ApprovalOrigin`, and the two non-MCP production mints pass `kInstruction`/`kSchedule`. Kimi’s own scenario says the only current writer of `''` is MCP or migration, so this is not an implementation miss.

K2 and K3 are adopted as LOW judgment findings. They do not change the verdict: K2 requires a future cap increase past 64 with no build/test tripwire; K3 has no production caller and does not affect the current MCP recall path.

## Coverage Adoption

Kimi went deeper than I did in explicitly calling out the dedup scan limit/cap coupling and the legacy two-argument consume overload. I verified both from code and adopted them as LOW. Kimi also covered schema migration and production submit call sites; my independent checks agree that REST and scheduler declare non-MCP origins and MCP still declares `kUnspecified`.

Kimi did not cover my Phase 1 observability finding. I re-verified it from `mcp_server.cpp:3227-3260`, `mcp_server.cpp:3318-3330`, and `docs/user-manual/metrics.md:162-168`; I keep it unchanged.

## Revised Findings

[CDX-P1-001] unchanged · MEDIUM · CONFIDENCE(hi) · PROVENANCE(test-run)
Foreign-origin recall attempts are only counted after approval, despite the security metric documenting "presented to MCP recall"
- Location:  server/core/src/mcp_server.cpp:3228  (+ status pre-returns at server/core/src/mcp_server.cpp:3241 and server/core/src/mcp_server.cpp:3252; metric/audit branch at server/core/src/mcp_server.cpp:3318)
- Claim:     A REST/scheduler-origin ticket that matches the MCP tool and args but is pending, rejected, or expired returns before `consume_ticket()`, so it never emits `yuzu_mcp_approval_forgery_total` or the paired foreign-origin audit detail.
- Evidence:  `mcp_server.cpp:3228` reads the ticket with `approval_manager->get(supplied_id)`, `mcp_server.cpp:3241` returns for `status == "pending"`, and `mcp_server.cpp:3252` returns for `status != "approved"`; only `mcp_server.cpp:3268` calls `consume_ticket()`, and only `mcp_server.cpp:3318-3330` increments `yuzu_mcp_approval_forgery_total`. `docs/user-manual/metrics.md:166-168` describes that metric as "an approval minted by the REST instruction gate or the scheduler, presented to the MCP recall."
- Scenario:  An operator or agentic worker with a leaked REST approval id replays it through MCP before approval or after rejection; the caller gets a pending/rejected/expired answer and the SIEM-facing forgery metric remains flat.
- Inference: This does not bypass the consume-side origin guard for an approved ticket; it undercounts cross-surface probing and keeps the documented forensic signal from firing for some matching foreign-origin recall attempts.
- Anchor:    docs/observability-conventions.md "Prometheus metrics" / "Security events route to the SIEM via Prometheus" (`docs/observability-conventions.md:18` and `docs/observability-conventions.md:42`); docs/user-manual/metrics.md "MCP approval-gate metrics" (`docs/user-manual/metrics.md:162-168`).
- Precedent: server/core/src/mcp_server.cpp:3318 correctly emits both `reason="foreign_origin"` and `event="security"` once `consume_ticket()` identifies `ConsumeFailure::kForeignOrigin`.
- Mitigations: Requires a known approval id and matching MCP tool arguments; no mutating command executes; approved foreign-origin tickets are refused and counted.
- Fix:       After the `get()`/definition/scope match and before the pending/status branches, check `declares_non_mcp_surface(appr->origin)`, emit the same denied audit detail and both counters, return the same opaque permission-denied response, and do not consume the row.

[CDX-P2-002] new-from-cross-exam · LOW · CONFIDENCE(hi) · PROVENANCE(static-read)
`find_pending` relies on an uncoupled `64 > 25` invariant
- Location:  server/core/src/approval_manager.cpp:511  (+ server/core/src/mcp_server.cpp:3184)
- Claim:     The MCP dedup scan limit and the per-submitter cap are separate literals in separate translation units, so a future cap increase can make foreign-origin rows hide an eligible MCP row past the scan window.
- Evidence:  `approval_manager.cpp:511-528` says "`LIMIT 64` does truncate" and "`LIMIT` > `kMcpSubmitterPendingCap`" but "nothing couples the two numbers"; `mcp_server.cpp:3184` defines `constexpr int kMcpSubmitterPendingCap = 25`.
- Scenario:  A later patch raises the per-submitter cap above 64; a principal accumulates more than 64 same-tuple foreign-origin pending rows; `find_pending()` returns `nullopt` although an eligible MCP ticket exists behind them.
- Inference: Current behavior is safe because 25 is below 64; this is a future-maintenance tripwire, not an active #2442 bypass.
- Anchor:    judgment.
- Precedent: none found.
- Mitigations: Current cap is 25; `tests/unit/server/test_approval_manager.cpp:990-1022` verifies a foreign-origin row in front of one eligible row is skipped.
- Fix:       Move the cap and scan limit into one shared constant/contract with `static_assert(kFindPendingScanLimit > kMcpSubmitterPendingCap)`, or make the SQL filter single-source-safe another way.

[CDX-P2-003] new-from-cross-exam · LOW · CONFIDENCE(hi) · PROVENANCE(static-read)
Two-argument `consume_ticket()` keeps a public path that discards failure kind
- Location:  server/core/src/approval_manager.cpp:554
- Claim:     The legacy overload drops `ConsumeFailure`, creating an avoidable trap for future production callers that need to distinguish foreign-origin denial from replay/store/precondition failures.
- Evidence:  `approval_manager.cpp:556` calls the typed overload, then `approval_manager.cpp:568` returns only `r.error().message`; `rg -n "consume_ticket\\(" server/core/src` found the only production caller at `mcp_server.cpp:3268`, and it uses the typed three-argument overload.
- Scenario:  A future MCP or REST-facing caller chooses the simpler overload, can only log/branch on a flat string, and loses the `kForeignOrigin` distinction this change added for audit and metrics.
- Inference: This does not affect the current branch behavior because the production MCP recall already uses the typed overload.
- Anchor:    judgment.
- Precedent: server/core/src/mcp_server.cpp:3268 uses `consume_ticket(id, consumed_by, {})` and switches on `consumed.error().kind` at `mcp_server.cpp:3293-3305`.
- Mitigations: No production caller uses the flat overload today; tests exercise it.
- Fix:       Remove the two-argument overload, make it private/test-only, or change it to return `ConsumeError`.

## Delta Since Phase 1

- Adopted Kimi K2 as [CDX-P2-002] LOW and K3 as [CDX-P2-003] LOW after independent verification.
- Rebutted K1 as a documented accepted residual, not a separate defect.
- Re-ran compile and targeted tests in the current tree; `[security]`, `[approval]`, `"MCP 2442*"`, and `[approval_manager][security]` passed.
- `[mcp]` still fails in four unrelated `test_mcp_body_cap.cpp:110` listener-start assertions (`port == -1`), matching my Phase 1 failure and contradicting Kimi’s reported green `[mcp]`.

VERDICT:  PASS — no CRITICAL/HIGH finding; the consume-side origin guard remains sound for declared non-MCP mints, with one MEDIUM observability undercount and two LOW maintenance issues.
COVERAGE: Deep: security/privilege, origin guard, `kUnspecified` exemption, dedup path, consume CAS/kind branching, REST/scheduler/MCP mint sites, metrics/audit behavior, and Kimi cross-exam. Medium: resource/concurrency safety for changed code paths; no new raw owning resources or threads were introduced. Skimmed: cross-platform beyond Linux compile; CI status on PR head was not checked because network/GitHub access was not used. `STREAM.md` is absent at the worktree root despite AGENTS/CLAUDE requiring it.
RAN:      `source scripts/ensure-erlang.sh && CCACHE_DIR=/tmp/advrev-2442/ccache CCACHE_TEMPDIR=/tmp/advrev-2442/ccache-tmp meson compile -C build-linux` passed. Initial direct test execution failed because `build-linux/tests/yuzu_server_tests` was mode `0644`; after `chmod +x build-linux/tests/yuzu_server_tests`, `./build-linux/tests/yuzu_server_tests "[security]"` passed: 214 cases, 192 passed, 22 skipped, 1483 assertions. `./build-linux/tests/yuzu_server_tests "[approval]"` passed: 65 cases, 64 passed, 1 skipped, 835 assertions. `./build-linux/tests/yuzu_server_tests "[mcp]"` failed: 417 cases, 372 passed, 4 failed, 41 skipped; all failures were `test_mcp_body_cap.cpp:110 REQUIRE(port > 0)` with `port == -1`. `./build-linux/tests/yuzu_server_tests "MCP 2442*"` passed: 2 cases, 27 assertions. `./build-linux/tests/yuzu_server_tests "[approval_manager][security]"` passed: 6 cases, 50 assertions. `git diff --check b061cd7475f383b5eef946b9833bd0fed2d0b76a..4b83f70be1a6ded48629f339f4c6065fd1fcca1d` passed. `git status --short` was clean. CI status on PR head: not checked.
FILES:    docs/workstreams.md; attempted root STREAM.md (missing); CLAUDE.md; .claude/routed-concerns.md; docs/mcp-server.md; docs/auth-architecture.md; docs/observability-conventions.md; docs/cpp-conventions.md; docs/adr/1005-headless-platform-use-case-engines.md; docs/user-manual/metrics.md; /tmp/advrev-2442/codex.phase1.md; /tmp/advrev-2442/kimi.phase1.md; server/core/src/approval_manager.hpp; server/core/src/approval_manager.cpp; server/core/src/mcp_server.cpp; server/core/src/workflow_routes.cpp; server/core/src/schedule_runner.cpp; server/core/src/server.cpp; tests/unit/server/test_approval_manager.cpp; tests/unit/server/test_mcp_server.cpp.
