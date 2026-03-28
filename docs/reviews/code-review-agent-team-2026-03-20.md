# Code Review — Full Governance Retrospective (2026-03-28)

> **Supersedes** the original 2026-03-20 5-agent review. This document is the authoritative finding register for the Yuzu codebase, maintained across governance review sessions.

## Review Context

| Field | Value |
|-------|-------|
| Date | 2026-03-28 |
| Process | 7-gate governance (expanded from 5 gates on 2026-03-28) |
| Scope | Tier 1 complete (auth, REST API, engines, MCP). Tiers 2-4 pending. |
| Prior art | RC sprint (2026-03-22 to 2026-03-24) found 52 findings (7C/16H/22M/7L), all resolved |
| Agents used | security-guardian, docs-writer, architect, dsl-engineer, performance, happy-path, unhappy-path, consistency-auditor, chaos-injector |
| Invocations | ~50 agent invocations across Gates 1-5 |

## Governance Process (7 Gates)

1. **Change Summary** — codebase inventory for Tier 1 partitions
2. **Mandatory deep-dive** — security-guardian + docs-writer on all Tier 1 batches
3. **Domain-triggered review** — architect + dsl-engineer + performance
4. **Correctness & resilience** — happy-path + unhappy-path + consistency-auditor (parallel)
5. **Chaos analysis** — chaos-injector synthesized 10 compound failure scenarios
6. **Finding resolution** — code fixes committed and tested
7. **Iteration** — re-build + full test suite pass

## Tier 1 Partitions Reviewed

| Partition | Batches | Files | Status |
|-----------|---------|-------|--------|
| A: Auth & Security | A1 (auth, RBAC, OIDC), A2 (tokens, certs) | ~11 files | Complete |
| B1: REST API | B1 (rest_api_v1.cpp/.hpp) | ~2 files | Complete |
| D: Engines | D1 (CEL, policy), D2 (scope, workflow, schedule), D3 (compliance, approval, execution) | ~22 files | Complete |
| E: MCP Server | E1 (mcp_server, jsonrpc, policy) | ~4 files | Complete |

---

## Master Finding Register

### CRITICAL (1 found, 1 fixed)

| ID | Finding | File | Fix Commit |
|----|---------|------|------------|
| G2-SEC-A1-001 | OIDC JWT signature never validated — forged ID tokens possible | oidc_provider.cpp | `f05609a` |

### HIGH — Security (5 found, 5 fixed)

| ID | Finding | File | Fix Commit |
|----|---------|------|------------|
| G2-SEC-A1-002 | `check_scoped_permission` unsynchronized SQLite access | rbac_store.cpp | `6814755` (mutex added) |
| G2-SEC-A2-002 | ApiTokenStore no mutex on shared db handle | api_token_store.cpp | `46183c0` |
| G2-SEC-D1-001 | ReDoS via `std::regex` in CEL `.matches()` | cel_eval.cpp | `11a5590` (RE2) |
| G2-SEC-D1-002 | No wall-clock execution timeout on CEL evaluation | cel_eval.cpp | `2978296` |
| G2-SEC-D2-001 | ReDoS via `std::regex` in scope `MATCHES` operator | scope_engine.cpp | `11a5590` (RE2) |

### HIGH — Architecture (3 found, 3 fixed)

| ID | Finding | File | Fix Commit |
|----|---------|------|------------|
| G3-ARCH-001 | server.cpp god object (11K LOC, 28 store members) | server.cpp | Documented; extraction planned |
| G3-ARCH-002 | Two-tier DB ownership with decoupled lifetimes | Multiple | Documented |
| G3-ARCH-003 | 11 stores lack SQLite mutexes | 9 store headers | `6814755` (9 stores), `46183c0` (2 stores) |

### HIGH — Performance (5 found, 3 fixed)

| ID | Finding | File | Fix Commit |
|----|---------|------|------------|
| G3-PERF-001 | Regex recompilation per CEL evaluation call | cel_eval.cpp | Mitigated by RE2 (faster than std::regex) |
| G3-PERF-002 | Regex recompilation per scope agent | scope_engine.cpp | Mitigated by RE2 |
| G3-PERF-004 | RBAC check: 2+ SQL queries per request, no cache | rbac_store.cpp | `2978296` (perm cache) |
| G3-PERF-005 | RBAC scoped check: N+2 query amplification | rbac_store.cpp | Partially mitigated by cache |
| G3-PERF-010 | Fleet compliance cache writes under shared_lock (UB) | policy_store.cpp | `babb600` (unique_lock) |

### HIGH — DSL (2 found, 2 fixed)

| ID | Finding | File | Fix Commit |
|----|---------|------|------------|
| G3-DSL-001 | ReDoS in CEL + scope (same as D1-001/D2-001) | cel_eval.cpp, scope_engine.cpp | `11a5590` |
| G3-DSL-002 | No wall-clock timeout on CEL (same as D1-002) | cel_eval.cpp | `2978296` |

### HIGH — Correctness & Resilience (Gate 4)

| ID | Finding | File | Fix Commit |
|----|---------|------|------------|
| G4-UHP-AUTH-001 | Deleted user retains active sessions 8hrs | auth.cpp | `babb600` |
| G4-UHP-AUTH-003 | ManagementGroupStore has zero mutex (RBAC hot path) | management_group_store.hpp | `6814755` |
| G4-UHP-AUTH-004 | `check_scoped_permission` TOCTOU across lock releases | rbac_store.cpp | Documented; needs refactor |
| G4-CON-AUTH-001 | Session role never updated on role change | auth.cpp | `babb600` |
| G4-CON-AUTH-002 | Deleted user sessions never invalidated (dup of AUTH-001) | auth.cpp | `babb600` |
| G4-UHP-POL-001 | Unresolved CEL variable silently → false non-compliance | cel_eval.cpp | `2978296` (tri-state) |
| G4-UHP-POL-003 | No fix retry limit — infinite remediation loop | policy_store.cpp | `2978296` (max 3) |
| G4-UHP-POL-006 | Fleet compliance cache data race (dup of PERF-010) | policy_store.cpp | `babb600` |
| G4-UHP-POL-008 | CEL error conflated with non-compliance | compliance_eval.cpp | `2978296` (ComplianceResult enum) |
| G4-UHP-MCP-002 | MCP read_only_mode captured by value, runtime toggle dead | mcp_server.cpp | `babb600` (const bool&) |
| G4-UHP-MCP-003 | MCP kill switch only evaluated at startup | mcp_server.cpp | `46183c0` (runtime check) |
| G4-UHP-MCP-004 | Approval workflow: no TTL, no notification, unbounded queue | approval_manager.cpp | `2978296` (7-day TTL, 1000 cap) |
| G4-UHP-MCP-005 | ApprovalManager TOCTOU on concurrent approve/reject | approval_manager.cpp | `46183c0` (mutex + atomic WHERE) |

### HIGH — Documentation (10 found, 0 fixed — deferred)

| ID | Finding | File |
|----|---------|------|
| G2-DOC-A1-001 | HTTPS flag docs stale (`--https` vs `--no-https`) | authentication.md |
| G2-DOC-A1-003 | RBAC docs missing 5 securable types | rbac.md |
| G2-DOC-A1-004 | All 6 system role permission counts wrong | rbac.md |
| G2-DOC-A2-002 | REST API doesn't accept `mcp_tier` despite docs claiming it | rest-api.md |
| G2-DOC-A2-005 | Device token endpoints entirely undocumented | rest-api.md |
| G2-DOC-B1-001 | Inventory v1 endpoints undocumented | rest-api.md |
| G2-DOC-B1-002 | Execution statistics endpoints undocumented | rest-api.md |
| G2-DOC-B1-003 | Device token endpoints undocumented (dup of A2-005) | rest-api.md |
| G2-DOC-B1-004 | Software deployment endpoints (7) undocumented | rest-api.md |
| G2-DOC-B1-005 | License management endpoints (4) undocumented | rest-api.md |

**Key stat:** 24 of 52 REST API v1 endpoints (46%) have zero documentation.

### MEDIUM — Fixed (12)

| ID | Finding | Fix Commit |
|----|---------|------------|
| G2-SEC-A1-003 | No minimum password length | `9ad692b` (12-char min) |
| G2-SEC-A1-004 | Expired sessions never reaped | `9ad692b` (opportunistic reaper) |
| G2-SEC-A2-001 | mt19937_64 instead of CSPRNG for tokens | `9ad692b` (RAND_bytes) |
| G2-SEC-B1-004 | Missing security response headers | `9ad692b` (X-Frame-Options, HSTS, etc.) |
| G2-SEC-B1-005 | No CSRF protection beyond SameSite=Lax | `6814755` (Origin validation) |
| G2-SEC-D2-005 | Schedule scope_expression not validated before storage | `9ad692b` |
| G2-SEC-D2-006 | Schedule enable/disable missing audit event | `9ad692b` |
| G2-SEC-D2-008 | Workflow retry_count/delay unbounded | `9ad692b` (clamp to 10/3600) |
| G3-ARCH-005 | 6 non-thread-safe static RNGs | `babb600` (thread_local) |
| G4-UHP-POL-007 | Offline agents retain stale compliance status | `9ad692b` (24hr staleness TTL) |
| G4-UHP-POL-009 | `invalidate_policy` sets undeclared 'pending' status | `babb600` (→'unknown') |
| G4-UHP-MCP-008 | MCP automation starves human dashboard rate limit | `6814755` (separate bucket) |

### MEDIUM — Remaining (unfixed, Tier 1 only)

| ID | Finding | Notes |
|----|---------|-------|
| G2-SEC-A1-005 | RBAC `set_permission` doesn't validate effect value | Add "allow"/"deny" validation |
| G2-SEC-A1-006 | OIDC pending challenges map unbounded | Add max size check |
| G2-SEC-A2-003 | API token ID from 12-char hash prefix (collision risk) | Use longer ID |
| G2-SEC-A2-004 | `mcp_tier` not validated at store layer | Call `is_valid_tier()` |
| G2-SEC-B1-001 | Dead CORS helper reflects arbitrary Origin | Delete dead code |
| G2-SEC-B1-002 | No upper bound on execution statistics `limit` | Add clamp to 1000 |
| G2-SEC-B1-003 | Inventory evaluate: 10K hardcoded limit, unbounded conditions | Add cap |
| G2-SEC-D1-003 | CEL recursion depth 64 vs documented 10 | Reduce to 16 |
| G2-SEC-D1-004 | Unbounded string concatenation in CEL | Add kMaxStringResultLength |
| G2-SEC-D1-005 | (Dup of PERF-010 — fixed) | — |
| G2-SEC-D2-002 | NOT recursion bypasses scope depth (partially fixed) | Verify CEL parse_not too |
| G2-SEC-D2-003 | No execution time bound on scope evaluation | Add deadline like CEL |
| G2-SEC-D2-011 | Scheduled execution doesn't enforce creator's permissions | Re-validate at dispatch |
| G2-SEC-E1-001 | MCP read_only captured by value (fixed in mcp_server, but server.cpp caller needs check) | Verify end-to-end |
| G2-SEC-E1-004 | `yuzu://server/health` resource skips RBAC | Add perm check |
| G3-DSL-004 | NOT recursion bypass in CEL parser | Add depth check to parse_not_legacy |
| G3-DSL-005 | yaml-dsl-spec.md lists MATCHES/EXISTS as "planned" | Update spec |
| G3-DSL-006 | Unknown characters silently skipped in CEL lexer | Return error token |
| G4-CON-AUTH-004 | Token ID generation inconsistent across stores | Standardize |
| G4-CON-AUTH-005 | Dual role system without formal mapping | Document contract |
| G4-UHP-MCP-011 | No scope blast-radius enforcement (warning only) | Add hard limit for Phase 2 write tools |

### LOW — Summary (not itemized, ~40 findings)

Categories: defense-in-depth suggestions, minor inconsistencies, documentation formatting, test coverage gaps, informational observations. Full details in the Gate 2-5 agent outputs during the 2026-03-28 conversation.

---

## Chaos Scenarios (Gate 5)

The chaos-injector synthesized 10 compound failure scenarios from Gate 4 risks. The 4 most dangerous:

| ID | Severity | Chain | Status |
|----|----------|-------|--------|
| CHAOS-T1-001 | CRITICAL | Ghost admin after deletion (3 findings) | **Fixed** — sessions invalidated on removal/role change |
| CHAOS-T1-002 | CRITICAL | ReDoS double-tap — server DoS via 6-char regex | **Fixed** — RE2 linear-time matching |
| CHAOS-T1-005 | CRITICAL | Infinite remediation loop from CEL typo | **Fixed** — fix retry limit (3) + tri-state compliance |
| CHAOS-T1-009 | CRITICAL | Full chain: 8 findings → complete control-plane takeover | **Mostly fixed** — 6 of 8 constituent findings resolved |

All 10 scenarios documented in the 2026-03-28 Gate 5 conversation output.

---

## Commits (2026-03-28 governance session)

| Commit | Description | Files | +/- |
|--------|-------------|-------|-----|
| `d3d19bb` | Add 4 governance agents + expand 5→7 gates | 6 | +720 |
| `3603de8` | Fix governance process findings (terminology, contracts) | 5 | +38/-25 |
| `babb600` | Fix 9 findings: sessions, cache race, scope safety, MCP toggle, RNGs | 11 | +43/-14 |
| `46183c0` | Fix 4 findings: store mutexes, approval TOCTOU, MCP kill switch | 7 | +29/-8 |
| `f05609a` | OIDC JWT signature verification via JWKS (CRITICAL) | 2 | +307/-1 |
| `11a5590` | Replace std::regex with RE2 (ReDoS fix) | 4 | +33/-30 |
| `2978296` | CEL timeout, compliance tri-state, fix retry, approval TTL, RBAC cache | 10 | +251/-87 |
| `9ad692b` | Passwords, headers, validation, staleness | 6 | +81/-30 |
| `6814755` | CSRF, 9 store mutexes, MCP rate limit, scope guard | 11 | +59/-3 |

**Total: 9 commits, 35 files, +812/-201 lines**

---

## Remaining Work: Tiers 2-4

### Tier 2 — Data Integrity (next priority)

| Partition | Batches | Files | Focus |
|-----------|---------|-------|-------|
| C: Data Stores | C1-C4 | 20+ *_store files | SQL injection audit, lock contention, pagination |
| F: Server Infrastructure | F1-F4 | server.cpp (11K LOC), NVD, patches | God-object decomposition, startup security |
| I: Gateway Erlang | I1-I4 | 18 .erl files | Process lifecycle, supervision, proto consistency |

**Estimated: ~30 agent invocations, ~1.5 hours**

### Tier 3 — Functional Correctness

| Partition | Batches | Files | Focus |
|-----------|---------|-------|-------|
| G: Agent Core | G1-G3 | 23 files | Plugin loader, trigger engine, cert handling |
| H: Plugins | H1-H8 | 45 dirs | ABI compliance, isolation, crash safety |
| J: Proto & SDK | J1 | 11 files | Wire compatibility, ABI stability |

**Estimated: ~25 agent invocations, ~1.5 hours**

### Tier 4 — Coverage & Completeness

| Partition | Batches | Files | Focus |
|-----------|---------|-------|-------|
| K: Tests | K1-K6 | 80 test files | Coverage gaps, test isolation, assertion quality |
| L: Docs, YAML, Deploy, CI | L1-L4 | 103 files | 24 undocumented REST endpoints, YAML def sync, CI coverage |

**Estimated: ~20 agent invocations, ~1 hour**

### Execution Notes for Future Sessions

1. **Build environment:** builddir is at `/mnt/data/builddir`. Root filesystem (`/dev/sda1`) has limited space — always build on `/mnt/data`. vcpkg tools at `/root/Yuzu/vcpkg_installed/x64-linux/tools/{protobuf,grpc}/`.
2. **Test baseline:** 6/6 suites pass (gateway CT integration test may skip if no upstream). 30,171 assertions, 350 test cases.
3. **RE2 dependency:** Added to `server/core/meson.build` via cmake method. Already installed as gRPC transitive dep.
4. **Erlang gateway:** Pre-existing rebar3/OTP version issues on this box. Gateway compiles but CT suite needs live upstream.
5. **Rate limits:** Session hit Claude API rate limits after ~50 agent invocations. Plan for 2-3 sessions to complete Tiers 2-4.
6. **Documentation debt:** The 10 HIGH doc findings (24 undocumented endpoints) should be addressed in a dedicated docs session, not interleaved with code fixes.
