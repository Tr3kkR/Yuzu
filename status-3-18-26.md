# Yuzu Status Assessment — 2026-03-18

> **HISTORICAL SNAPSHOT (2026-03-18).** This assessment is outdated. At the time of writing, Phases 3-7 were marked "not started" and capability completion was 32%. As of 2026-03-26, all 72 roadmap issues are done (100%) and capability completion is 68% (96/142). See `docs/roadmap.md` for current status.

## Overall Numbers

| | Done | Open | Total |
|---|---:|---:|---:|
| **GitHub Issues** | — | **95** | 95 |
| **Roadmap Items** | **19** | **51** | 70 |
| **Capabilities** | **44** | **95** | 139 (32%) |

---

## Phase-by-Phase Status

| Phase | Roadmap | Code Verified | Notes |
|---|---|---|---|
| **0 — Foundation** | 5/5 Done | All verified | HTTPS, OTA, temp files, SDK utils, partial items |
| **1 — Data Infra** | 7/7 Done | All verified | ResponseStore, AuditStore, TagStore, ScopeEngine, export |
| **2 — Instructions** | 7/12 Done | 7 verified | InstructionStore, ExecutionTracker, ApprovalManager, ScheduleEngine all functional |
| **3 — Security** | 0/9 Done | **Discrepancy** | See below |
| **4 — Agent Infra** | 0/8 Done | Confirmed not started | No trigger engine, KV store, content staging, or user interaction |
| **5 — Policy** | 0/5 Done | Confirmed not started | No policy engine code |
| **6 — Windows** | 0/6 Done | Confirmed not started | No registry/WMI plugins |
| **7 — Scale** | 0/18 Done | Confirmed not started | No health monitoring, AD sync, webhooks, etc. |

---

## Key Discrepancies (Roadmap vs Code)

3 Phase 3 items have substantial implementations but are still marked "Open" in the roadmap:

1. **Issue #159 — OIDC SSO** (Phase 3.4): 575 LOC, fully functional — PKCE flow, Entra ID discovery, JWT validation, group claim parsing, token exchange, session creation with group-to-role mapping. Should be marked Done or near-done.

2. **Issue #154 — Granular RBAC** (Phase 3.1): 777 LOC — full CRUD for roles/permissions/principals, 10 securable types, 5 operations, deny-override logic, system roles. Infrastructure is done, but granular enforcement isn't wired into all REST endpoints yet.

3. **Issue #161 — REST API v1** (Phase 3.5): 70+ endpoints already exist across instructions, executions, schedules, approvals, responses, audit, tags, scope, settings. Substantially implemented, though the issue asks for consistent `/api/v1/` prefix and full standardization.

**Capability map inconsistency**: Progress bar shows "32/33 (97%)" for Foundation, but Appendix B claims "33/33 (100%) — all gaps closed as of 2026-03-18."

---

## Phase 2 Remaining (5 Open Items)

| Issue | Title | Status |
|---|---|---|
| #205 | Error code taxonomy (1xxx-4xxx) | Open |
| #206 | Concurrency enforcement (5 modes) | Open |
| #207 | YAML authoring UI (CodeMirror) | Open |
| #208 | Legacy command shim | Open |
| #209 | Structured result envelope | Open |

---

## Phase 3 — Actual Gaps (after accounting for implemented code)

| Issue | Title | True Status |
|---|---|---|
| #154 | Granular RBAC System | Store done; endpoint enforcement not wired |
| #156 | Management Groups | Group infrastructure in RBAC; no hierarchy yet |
| #157 | Token-Based API Authentication | Not started |
| #159 | OIDC / SSO Integration | Implemented (575 LOC) |
| #161 | REST / HTTP Management API (v1) | 70+ endpoints exist; needs `/api/v1/` standardization |
| #162 | Device Quarantine | Not started |
| #164 | IOC Checking | Not started |
| #165 | Certificate Inventory and Management | Not started |
| #210 | Scope DSL Extensions | Not started |

---

## Gateway (Erlang) — Bugs

| Issue | Title | Severity |
|---|---|---|
| #120 | Fanout completion — `fanout_terminal` path inactive | HIGH |
| #121 | `persistent_term` misuse for transient agent state | HIGH |
| #124 | Unbounded spawn in `notify_stream_status` | HIGH |
| #122 | Inconsistent error tuple shapes across modules | MEDIUM |
| #123 | Command duration hard-coded to 0 | MEDIUM |
| #125 | ListAgents hostname field empty | MEDIUM |
| #126 | pg:start_link safety in app startup | MEDIUM |

## Gateway (Erlang) — Enhancements (14 Open)

Issues #127-#142, #204 — ranging from dynamic supervisor migration to multi-tenant isolation and signed command envelopes.

---

## Infrastructure & Code Quality (12 Open)

Notable items:
- #80 — Plugin code signing and allowlist
- #81 — Config file and environment variable support
- #82 — Docker images, Compose, and Kubernetes manifests
- #87 — Agent reconnection with exponential backoff
- #117 — Expand test coverage for agent command lifecycle
- #118 — Refactor long core routines

---

## Server Implementation Summary

| Component | Status | LOC | Maturity |
|-----------|--------|-----|----------|
| RBAC Store | Functional | 777 | Production |
| OIDC SSO | Functional | 575 | Production |
| REST API v1 | Functional | 5,187 | Production |
| Response Store | Functional | 328 | Production |
| Audit Store | Functional | 255 | Production |
| Tag Store | Functional | 264 | Production |
| Scope Engine | Functional | 580 | Production |
| Instruction Store | Functional | 541 | Production |
| Execution Tracker | Functional | 392 | Production |
| Approval Manager | Functional | 268 | Production |
| Schedule Engine | Functional | 353 | Production |
| Policy Engine | Not started | 0 | Phase 5 |
| Management Groups | Partial | ~100 | Foundation only |
| API Tokens | Not started | 0 | Phase 3 |
| Agent Health Store | Not started | 0 | Phase 7 |

## Agent Implementation Summary

| Component | Status | LOC | Notes |
|-----------|--------|-----|-------|
| Agent Core | Functional | 2,877 | gRPC, heartbeat, plugin loading, OTA, mTLS, enrollment |
| 30 Plugins | Functional | 9,902 | Hardware, network, filesystem, users, processes, security |
| Trigger Engine | Not started | 0 | Phase 4 |
| KV Storage | Not started | 0 | Phase 4 |
| Content Distribution | Partial | 543 | OTA binary download only |
| User Interaction | Not started | 0 | Phase 4/6 |

## Test Coverage

- 27 C++ test files (Catch2) covering server + agent + SDK
- 16 Erlang test files (EUnit + Common Test) for gateway
- Gateway tests now wired into Meson (`meson test --suite gateway`)

---

## Recommended Next Actions

1. **Update the roadmap** — Mark #159 (OIDC), #154 (RBAC store), and #161 (REST API) to reflect implementation reality
2. **Fix capability map** Foundation progress bar (97% vs 100% conflict)
3. **Finish Phase 2** — 5 remaining items (#205-#209) close out instruction system
4. **Fix gateway HIGH-severity bugs** (#120, #121, #124) before scaling
5. **Phase 3 remaining** — API tokens (#157), management group hierarchy (#156), and wiring RBAC enforcement into endpoints are the real gaps
