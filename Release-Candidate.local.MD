# Yuzu Release Candidate — Readiness Assessment & Sprint Plan

**Author:** Software Architect (Claude Code Team Review)
**Date:** 2026-03-22 (sprint outcome updated 2026-03-26)
**Branch:** `dev` (commit `df3d0cb`)
**Roadmap Status:** 72/72 issues closed (100%), 96/142 capabilities (68%)

---

## Sprint Outcome

**All 52 findings resolved** as of 2026-03-24 — ahead of the 2026-03-27 deadline.

| Severity | Count | Status | Key Commits |
|----------|:-----:|--------|-------------|
| **CRITICAL** | 7 | All fixed | `4bdae88` — Fix 8 CRITICALs from team review |
| **HIGH** | 16 | All fixed | `73b1d65` — Fix 14 HIGH findings from MCP team review |
| **MEDIUM** | 22 | All fixed | Across multiple commits |
| **LOW** | 7 | All fixed | `b1fca75` — Fix all 7 LOWs |

Additional hardening: `47aa65d` (MCP server), `c8f74fc` (gateway test cleanup), `492ec35` (scale test isolation).

**Updated Verdict: RC-READY** (conditional on final validation pass).

> The original assessment below retains the "NOT YET RC-READY" verdict as written on 2026-03-22,
> prior to the sprint. All findings described below have since been resolved.

---

---

## Team Structure

| Role | Domain | Primary Concerns |
|------|--------|------------------|
| **Architect** | System-wide | Module boundaries, proto compat, ABI stability, sprint coordination |
| **Security Guardian** | Auth, crypto, input validation | Session mgmt, injection, RBAC enforcement, audit, secrets |
| **Server Dev** | `server/core/` | REST API, SQLite stores, gRPC services, state management |
| **Plugin Developer** | `agents/core/`, `agents/plugins/`, `sdk/` | Plugin ABI, loader, agent lifecycle, trigger engine |
| **Quality Engineer** | `tests/`, CI | Test coverage, fuzz targets, integration tests, CI matrix |
| **Docs Writer** | `docs/` | User manual, REST API docs, YAML DSL spec, getting-started |
| **Build & CI/CD** | `.github/workflows/`, `meson.build`, `deploy/` | Packaging, signing, release workflow, cross-compilation |
| **Erlang Gateway Dev** | `gateway/` | OTP supervision, gRPC client, connection mux, backpressure |
| **Metrics/Observability** | Prometheus, Grafana, ClickHouse | Metrics endpoints, audit log, analytics sinks, dashboards |
| **HTMX/UI Champion** | `server/core/src/*_ui.cpp` | Dashboard rendering, dark theme, HTMX fragments, UX |
| **DSL & YAML Author** | `docs/yaml-dsl-spec.md`, `content/definitions/` | Scope DSL, CEL, parameter interpolation, YAML content kinds |
| **Darwin Specialist** | macOS builds, `/private/var` symlinks | Apple Clang, Gatekeeper, notarization, path canonicalization |
| **Windows Specialist** | MSVC, cert store, registry, WMI | Authenticode, service install, DLL deployment, SmartScreen |
| **Linux Specialist** | systemd, deb/rpm, LSM | Package builds, SELinux/AppArmor, hardening flags |

---

## Executive Summary

Yuzu is feature-complete across all 7 roadmap phases. The codebase demonstrates strong
fundamentals: stable C ABI for plugins, production-grade mTLS, comprehensive RBAC,
well-structured SQLite stores, and a 45-plugin inventory covering enterprise endpoint
management.

The team identified **52 findings** across all domains:

| Severity | Count | Disposition |
|----------|:-----:|-------------|
| **CRITICAL** | 7 | Must fix before RC |
| **HIGH** | 16 | Must fix or explicitly accept risk |
| **MEDIUM** | 22 | Should fix; acceptable to defer with documentation |
| **LOW** | 7 | Defer to post-RC |

**Verdict: NOT YET RC-READY.** Blockers concentrate in three areas:
1. Erlang gateway lacks production hardening (TLS, health, circuit breaker)
2. Binary signing absent for Windows/macOS
3. Test coverage has critical gaps (REST API, plugin functional tests)

A focused 3-4 week sprint resolves all blockers.

---

## Domain-by-Domain Verdict

| Domain | Owner | Verdict | Blockers |
|--------|-------|---------|----------|
| **Security** | Security Guardian | APPROVED (conditional) | H1-H5 must be addressed |
| **Server/REST API** | Server Dev | APPROVED (conditional) | C6, H6-H7 must be fixed |
| **Agent & Plugins** | Plugin Developer | APPROVED | M13 only (chargen.yaml) |
| **Test Suite** | Quality Engineer | NOT APPROVED | C5 is release-blocking |
| **Documentation** | Docs Writer | APPROVED | M18-M19 are low-effort fixes |
| **Build & CI/CD** | Build & CI/CD | NOT APPROVED | C4, C7, H8-H11 blocking |
| **Erlang Gateway** | Erlang Gateway Dev | NOT APPROVED | C1-C3, H12-H16 blocking |
| **Observability** | Metrics/Observability | APPROVED | M17, M20 are nice-to-haves |

---

## TIER 0 — CRITICAL (Must Fix Before RC)

### C1. Erlang Gateway: Plaintext gRPC to Upstream Server
- **Owner:** Erlang Gateway Dev
- **Finding:** Gateway connects to Yuzu Server over unencrypted HTTP/2 by default.
  `sys.config` has TLS commented out.
- **Risk:** Entire management plane (commands, inventory, heartbeats) in cleartext.
- **Fix:** Create `sys.config.prod` with mandatory TLS. Add environment variable
  overrides for container deployment. Document cert provisioning.
- **Files:** `gateway/config/sys.config`

### C2. Erlang Gateway: No Health/Readiness Endpoints
- **Owner:** Erlang Gateway Dev
- **Finding:** Gateway exposes only Prometheus `/metrics`. No `/health`, `/ready`,
  or gRPC Health Check service.
- **Risk:** Cannot integrate with Kubernetes, Docker health checks, or load balancers.
  Enterprise evaluators will flag this immediately.
- **Fix:** Implement standard gRPC `grpc.health.v1.Health` service + HTTP `/healthz`.

### C3. Erlang Gateway: No Circuit Breaker for Upstream Failures
- **Owner:** Erlang Gateway Dev
- **Finding:** If upstream server is unreachable, all agent Register calls block for
  30s with no backoff. Commands silently dropped under backpressure (threshold 1000,
  not configurable).
- **Risk:** Cascading failure — server restart causes thundering herd that exhausts
  Erlang schedulers.
- **Fix:** Exponential backoff, circuit breaker state machine, configurable backpressure
  threshold with operator alerting.

### C4. Windows/macOS Binary Signing Not Implemented
- **Owner:** Build & CI/CD + Windows Specialist + Darwin Specialist
- **Finding:** Release workflow produces unsigned executables. Windows SmartScreen
  blocks `yuzu-agent.exe`. macOS Gatekeeper rejects unsigned binaries entirely.
- **Risk:** Enterprise evaluators on Windows/macOS cannot run the software without
  overriding OS security warnings — a non-starter.
- **Fix:** Integrate Authenticode signing (Windows) and `codesign` + notarization
  (macOS) into release workflow. Requires code signing certificates.
- **Files:** `.github/workflows/release.yml`

### C5. REST API Has Zero Unit Tests
- **Owner:** Quality Engineer + Server Dev
- **Finding:** `rest_api_v1.cpp` (1,355 lines, 31+ endpoints) has no unit test
  coverage. Only indirect coverage via `scripts/integration-test.sh` which is not
  run in CI.
- **Risk:** Regressions in the primary operator interface go undetected.
- **Fix:** Create `test_rest_api_v1.cpp` covering all endpoint groups (auth, CRUD,
  error cases, validation). Wire integration test into CI.
- **Files:** `tests/unit/server/` (new), `scripts/integration-test.sh`

### C6. AnalyticsEventStore Thread Safety Bug
- **Owner:** Server Dev
- **Finding:** `query_recent()`, `pending_count()`, and `total_emitted()` access
  `db_` without acquiring `mu_`. `emit()` does hold the mutex. This is a data race.
- **Risk:** Concurrent analytics queries during event emission corrupt SQLite state,
  causing server crash.
- **Fix:** Add `std::lock_guard<std::mutex> lock(mu_);` to all three methods.
- **File:** `server/core/src/analytics_event_store.cpp:84-120`

### C7. Proto Codegen Not Reproducible
- **Owner:** Build & CI/CD
- **Finding:** `gen_proto.py` does not validate `protoc` version. Different CI
  environments may generate incompatible code silently.
- **Risk:** Binary incompatibility between server and agent built on different machines.
- **Fix:** Add version assertion to `gen_proto.py`. Print and validate
  `protoc --version` matches expected baseline.
- **Files:** `proto/gen_proto.py`

---

## TIER 1 — HIGH (Must Fix or Accept Risk)

### Security (Security Guardian)

| ID | Finding | File | Fix |
|----|---------|------|-----|
| H1 | Web dashboard binds `0.0.0.0` by default | `server.hpp:17` | Change default to `127.0.0.1`, add startup warning if overridden |
| H2 | HTTPS disabled by default for dashboard | `server.hpp:56` | Change `https_enabled` default to `true` |
| H3 | `/metrics` endpoint unauthenticated | `server.cpp` | Gate with auth or bind to localhost only |
| H4 | No certificate hot-reload | `server.cpp` | Implement inotify/FSEvents watcher for cert file changes |
| H5 | Private key file permissions not validated at startup | `agent.cpp:547`, `server.cpp:717` | Check `st_mode & (S_IRWXG \| S_IRWXO)`, fail if world-readable |

### Server (Server Dev)

| ID | Finding | File | Fix |
|----|---------|------|-----|
| H6 | CORS response headers missing on 28/31 REST endpoints | `rest_api_v1.cpp` | Add `add_cors_headers(res, req)` to all handlers |
| H7 | 503 responses lack JSON error envelope | `rest_api_v1.cpp:408,435,473` | Return `{"error":"service unavailable","meta":{"api_version":"v1"}}` |

### Build & Release (Build & CI/CD)

| ID | Finding | Fix |
|----|---------|-----|
| H8 | Release workflow doesn't validate artifacts exist before signing | Add explicit file existence check before cosign |
| H9 | No integration/smoke tests in release builds (only `--help`) | Run full test suite in at least one release job |
| H10 | Debian/RPM packages not integrated into release workflow | Wire `build-deb.sh`/`build-rpm.sh` into CI, extract version from tag |
| H11 | Docker images not tested after build | Add `docker run --rm <image> --help` health check |

### Gateway (Erlang Gateway Dev)

| ID | Finding | Fix |
|----|---------|-----|
| H12 | Command duration metric always reports 0ms | Track dispatch timestamp per `command_id`, compute actual duration |
| H13 | Silent command drops under backpressure, no operator alert | Make threshold configurable, emit WARN, increment error counter |
| H14 | `grpcbox_plugin` dependency unpinned (`{branch, "master"}`) | Pin to release tag in `rebar.config` |
| H15 | No graceful shutdown handler | Implement SIGTERM -> drain pending commands -> close streams |
| H16 | No `.appup` file for hot-code upgrades | Generate `.appup`, test upgrade path |

---

## TIER 2 — MEDIUM (Should Fix, Can Defer with Documentation)

### Security & Hardening

| ID | Finding | Notes |
|----|---------|-------|
| M1 | Missing compiler hardening flags (RELRO, FORTIFY_SOURCE, stack canaries) | Add to `meson.build` for release builds |
| M2 | Session timeout not actively enforced in Subscribe RPC | Check `last_heartbeat_time` vs `session_timeout` |
| M3 | OIDC redirect_uri derived from Host header (phishing risk) | Use configured canonical URL instead |
| M4 | Secrets visible via CLI flags in `ps aux` | Enforce env var usage for secrets |
| M5 | Unauthenticated `/metrics` exposes fleet metadata | Gate or bind to localhost |
| M6 | No plugin allowlist by name or hash | Add optional hash validation at load time |
| M7 | Response store (SQLite) not encrypted at rest | Document; add `--encrypt-db` option later |
| M8 | No command replay protection (no sequence numbers) | Add monotonic command IDs |

### Server & Agent

| ID | Finding | Notes |
|----|---------|-------|
| M9 | Broad exception suppression (`catch (...)` without logging) | Replace in `analytics_event_store.cpp`, `auth.cpp` |
| M10 | Config file permissions not explicitly set to 0600 | Add `fs::permissions()` after write |
| ~~M11~~ | ~~HTMX loaded from unpkg CDN (external dependency)~~ | **RESOLVED** — HTMX 2.0.4 + htmx-ext-sse 2.2.2 vendored locally as `server/core/src/static_js_bundle.cpp`; served from same-origin `/static/htmx.js` and `/static/sse.js`. CSP `script-src` is now `'self'`-only with no external CDN allowance. Air-gap-friendly by default. Both upstream packages are 0BSD (no attribution required). |
| M12 | Config file format lacks schema versioning | Add version header for migration path |
| M13 | Missing `chargen.yaml` instruction definition | Only plugin without YAML (44/45 covered) |
| M14 | Max 500 triggers hardcoded | Make configurable or bump to 1000 |

### Build, Docs & Observability

| ID | Finding | Notes |
|----|---------|-------|
| M15 | Meson version hardcoded (`0.1.0`), not synced with git tags | Pull from tag or enforce pre-commit check |
| M16 | No sanitizer tests (ASan/UBSan/TSan) in CI or release builds | Add at least one ASan job to CI matrix |
| M17 | Grafana dashboard templates missing (referenced but don't exist) | Create `docs/grafana/*.json` dashboard exports |
| M18 | Windows service installation not documented | Add section to `docs/user-manual/server-admin.md` |
| M19 | REST API docs mix v1 and legacy endpoints without clear demarcation | Reorganize Table of Contents |
| M20 | Alert rules incomplete (no agent/gateway/store alerts) | Add comprehensive Prometheus rules file |
| M21 | No structured JSON logging mode for Splunk/ELK | Add `--log-format json` option |
| M22 | Gateway: fragile `pg:start_link` doesn't handle `already_started` | Guard in `yuzu_gw_app:start/2` |

---

## TIER 3 — LOW (Defer to Post-RC)

| ID | Finding | Notes |
|----|---------|-------|
| L1 | OIDC client secret sent in POST body vs Authorization header | Cosmetic OAuth 2.0 best practice |
| L2 | Plugin ABI not runtime-versioned beyond min/max check | Add `plugin_sdk_version` to manifest |
| L3 | Agent UUID uses Mersenne Twister instead of CSPRNG | Switch to `RAND_bytes()` |
| L4 | No Changelog automation (manual `CHANGELOG.md`) | Adopt conventional commits + `git-cliff` |
| L5 | Docker base images not pinned to digest | Use `ubuntu:24.04@sha256:...` |
| L6 | No macOS x64 (Intel) builds | ARM64 only; document limitation |
| L7 | No proto backward-compatibility validation in CI | Add `protolint` or custom check |

---

## RC Sprint Plan

### Week 1: Critical Fixes

**Erlang Gateway Dev:**
- [ ] C1: Create `sys.config.prod` with mandatory TLS, env var overrides
- [ ] C2: Implement gRPC `grpc.health.v1.Health` service + HTTP `/healthz`
- [ ] C3: Implement exponential backoff + circuit breaker for upstream

**Build & CI/CD + Windows Specialist + Darwin Specialist:**
- [ ] C4: Set up Authenticode signing for Windows executables
- [ ] C4: Set up `codesign` + Apple notarization for macOS binaries
- [ ] C7: Add `protoc --version` assertion to `gen_proto.py`

**Server Dev:**
- [ ] C6: Fix AnalyticsEventStore mutex protection (3 methods)
- [ ] H6: Add CORS headers to all REST endpoint handlers
- [ ] H7: Fix 503 response formatting (JSON error envelope)

**Security Guardian:**
- [ ] H1: Change default `web_address` to `127.0.0.1`
- [ ] H2: Change default `https_enabled` to `true`
- [ ] H3: Gate `/metrics` endpoint with auth or bind to localhost
- [ ] H5: Add key file permission check at startup (agent + server)

### Week 2: High-Priority & Testing

**Quality Engineer + Server Dev:**
- [ ] C5: Create `tests/unit/server/test_rest_api_v1.cpp` (all endpoint groups)
- [ ] C5: Wire `scripts/integration-test.sh` into CI pipeline
- [ ] M16: Add ASan+UBSan CI job (at least Linux GCC)

**Build & CI/CD:**
- [ ] H8: Add artifact existence validation before cosign in release workflow
- [ ] H9: Run full test suite in at least one release build job
- [ ] H10: Integrate `build-deb.sh`/`build-rpm.sh` into release workflow
- [ ] H11: Add Docker image health check (`docker run --rm <image> --help`)

**Erlang Gateway Dev:**
- [ ] H12: Fix command duration metric (track dispatch timestamp)
- [ ] H13: Make backpressure threshold configurable, add WARN log + counter
- [ ] H14: Pin `grpcbox_plugin` to release tag in `rebar.config`
- [ ] H15: Implement SIGTERM graceful shutdown handler
- [ ] H16: Generate `.appup` file, test upgrade path

### Week 3: Medium-Priority Hardening

**Build & CI/CD + Linux Specialist:**
- [ ] M1: Add compiler hardening flags to `meson.build` (RELRO, FORTIFY, canaries)
- [ ] M15: Sync meson.build version with git tags

**Docs Writer:**
- [ ] M18: Add Windows service installation section to server-admin.md
- [ ] M19: Reorganize REST API docs ToC (v1 vs legacy)

**Metrics/Observability:**
- [ ] M17: Create Grafana dashboard JSON templates in `docs/grafana/`
- [ ] M20: Write comprehensive Prometheus alert rules file

**Plugin Developer + DSL Author:**
- [ ] M13: Create `content/definitions/chargen.yaml`

**HTMX/UI Champion:**
- [x] ~~M11: Vendor HTMX library (remove CDN dependency)~~ — done; embedded in `static_js_bundle.cpp`

**Server Dev:**
- [ ] M2: Enforce session timeout in Subscribe RPC
- [ ] M9: Replace broad `catch (...)` with specific exception handling
- [ ] M10: Set config file permissions to 0600 after write

**Security Guardian:**
- [ ] H4: Implement certificate hot-reload via file watcher
- [ ] M3: Use configured canonical URL for OIDC redirect_uri

**Erlang Gateway Dev:**
- [ ] M22: Fix fragile `pg:start_link` in `yuzu_gw_app:start/2`

### Week 4: Stabilization & RC Tag

**All Teams:**
- [ ] Full regression pass: Linux (GCC 13, Clang 18), Windows (MSVC), macOS (Apple Clang), ARM64
- [ ] Integration test with 100+ agents (`scripts/integration-test.sh --agents 100 --tls`)
- [ ] Security Guardian: final review of all fixes from Weeks 1-3
- [ ] Quality Engineer: verify all new tests pass across CI matrix
- [ ] Darwin Specialist: run `bash scripts/run-tests.sh all` on macOS
- [ ] Windows Specialist: verify signed executables pass SmartScreen
- [ ] Docs Writer: final pass on all user manual sections
- [ ] Architect: review all PRs, verify no regressions
- [ ] Tag `v0.1.0-rc1`

---

## What's Strong (Evaluator Highlights)

These are the strengths that enterprise evaluators will notice positively:

- **45 plugins** spanning hardware, network, security, filesystem, Windows depth
- **Stable C ABI** with CRTP C++23 wrapper — plugin development is approachable
- **mTLS + 3-tier enrollment** — security-first architecture
- **Instruction Engine** with YAML DSL, scheduling, approvals, workflows
- **Policy Engine** with CEL, triggers, auto-remediation — desired-state compliance
- **ClickHouse analytics pipeline** with structured events, materialized views
- **Comprehensive audit trail** (21 event types, structured JSON, queryable REST API)
- **Zero critical security vulnerabilities** found (signal handler safety, PBKDF2, Ed25519 pack signing)
- **Script execution plugin** uses `execvp`/`CreateProcessA` (no shell) — best-practice remote execution
- **Content distribution** with HTTPS verification, SHA256 hash checks, filename validation, arg sanitization

The delta between current state and RC is **operational hardening and test confidence**,
not architecture or feature gaps.

---

## Test Coverage Summary

| Category | Files | Notes |
|----------|:-----:|-------|
| C++ server unit tests | 32 | Good store coverage; REST API untested |
| C++ agent unit tests | 14 | ABI checks; no plugin functional tests |
| Erlang EUnit tests | 11 | Registry, router, upstream, agent, heartbeat |
| Erlang Common Test suites | 5 | E2E, integration, metrics, Prometheus, perf |
| Integration test script | 1 | Full-stack but not wired into CI |
| Fuzz targets | 0 | CRITICAL GAP: YAML DSL, scope expressions |
| Sanitizer CI jobs | 0 | HIGH GAP: ASan/UBSan/TSan not in CI |

**Priority test additions for RC:**
1. `test_rest_api_v1.cpp` — all 31+ endpoints
2. Integration test in CI — `scripts/integration-test.sh`
3. ASan+UBSan CI job — at least Linux GCC
4. Scope expression fuzzer — libFuzzer target
5. YAML policy parser fuzzer — libFuzzer target

---

## Security Review Summary

| Category | Status | Key Metric |
|----------|--------|------------|
| Critical vulnerabilities | 0 | All 5 historical CRITICALs resolved |
| Authentication | Strong | mTLS, PBKDF2, OIDC, API tokens |
| Authorization | Strong | RBAC with 14 securable types, per-operation |
| Input validation | Strong | Parameterized SQL, no shell invocation, filename validation |
| Cryptography | Strong | OpenSSL/BCrypt, CSPRNG sessions, Ed25519 packs |
| Secrets management | Good | No hardcoded creds, key zeroing, env var support |
| Compiler hardening | Incomplete | PIE enabled; missing RELRO, FORTIFY, canaries |
| Default configuration | Needs work | `0.0.0.0` bind, HTTP default, unauthenticated `/metrics` |

---

## File Quick-Reference

Key files referenced in findings:

```
server/core/include/yuzu/server/server.hpp      # H1, H2 (defaults)
server/core/src/server.cpp                       # H3, H4 (metrics, TLS)
server/core/src/rest_api_v1.cpp                  # C5, H6, H7 (REST API)
server/core/src/analytics_event_store.cpp        # C6 (race condition)
server/core/src/auth.cpp                         # M9, M10 (exception, perms)
server/core/src/oidc_provider.cpp                # M3 (Host header)
agents/core/src/agent.cpp                        # H5 (key perms)
agents/core/src/plugin_loader.cpp                # M6 (allowlist)
agents/core/src/trigger_engine.cpp               # M14 (max triggers)
proto/gen_proto.py                               # C7 (protoc version)
gateway/config/sys.config                        # C1 (TLS)
gateway/rebar.config                             # H14 (grpcbox_plugin pin)
gateway/apps/yuzu_gw/src/yuzu_gw_app.erl         # M22 (pg scope)
gateway/apps/yuzu_gw/src/yuzu_gw_agent.erl       # H12 (duration metric)
gateway/apps/yuzu_gw/src/yuzu_gw_agent_service.erl # H13 (backpressure)
.github/workflows/release.yml                    # C4, H8-H11 (release)
meson.build                                      # M1, M15 (hardening, version)
content/definitions/                             # M13 (chargen.yaml)
docs/user-manual/server-admin.md                 # M18 (Windows service)
docs/user-manual/rest-api.md                     # M19 (ToC clarity)
docs/grafana/                                    # M17 (dashboards, missing)
```

---
---

## RC Sprint Governance Process

This section defines how the team operates during the 4-week RC sprint. It extends the
existing 5-gate model from CLAUDE.md (Gates 1-5) with two additional gates and concrete
operational procedures that close 12 identified process gaps.

**Effective:** Sprint start through `v0.1.0-rc1` tag.
**Scope:** All code changes merged to the `dev` branch during the sprint.

---

### Extended Gate Model (Gates 1-7)

Gates 1-5 are preserved from CLAUDE.md. Gates 6 and 7 are new.

| Gate | Name | Owner | Blocking? |
|------|------|-------|-----------|
| 1 | Change Summary | PR Author | Yes (PR cannot open without it) |
| 2 | Mandatory Deep-Dive | Security Guardian + Docs Writer | Yes (CRITICAL/HIGH block) |
| 3 | Domain-Triggered Review | Domain owners per trigger matrix | Yes (CRITICAL/HIGH block) |
| 4 | Findings Resolution | All reviewers | Yes (CRITICAL/HIGH must reach VERIFIED) |
| 5 | Iterate | All reviewers | Yes (no merge until clean) |
| **6** | **Merge Authority** | **Per merge authority table** | **Yes (wrong approver = blocked)** |
| **7** | **Audit Trail** | **PR Author + Architect** | **Yes (commit trailer required)** |

---

### Gate 1: Structured Change Summary Template

Every PR must begin with this template as the opening description. No PR may enter
review without a completed template. *(Closes Gap 1 and Gap 10.)*

```markdown
## Change Summary

**Finding:** [ID, e.g., C-003 or H-012]
**Severity:** CRITICAL / HIGH / MEDIUM / LOW
**Sprint Week:** 1 / 2 / 3 / 4
**Author:** [Role name]
**Date:** YYYY-MM-DD

### What Changed
- [File path]: [Description of change]

### Why
[1-2 sentences: root cause and why this fix is correct]

### Interfaces Affected
- [ ] Proto files modified
- [ ] Plugin ABI modified
- [ ] REST API endpoints added/changed/removed
- [ ] Config keys or CLI flags added/changed
- [ ] Build graph modified (meson.build)
- [ ] None

### Security Surface
- [ ] Auth/RBAC logic modified
- [ ] Crypto or key material handling modified
- [ ] Input parsing or validation modified
- [ ] SQL queries added or modified
- [ ] Expression evaluation modified
- [ ] Shell/process execution modified
- [ ] None

### User-Facing Impact
- [ ] Dashboard UI behavior changed
- [ ] REST API behavior changed
- [ ] Agent CLI behavior changed
- [ ] Config file format changed
- [ ] Documentation update required
- [ ] None (internal only)

### Test Plan
- [ ] New test(s) added: [test file names]
- [ ] Existing tests modified: [test file names]
- [ ] Manual verification: [steps]
- [ ] CI matrix sufficient (no manual platform test needed)
```

---

### Gate 2: Mandatory Deep-Dive (unchanged, verdict formalized)

Security Guardian and Docs Writer read every modified file for every PR. Each posts a
structured verdict comment. *(Closes Gap 2.)*

**Verdict format:**

```
**[ROLE] Review: [FINDING-ID]**
Verdict: PASS / PASS WITH NOTES / BLOCK
Findings:
- [Severity] [Description] -- Status: OPEN
Notes: [Advisory comments]
```

- **Security Guardian** verdicts: `SECURITY: PASS`, `SECURITY: PASS WITH NOTES`,
  or `SECURITY: BLOCK [finding-id]`
- **Docs Writer** verdicts: `DOCS: PASS`, `DOCS: UPDATE REQUIRED [section]`,
  or `DOCS: BLOCK [reason]`

---

### Gate 3: Domain Trigger Matrix

A domain owner must review when any checked condition is true. *(Closes Gap 3.)*

| Condition | Architect | Quality | Cross-Plat | Perf | Build-CI | DSL | Gateway | Plugin | Release |
|-----------|:---------:|:-------:|:----------:|:----:|:--------:|:---:|:-------:|:------:|:-------:|
| Spans >2 directories | X | | | | | | | | |
| .proto files changed | X | | | | | | X | | |
| plugin.h/hpp changed | X | | | | | | | X | |
| meson.build changed | | | X | | X | | | | |
| SQLite queries changed | | | | X | | | | | |
| Scope/CEL/DSL changed | | | | X | | X | | | |
| gateway/ changed | | | | | | | X | | |
| REST API changed | | X | | | | | | | |
| CI workflow changed | | | | | X | | | | |
| Deploy artifacts changed | | | | | | | | | X |
| Platform #ifdef code | | | X | | | | | | |
| New test files added | | X | | | | | | | |

Each domain reviewer posts: `DOMAIN: PASS`, `DOMAIN: CONCERN [description]`,
or `DOMAIN: BLOCK [finding-id]`.

---

### Gate 4: Finding Status Tracking

Every review finding is tracked through a state machine. *(Closes Gap 9.)*

```
OPEN --> ACKNOWLEDGED --> FIXED --> VERIFIED
                                       |
                              (CRITICAL/HIGH: must reach here)

OPEN --> DEFERRED   (MEDIUM/LOW only, requires Architect justification)
OPEN --> WONTFIX    (requires 2 reviewers to agree)
```

| Status | Meaning | Who Sets It |
|--------|---------|-------------|
| OPEN | Finding raised, not yet addressed | Reviewer |
| ACKNOWLEDGED | Author understands, working on fix | Author |
| FIXED | Author believes fix is complete | Author |
| VERIFIED | Reviewer confirms fix is correct | Original reviewer |
| DEFERRED | Accepted for post-RC (MEDIUM/LOW only) | Architect + justification |
| WONTFIX | Rejected with rationale | Architect + 2 reviewers agree |

**Rule:** CRITICAL and HIGH findings cannot be DEFERRED or WONTFIX. They must reach
VERIFIED before the PR can pass Gate 5.

---

### Gate 5: Iterate with SLAs

Review timelines are bounded to prevent stalls. *(Closes Gap 5.)*

| Action | SLA |
|--------|-----|
| Gate 2 deep-dive review posted | 4 hours from PR opening |
| Gate 3 domain review posted | 8 hours from PR opening |
| Author responds to findings | 4 hours from finding posted |
| Re-review after fix pushed | 4 hours from fix commit |

| PR Type | Total open-to-merge target |
|---------|---------------------------|
| CRITICAL finding | 24 hours maximum |
| HIGH finding | 48 hours maximum |
| MEDIUM/LOW finding | 72 hours maximum |

If an SLA is breached, escalation triggers automatically (see Escalation Process below).

---

### Gate 6: Merge Authority

Defines who can approve and who can merge, by PR type. *(Closes Gap 4.)*

| PR Type | Required Approvals | Who Can Merge |
|---------|-------------------|---------------|
| CRITICAL fix | Security Guardian + Architect | Architect only |
| HIGH fix | Security Guardian + 1 domain reviewer | Architect or domain owner |
| MEDIUM fix | 1 domain reviewer | Any reviewer who approved |
| LOW fix | 1 reviewer (any role) | Any reviewer who approved |
| Docs-only | Docs Writer | Docs Writer |
| CI/build-only | Build & CI/CD | Build & CI/CD |
| Gateway-only | Erlang Gateway Dev + 1 other | Erlang Gateway Dev |

**Universal merge prerequisites (all PR types):**
1. CI passes on all non-skipped matrix jobs
2. All CRITICAL/HIGH findings at VERIFIED
3. All MEDIUM findings at VERIFIED or DEFERRED
4. Change Summary template complete
5. Security Guardian verdict is PASS or PASS WITH NOTES
6. Docs Writer verdict is PASS (or N/A for non-user-facing)

---

### Gate 7: Audit Trail

Every merge creates a searchable governance record. *(Closes Gap 7.)*

**Commit trailer format** (appended to merge commit message):

```
Governance: C-003 (CRITICAL) gateway TLS mutual auth
Reviewed-By: security-guardian (PASS)
Reviewed-By: docs-writer (PASS)
Reviewed-By: gateway-erlang (PASS)
Reviewed-By: architect (PASS)
Findings: 0 CRITICAL, 0 HIGH, 1 MEDIUM (DEFERRED: M-017)
```

The Architect produces a **weekly governance summary** listing all PRs merged, their
verdicts, open findings, and deferred items.

---

### Escalation Process

Four levels of escalation for blocked or disputed work. *(Closes Gap 6.)*

**Level 1 -- Peer Resolution (0-4 hours):**
Reviewers discuss in PR comments with technical arguments. Either concedes or they
agree on a compromise.

**Level 2 -- Architect Arbitration (4-8 hours):**
Architect reads both positions, examines the code, posts binding decision:

```
**ARBITRATION: [Finding ID]**
Decision: ACCEPT / REJECT / MODIFY
Rationale: [Technical reasoning]
Action required: [Specific next steps]
```

**Level 3 -- Security Override (immediate):**
If Security Guardian and Architect disagree:
- CRITICAL/HIGH severity: **Security Guardian's position wins.** Rationale: Yuzu
  controls enterprise endpoints. A compromised server means fleet-wide arbitrary code
  execution. Security findings are not subject to velocity trade-offs.
- MEDIUM/LOW severity: Architect's decision is final.

**Level 4 -- Sprint Scope Adjustment:**
If a finding cannot be resolved within the sprint, the Architect may defer it with a
formal document containing: (a) risk assessment if unfixed in RC, (b) mitigation steps,
(c) timeline for post-RC fix. Both Security Guardian and Quality Engineer must
acknowledge the deferral.

**Blocked Work Protocol:**
1. Developer posts BLOCKED status in standup with finding ID and description.
2. Architect responds within 2 hours: unblock action, reassignment, or escalation.
3. If Architect does not respond within 2 hours, any reviewer may make interim decision.

---

### Fast-Track Process

For urgent issues discovered during the sprint that are outside the planned 52 findings.
*(Closes Gap 8.)*

**Security Hotfix Fast-Track** (CRITICAL/HIGH, exploitable):

| Step | Action | Timeline |
|------|--------|----------|
| 1 | Security Guardian opens finding tagged `HOTFIX` | Immediate |
| 2 | Developer opens PR | Within 2 hours |
| 3 | Gate 2: Security Guardian only (Docs Writer post-merge if no UI impact) | Within 2 hours |
| 4 | Gate 3: Affected domain owner(s) only | Within 2 hours |
| 5 | Merge: Security Guardian + Architect | Within 2 hours |
| | **Total discovery-to-merge** | **8 hours** |

Post-merge: Docs Writer and Quality Engineer review within 24 hours. Issues raised
become new tracked findings.

**Infrastructure Fix Fast-Track** (build breaks, CI failures):

| Step | Action | Timeline |
|------|--------|----------|
| 1 | Build & CI/CD opens PR tagged `INFRA-FIX` | Immediate |
| 2 | Gate 2 reviews waived (no security/user impact) | -- |
| 3 | One domain reviewer approves | Within 2 hours |
| 4 | Merge: Build & CI/CD + one other | Within 2 hours |
| | **Total** | **4 hours** |

---

### Sprint Ceremonies

#### Daily Standup (async-first, 15 min sync in Week 1)

Each role posts by 09:00 local time:

```
**[Role] Standup YYYY-MM-DD**
- Yesterday: [finding IDs worked on, PRs opened/merged]
- Today: [finding IDs planned]
- Blocked: [blockers with finding ID]
- Review queue: [N PRs awaiting my review]
```

Architect reviews all standups by 10:00 and flags coordination issues.
Week 1 (CRITICAL fixes): supplemental 15-min synchronous call daily.

#### Weekly Review (Friday, 45 min)

| Segment | Duration | Content |
|---------|----------|---------|
| Scorecard | 5 min | Findings closed/open by severity, CI health |
| Blocked triage | 10 min | Stuck items, escalation decisions |
| Cross-cutting | 10 min | Patterns from reviews, shared concerns |
| Next week preview | 10 min | Assignment adjustments, dependencies |
| Process retro | 10 min | What worked, what slowed us down |

#### Gate Checkpoints

| Checkpoint | Date | Exit Criteria |
|------------|------|---------------|
| **Week 1 exit** | Fri 2026-03-27 | All 7 CRITICAL findings merged and VERIFIED. CI green all platforms. |
| **Week 2 exit** | Fri 2026-04-03 | All 16 HIGH findings merged and VERIFIED. Security Guardian re-review of all Weeks 1-2 changes complete. |
| **Week 3 exit** | Fri 2026-04-10 | All 22 MEDIUM findings merged or DEFERRED (max 5). Docs updated for all user-facing changes. |
| **RC gate** | Wed 2026-04-15 | Full regression pass. LOW findings addressed or documented. RC acceptance criteria met. |
| **Tag** | Thu 2026-04-17 | Release signed, artifacts verified, CHANGELOG finalized. |

---

### Definition of Done (per severity)

#### CRITICAL Finding

- [ ] Root cause identified and documented in PR description
- [ ] Fix implemented with no regressions
- [ ] Regression test added (test that would have caught the original issue)
- [ ] Security Guardian deep-dive: PASS
- [ ] Architect review: PASS
- [ ] CI green on all PR-triggered jobs (Linux GCC, Windows MSVC, macOS)
- [ ] If gateway: Erlang EUnit + Common Test pass
- [ ] All findings at VERIFIED
- [ ] Merged to dev
- [ ] Fix confirmed in post-merge full-matrix CI (including sanitizers)

#### HIGH Finding

- [ ] Fix implemented and tested
- [ ] Test added (unit or integration, covers the specific scenario)
- [ ] Security Guardian deep-dive: PASS
- [ ] One domain reviewer: PASS
- [ ] CI green on PR-triggered jobs
- [ ] User manual updated if user-facing
- [ ] All CRITICAL/HIGH findings at VERIFIED
- [ ] Merged to dev

#### MEDIUM Finding

- [ ] Fix implemented
- [ ] Existing test coverage sufficient, or new test added
- [ ] One reviewer: PASS (Security Guardian if security-related, otherwise domain owner)
- [ ] CI green
- [ ] Documentation updated if applicable
- [ ] Merged to dev, OR DEFERRED with Architect justification

#### LOW Finding

- [ ] Fix implemented, or documented as known limitation in release notes
- [ ] No test regression
- [ ] One reviewer: PASS
- [ ] CI green
- [ ] Merged to dev, OR documented in RC release notes as known issue

---

### RC Acceptance Criteria

v0.1.0-rc1 will **not** be tagged until ALL mandatory gates are satisfied.

#### Mandatory Gates (all must pass)

| # | Gate | Verified By |
|---|------|-------------|
| 1 | All 7 CRITICAL findings: VERIFIED and merged | Quality Engineer |
| 2 | All 16 HIGH findings: VERIFIED and merged | Quality Engineer |
| 3 | All 22 MEDIUM findings: VERIFIED/merged or DEFERRED (max 5 deferred) | Architect |
| 4 | CI full matrix green on release commit (all 8 jobs) | Build & CI/CD |
| 5 | Sanitizer jobs pass (ASan+UBSan, TSan) | Quality Engineer |
| 6 | Integration test passes: `scripts/integration-test.sh` | Quality Engineer |
| 7 | Gateway tests pass: `rebar3 ct --dir apps/yuzu_gw/test` | Erlang Gateway Dev |
| 8 | Unit test count: no decrease from 628; net-new >= 30 tests | Quality Engineer |
| 9 | Binary signing verified: cosign keyless verification succeeds | Build & CI/CD |
| 10 | CHANGELOG.md updated with all 52 findings summarized | Docs Writer |
| 11 | User manual current: Docs Writer certifies `docs/user-manual/` | Docs Writer |
| 12 | SECURITY_REVIEW.md delta-checked against RC code | Security Guardian |

#### Advisory Gates (should pass, do not block RC)

| # | Gate | Verified By |
|---|------|-------------|
| 13 | Line coverage does not decrease from current baseline | Quality Engineer |
| 14 | No new SQLite queries in hot path without index verification | Performance |
| 15 | All 3 Dockerfiles (server, agent, gateway) build successfully | Build & CI/CD |

---

### RC Signing Ceremony

When all mandatory gates are satisfied:

1. Architect announces RC readiness, lists all 12 gate statuses.
2. Security Guardian performs final sign-off on `dev` branch HEAD.
3. Quality Engineer confirms test results and coverage.
4. Docs Writer confirms user manual currency.
5. Build & CI/CD prepares the tag.
6. Architect authorizes: `git tag v0.1.0-rc1 && git push origin v0.1.0-rc1`
7. Release workflow runs, producing signed artifacts on GitHub Releases.
8. Build & CI/CD verifies cosign signature on published SHA256SUMS.
9. Architect announces RC publication to the team.

---

### Parallel Work Tracks

To maximize throughput, the team operates in three parallel tracks:

| Track | Roles | Focus | Review Model |
|-------|-------|-------|-------------|
| **Security & Core** | Security Guardian, Server Dev, Architect | CRITICAL/HIGH: auth, crypto, thread safety, REST API | Full 7-gate governance |
| **Gateway & Scale** | Erlang Gateway Dev, Performance, Metrics | Gateway TLS, health, circuit breaker, metrics | Full 7-gate governance |
| **Platform & Polish** | Cross-Plat specialists, Docs Writer, Build & CI/CD, HTMX/UI, DSL Author | Compiler flags, docs, dashboards, packaging, YAML | Streamlined for non-security MEDIUM/LOW |

**Security Guardian bottleneck management:**
- Week 1 capacity: max 2 CRITICAL deep-dive reviews per day. No more than 2 CRITICAL
  PRs scheduled for final review on the same day.
- Weeks 2-3: if review queue exceeds 3 PRs, Architect may route non-security MEDIUM
  fixes to single-reviewer track (domain owner only, no Security Guardian deep-dive).
- Workload visible: each reviewer reports queue depth in daily standup.

---

### Finding ID Convention

Stable identifiers used in all governance artifacts:

| Range | Severity | Sprint Week |
|-------|----------|-------------|
| C-001 through C-007 | CRITICAL | Week 1 |
| H-001 through H-016 | HIGH | Week 2 |
| M-001 through M-022 | MEDIUM | Week 3 |
| L-001 through L-007 | LOW | Week 4 |

**Branch naming:** `fix/<finding-id>-<short-description>`
Examples: `fix/C-003-gateway-mtls`, `fix/H-012-cors-defaults`, `fix/M-017-compiler-hardening`

**PR labels:** `severity/critical`, `severity/high`, `severity/medium`, `severity/low`,
`track/security-core`, `track/gateway-scale`, `track/platform-polish`,
`sprint/week-1` through `sprint/week-4`

---

### Sprint Risk Register

| # | Risk | Likelihood | Impact | Mitigation |
|---|------|-----------|--------|------------|
| R1 | Gateway TLS changes break supervision tree | Medium | High | Security Guardian reviews TLS config. Quality Engineer verifies via CT suites. Architect reviews restart strategy. |
| R2 | Release workflow broken, blocks RC tagging | Medium | Critical | Test on pre-release tag (`v0.1.0-alpha.1`) in Week 1 before merging CRITICAL fixes. |
| R3 | REST API test backfill takes longer than 2 weeks | High | High | Prioritize security-critical endpoints (auth, RBAC, command dispatch). Server Dev writes integration tests in parallel. |
| R4 | Thread safety fix introduces new deadlock | Medium | High | Push to dev early to trigger TSan CI job. Add targeted concurrent test. Performance reviews lock ordering. |
| R5 | Proto codegen changes break cross-platform | Low | High | Build & CI/CD sole owner. No merge without full-matrix CI confirmation. |
| R6 | Week 3 MEDIUM fixes cause merge conflicts on shared files | High | Medium | Architect assigns to minimize overlap. Batch shared-file changes (meson.build, CLAUDE.md) into max 2 serialized PRs. |

---

### Governance for Governance

This process itself may need adjustment during the sprint. *(Closes Gap 12.)*

| Change Type | Approval Required | Procedure |
|-------------|-------------------|-----------|
| Reduces rigor (relaxes approvals, extends SLAs) | Security Guardian + Architect | Propose at weekly review, document rationale |
| Adds process (new review requirements) | Majority at weekly review | Discuss, vote, document |
| Emergency acceleration (sprint behind) | Architect + Security Guardian | Decide immediately, document, ratify at next weekly |

All governance changes are documented with: date, rationale, author, and what changed.

---

### Gap Closure Summary

| Gap | Description | Closed By |
|-----|-------------|-----------|
| 1 | No formal Change Summary template | Gate 1 template |
| 2 | No approval signaling mechanism | Gate 2 verdict format |
| 3 | No re-review trigger definition | Gate 3 domain trigger matrix |
| 4 | No merge permission model | Gate 6 merge authority table |
| 5 | No review timeline SLA | Gate 5 SLA table |
| 6 | No escalation process | 4-level escalation process |
| 7 | No governance audit trail | Gate 7 commit trailers + weekly summary |
| 8 | No hotfix fast-track | Fast-track process (security + infra) |
| 9 | No partial approval tracking | Gate 4 finding status state machine |
| 10 | No ready-for-review checklist | Gate 1 template checklists |
| 11 | No review workload tracking | Standup queue depth + bottleneck management |
| 12 | No governance for governance | Governance change procedure |

---

## Addendum: Items Adopted from External Review Team Checklist

*Cross-referenced from `docs/release-candidate-prep-checklist.md` (origin/dev). Five items below were identified as gaps in our sprint plan and are now incorporated.*

### A1. Upgrade Rehearsal on Real Data (Week 4)

**Source:** External checklist, "Pre-release validation" section.

Before tagging RC, perform a full upgrade rehearsal using cloned production-like data:
- Clone an existing SQLite database with realistic agent/enrollment/analytics data
- Run migration runner against the clone (`yuzu-server --migrate`)
- Verify all stores open cleanly, query results are correct post-migration
- Measure migration duration for sizing guidance in release notes

**Owner:** Server Dev + Quality Engineer
**Sprint:** Week 4 (Stabilization)
**Acceptance:** Migration completes without errors on cloned data; documented in release notes.

### A2. Rollback Test Under Pressure (Week 4)

**Source:** External checklist, "Rollback & recovery" section.

Validate that rollback works under realistic failure conditions:
- Mid-migration crash: kill server during migration, restart, verify DB integrity
- Mixed-version fleet: run N-1 agents against N server, confirm graceful degradation
- Partial deployment: simulate upgrade failure on subset of fleet, verify remaining agents continue operating
- Document rollback procedure in `docs/user-manual/operations.md`

**Owner:** Quality Engineer + Release & Deployment
**Sprint:** Week 4 (Stabilization)
**Acceptance:** All rollback scenarios pass; procedure documented.

### A3. Known-Issues Document — `KNOWN-ISSUES.md` (Week 4)

**Source:** External checklist, "Customer-facing documentation" section.

Create `KNOWN-ISSUES.md` at repo root listing:
- All findings with status DEFERRED from our 52-finding assessment
- The 47/139 capabilities not yet implemented (from capability map)
- Any platform-specific limitations (e.g., Windows-only features, Darwin quirks)
- Workarounds where available

This document ships with the RC so evaluators know what to expect.

**Owner:** Docs Writer + Architect
**Sprint:** Week 4 (Stabilization)
**Acceptance:** Document exists, covers all deferred items, reviewed by Security Guardian.

### A4. Release Commander Designation (Governance)

**Source:** External checklist, "Release process" section.

Formalize release roles to prevent confusion during the RC cut:

| Role | Assigned To | Responsibility |
|------|------------|----------------|
| Release Commander | Architect (Marcus Chen) | Final go/no-go, coordinates cut, owns release tag |
| Rollback Owner | Build & CI/CD (pipeline lead) | Executes rollback if post-release issues arise |
| Comms Lead | Docs Writer | Customer-facing release notes, changelog, known-issues |

The Release Commander has authority to delay the RC if any CRITICAL finding remains open.

### A5. Post-RC Hotfix Branch Policy (Governance)

**Source:** External checklist, "Post-release process" section.

After tagging `v0.1.0-rc1`:
1. Create `release/v0.1.0` branch from the RC tag
2. Development continues on `dev` — no freeze
3. Hotfixes: cherry-pick from `dev` to `release/v0.1.0`, never commit directly to release branch
4. Each hotfix cherry-pick triggers full CI matrix before merge
5. Re-tag as `v0.1.0-rc2`, `v0.1.0-rc3`, etc. for each hotfix batch
6. Final GA release tags `v0.1.0` on the release branch after evaluation period

**No direct commits to the release branch.** All fixes flow through `dev` first to prevent divergence.
