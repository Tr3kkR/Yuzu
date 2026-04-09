# Changelog

All notable changes to Yuzu are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-03-21

### Added

#### Server
- HTMX-based web dashboard with dark theme, role-based context bar, command palette
- REST API v1 with CORS support and OpenAPI documentation (133+ endpoints)
- Server-side response persistence with filtering, pagination, and aggregation (SQLite)
- Audit trail system with structured JSON events and configurable retention
- Device tagging system with hierarchical scope expression engine (AND/OR/NOT/LIKE/IN)
- Instruction engine: YAML-defined definitions, sets, scheduling, approval workflows
- Workflow primitives (if, foreach, retry) for multi-step instruction chains
- Policy engine with CEL-like compliance expressions and fleet compliance dashboard
- Granular RBAC with 6 roles, 14 securable types, per-operation permissions
- Management groups for hierarchical device grouping and access scoping
- OIDC SSO integration (tested with Microsoft Entra ID)
- Token-based API authentication (Bearer and X-Yuzu-Token)
- System notifications (in-app) and event subscriptions (webhooks with HMAC-SHA256)
- Product packs with Ed25519 signature verification for bundled YAML distribution
- Active Directory / Entra ID integration via Microsoft Graph API
- Agent deployment jobs and patch deployment workflow orchestration
- Device discovery (subnet scanning with ARP + ping sweep)
- Custom properties on devices with schema validation
- Runtime configuration API with safe key whitelist
- Inventory table enumeration and item lookup
- NVD CVE feed sync with vulnerability matching
- ClickHouse and JSONL analytics event drains
- Prometheus /metrics endpoint with fleet health gauges and request histograms
- CSV and JSON data export
- HTTPS for web dashboard with HTTP→HTTPS redirect
- Error code taxonomy (1xxx-4xxx)
- Concurrency enforcement (5 modes)

#### Agent
- Plugin architecture with stable C ABI (version 2, min 1) and C++ CRTP wrapper
- 44 plugins: hardware, network, security, filesystem, registry, WMI, WiFi, WoL, and more
- Trigger engine: interval, file_change, service_status, event_log, registry_change, startup
- Agent-side key-value storage (SQLite-backed, per-plugin namespaces)
- HTTP client plugin (cpp-httplib, no shell) with SSRF protection
- Content staging and execution (CreateProcessW/fork+execvp, no system())
- Desktop user interaction: notifications, questions, surveys, DND mode (Windows)
- Timeline Activity Record (TAR): persistent process tree, network, service, user session tracking
- OTA auto-update with hash verification and rollback
- Bounded thread pool (4-32 workers, 1000 max queue) with output buffering
- Windows certificate store integration (CryptoAPI/CNG)
- Tiered agent enrollment (manual approval, pre-shared tokens, platform trust stubs)

#### Gateway
- Erlang/OTP gateway node with process-per-agent supervision
- Heartbeat buffer (dedicated gen_server, batched upstream flush)
- Consistent hash ring for multi-gateway deployments
- Prometheus metrics endpoint

#### Infrastructure
- Meson + vcpkg build system with cross-platform support (Windows/Linux/macOS/ARM64)
- CI matrix: GCC 13, Clang 18, MSVC, Apple Clang, ARM64 cross-compile
- AddressSanitizer, ThreadSanitizer, and code coverage CI jobs
- Docker deployment (3 multi-stage Dockerfiles, docker-compose.yml)
- Systemd service units with security hardening
- GitHub Actions release workflow (3 platforms, SHA256 checksums)
- 628+ unit test cases across 44 test files

### Security
- 51 security findings identified and fixed (5 CRITICAL, 15 HIGH, 15 MEDIUM, 16 LOW)
- Eliminated 4 CRITICAL command injection vulnerabilities (replaced system()/popen() with safe alternatives)
- mTLS for agent-server gRPC with certificate chain validation
- PBKDF2 password hashing for local authentication
- Command-line redaction in TAR (configurable patterns)
- SSRF protection with private IP range blocking
- Input validation on all REST API endpoints
- Registry sensitive path audit logging
- PRAGMA secure_delete on TAR database

## [0.8.0] - 2026-04-09

### Added

#### Security
- **HTTP security response headers (SOC2-C1, #310)** — every HTTP response (dashboard, REST API, MCP, metrics, health probes) now carries six headers: `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy` (deny-all baseline for camera/mic/geo/usb/etc.), and `Strict-Transport-Security: max-age=31536000; includeSubDomains` on HTTPS deployments. The CSP also appends `upgrade-insecure-requests` on HTTPS.
- New `--csp-extra-sources` CLI flag (env: `YUZU_CSP_EXTRA_SOURCES`) for whitelisting customer CDNs, monitoring beacons, or analytics endpoints. Validated at startup with strict allow-list — rejects control bytes, semicolons, commas, `'unsafe-eval'`, `'strict-dynamic'`, and other unsafe CSP keywords.
- New `server/core/src/security_headers.{hpp,cpp}` module (`yuzu::server::security` namespace) with `HeaderBundle::make()`/`apply()` shared between the production server and the unit/integration tests, ensuring header logic cannot drift between code and tests.
- New `tests/unit/server/test_security_headers.cpp` (38 cases / 146 assertions) and `tests/unit/server/test_static_js_bundle.cpp` (11 cases / 30 assertions) covering CSP construction, validation grammar, end-to-end emission via real `httplib::Server`, and embedded HTMX bundle integrity.
- Resolved security header bundle is logged at INFO at startup so operators can confirm activation: `Security headers active: CSP=N bytes, HSTS=on/off, ...`.

#### Server
- **HTMX 2.0.4 runtime and htmx-ext-sse 2.2.2 extension embedded in the server binary** (`server/core/src/static_js_bundle.cpp`) and served from same-origin `GET /static/htmx.js` and `GET /static/sse.js`. The dashboard works in **air-gapped deployments out of the box** with no internet connectivity required. The HTMX bundle is split into 4 chunks of ≤14000 bytes (MSVC raw string literal limit C2026) and concatenated at static-init into a single `extern const std::string`. Reassembled output is byte-identical to the upstream minified file (50918 bytes). Both upstream packages are 0BSD which imposes no redistribution conditions.

### Changed

#### Security
- **CSP `script-src` is now fully `'self'`-only** with no external CDN allowance — `https://unpkg.com` whitelist removed because HTMX is now served same-origin. Improves SOC 2 supply-chain posture and removes a third-party origin from the dashboard's attack surface.
- All six dashboard-bearing UI templates (`dashboard_ui.cpp`, `settings_ui.cpp`, `compliance_ui.cpp`, `instruction_ui.cpp`, `statistics_ui.cpp`, `topology_ui.cpp`) migrated from `<script src="https://unpkg.com/htmx.org@2.0.4">` to `<script src="/static/htmx.js">`. Same for the SSE extension.

#### UAT Scripts
- `scripts/win-start-UAT.sh` and `scripts/linux-start-UAT.sh`: added `--listen 0.0.0.0:50054` to the server invocation when running with the gateway on the same host. In single-host UAT both server and gateway default to `:50051` for agent gRPC; without the override the server wins the bind and the agent connects directly, bypassing the gateway. Confirmed via `gw-session-` prefix on the agent session ID. Multi-host production deployments are unaffected.

### Fixed

- Closed M11 in `Release-Candidate.local.MD` risk register: HTMX no longer loaded from external `unpkg.com` CDN.

### Documentation

- `docs/user-manual/security-hardening.md` rewritten with: a six-row CSP/HSTS/X-Frame-Options/X-Content-Type-Options/Referrer-Policy/Permissions-Policy table, the `'unsafe-inline'` rationale, embedded HTMX runtime explanation (replacing the old "unpkg.com allowance" section), `--csp-extra-sources` validation behavior with rejection examples, "Behind a reverse proxy" CSP-intersection note, bandwidth note (~700-900 bytes/response overhead), and a corrected `curl | grep -E` verification example.
- `CLAUDE.md` Authentication & Authorization section updated to document the SOC2-C1 implementation, the local HTMX embedding, and the validated `--csp-extra-sources` flag.
- `docs/test-coverage.md` registers the new `test_security_headers.cpp` and `test_static_js_bundle.cpp` suites.
- `docs/user-manual/rest-api.md` cross-links to the new HTTP Security Response Headers section.
- `docs/user-manual/server-admin.md` documents the new `--csp-extra-sources` flag with rejection grammar.

## [0.7.1] - 2026-04-08

### Added

#### Server
- ClickHouse analytics event drain with CLI configuration parameters
- TAR data warehouse: typed SQLite tables, SQL query engine, rollup aggregation
- Instruction execute API endpoint for programmatic command dispatch
- Rich Grafana dashboard templates for fleet analytics and observability
- Ctrl+K command palette enabled on all dashboard pages
- Default evaluation credentials (`admin/administrator`, `user/useroperator`) documented with change-immediately warning

#### Infrastructure
- Enterprise readiness plan for SOC 2 compliance and first customer preparation
- Enterprise installers: DEB and RPM packages with systemd integration
- Pre-release QA pipeline with release workflow artifact validation
- Docker UAT environment with dep-cached builds and automated tests
- Windows UAT environment with Prometheus + Grafana observability stack
- Puppeteer synthetic UAT tests for end-to-end browser validation
- Pre-populated CI Docker images for faster build times
- Self-hosted runner infrastructure (Linux, Windows)
- NuGet binary cache as fallback for vcpkg package caching
- 3 new governance agents: compliance-officer, SRE, enterprise-readiness
- `scripts/docker-release.sh` — local Docker build + push script with `--dry-run` and `--build-only` flags

### Changed

#### Networking — Port Standardization
- **Port 50051 is now the universal agent door** — server listens on 50051 in standalone mode, gateway listens on 50051 in scaled deployments. Agents always connect to `<host>:50051` regardless of topology.
- Gateway agent-facing port changed from 50061 → 50051 (all configs, compose files, scripts, docs)
- Stale port 50054 references corrected to 50051 across 25 files
- Standalone Docker Compose (`docker-compose.yml`) simplified — server + agent only, no gateway required
- Gateway Docker Compose (`docker-compose.full-uat.yml`) updated for gateway-mode server deployment

#### Docker
- Server Dockerfile defaults to zero-arg startup: `--listen 0.0.0.0:50051 --no-tls --no-https --web-address 0.0.0.0 --web-port 8080 --config /var/lib/yuzu/yuzu-server.cfg`
- Gateway Dockerfile upgraded from Erlang/OTP 27 to 28 (pinned digest)
- Gateway Dockerfile exposes health port 8081
- Agent Docker image removed from release pipeline (use native installers instead)
- Multi-arch Docker builds removed (linux/amd64 only; macOS agent uses native installer)

#### Build & CI
- Release workflow gateway build upgraded from OTP 27 to OTP 28

### Fixed

#### Security — CRITICAL
- **SIGBUS crash in SQLite stores under concurrent HTTP load (#329)** — all 30 stores migrated from `sqlite3_open()` to `sqlite3_open_v2()` with `SQLITE_OPEN_FULLMUTEX`, enabling SQLite's serialized threading mode per-connection. Runtime `sqlite3_threadsafe()` guard added at server and agent startup. WAL mode and `busy_timeout` pragma consistency enforced across all stores.

#### Security — MEDIUM
- XSS, error information leakage, and missing SQLite pragmas (governance findings)
- MCP thread-safety race conditions identified and fixed via ThreadSanitizer
- CEL list index undefined behavior on out-of-bounds access

#### Server
- Gateway command forwarding: IPv6 port conflict resolution and retry logic
- ClickHouse analytics drain connection and ingest reliability
- Enter key form submission fixed on all dashboard pages
- Patch manager test crash on Windows

#### Build & CI
- macOS CI upgraded to macos-15 (Xcode 16) with `clock_cast` and CTAD compatibility fixes
- Clang upgraded 18 → 19 with CoreFoundation linkage and `from_chars` portability fixes
- ARM64 cross-compile: pkg-config path resolution for vcpkg
- Windows: migrated to `x64-windows-static-md` vcpkg triplet, static gRPC/abseil linkage fixes (LNK2005/LNK2019)
- Windows system libraries migrated to `#pragma comment(lib)` for build reliability
- LTO disabled for problematic configurations (Linux x64 self-hosted, Clang 19 release)
- Apple Clang: deduction guide for `ScopeExit`, `execvpe` platform guard, `environ` linkage
- CI concurrency: per-SHA group to prevent self-cancellation
- InnoSetup plugin paths corrected for Windows installer builds
- Linux ARM64 cross-compile removed from CI (no ARM64 runner available)

## [0.7.0] - 2026-03-30

### Added

#### Gateway
- Gateway defaults moved to own port range (5006x) — server, gateway, and agent can now run on the same box without port overrides
  - Agent-facing gRPC: 50051 → 50061
  - Management gRPC: 50052/50053 → 50063
  - Health HTTP: 8080 → 8081 (consistent across dev and prod configs)
- UAT enrollment token automatically saved to `/tmp/yuzu-uat/enrollment-token` for CT suite consumption

#### Server
- Semantic YAML syntax highlighting in the Instructions editor preview pane
  - `type: question` renders green, `type: action` orange, `approval: required` red, `concurrency: single/serial` yellow
  - Color legend now matches actual preview output
- YAML editor value color changed from near-blue (#a5d6ff) to gray-white (#c9d1d9) for clearer key/value contrast

#### Infrastructure
- Linux UAT script (`scripts/linux-start-UAT.sh`) with full server-gateway-agent stack, 6 automated connectivity and command round-trip tests
- `real_upstream_SUITE` CT suite auto-reads enrollment token from UAT environment (no manual token setup needed)

### Fixed
- YAML editor preview now triggers on paste events (changed HTMX trigger from `keyup` to `input` for cross-browser compatibility with Safari/context-menu paste)
- Stale database directories no longer break session authentication on server restart (UAT script wipes state on each run)
- Help command display and result table clearing on HTMX dashboard
- Enrollment token `max_uses` increased from 10 to 1000 to support CT suite test runs

## [0.6.0] - 2026-03-28

### Changed (Architecture — God Object Decomposition)

- **server.cpp decomposed from 11,437 to 4,411 LOC** — ServerImpl is now a slim composition root
- 24 new files extracted (9,008 LOC total), each independently compilable and testable
- Route modules use callback-injection pattern: `register_routes(httplib::Server&, AuthFn, PermFn, AuditFn, ...stores...)`
- Extracted route modules: `auth_routes`, `settings_routes`, `compliance_routes`, `workflow_routes`, `notification_routes`, `webhook_routes`, `discovery_routes`
- Extracted inner classes: `agent_registry`, `agent_service_impl`, `gateway_service_impl`, `event_bus`
- `InstructionDbPool` RAII wrapper replaces raw `sqlite3*` pointer for shared instruction DB (fixes G3-ARCH-T2-002)
- `route_types.hpp` provides shared `AuthFn`/`PermFn`/`AuditFn` callback type aliases
- `AgentServiceImpl` mutable members moved from public to private
- Governance findings G3-ARCH-001, G3-ARCH-T2-001, G3-ARCH-T2-002 marked FIXED in code review register

### Fixed
- Scoped API tokens with null `TagStore` now return 503 instead of silently granting access
- `InstructionDbPool` member declaration order corrected — destroyed after all consumers

### Added
- Wave 8: Release hardening (schema migrations, env var config, rate limiting, log rotation, health endpoints)
- MCP (Model Context Protocol) server embedded at `/mcp/v1/` with JSON-RPC 2.0 transport
- 22 read-only MCP tools: list_agents, get_agent_details, query_audit_log, list_definitions, get_definition, query_responses, aggregate_responses, query_inventory, list_inventory_tables, get_agent_inventory, get_tags, search_agents_by_tag, list_policies, get_compliance_summary, get_fleet_compliance, list_management_groups, get_execution_status, list_executions, list_schedules, validate_scope, preview_scope_targets, list_pending_approvals
- 3 MCP resources: yuzu://server/health, yuzu://compliance/fleet, yuzu://audit/recent
- 4 MCP prompts: fleet_overview, investigate_agent, compliance_report, audit_investigation
- Three-tier MCP authorization model (readonly, operator, supervised) enforced before RBAC
- MCP token support via existing API token system with mandatory expiration (max 90 days)
- `--mcp-disable` kill switch and `--mcp-read-only` mode CLI flags (+ YUZU_MCP_DISABLE / YUZU_MCP_READ_ONLY env vars)
- Audit trail integration for all MCP tool calls with `mcp_tool` field on AuditEvent
- MCP unit tests covering JSON-RPC parsing, tier policy, token integration, and store interactions

### Changed (Capability Audit — 2026-03-26)

- Capability map audited against codebase: 32 capabilities marked "not started" or "partial" were already implemented
- Corrected total from 96/142 (68%) to **150/184 (82%)**
- Updated per-domain summary counts and progress bars
- Plugin coverage matrix expanded from 29 to 44 entries with all plugin categories

#### Capabilities confirmed implemented (previously marked not started)
- **Network:** WiFi scanning (4.6), Wake-on-LAN (4.7), ARP subnet discovery (4.10)
- **User/Session:** Primary user determination (6.2), local group membership (6.3), connection history (6.4), active sessions (6.5)
- **Patch Management:** Deployment orchestration (8.3), per-device status tracking (8.4), metadata retrieval (8.5), fleet compliance summary (8.7)
- **Security:** Device quarantine with whitelist (9.6), IOC checking (9.7), certificate inventory (9.8), quarantine status tracking (9.9)
- **File System:** ACL/permissions inspection (10.7), Authenticode verification (10.8), find-by-hash (10.14)
- **Inventory:** Table enumeration (15.3)
- **Auth:** Management-group-scoped roles (18.4), AD/Entra integration via Graph API (18.6)
- **Device Mgmt:** Hierarchical management groups (19.4), device discovery (19.5), custom properties (19.6), deployment jobs (19.7)
- **Notifications:** System notifications (21.3), webhook event subscriptions (21.4)
- **Infrastructure:** Product packs with Ed25519 signing (22.8)

#### Capabilities upgraded from partial to done
- **Platform Configuration (22.4):** RuntimeConfigStore with safe-key whitelist, no-restart updates
- **Gateway / Scale-Out (22.5):** Full Erlang/OTP gateway with circuit breaker, heartbeat batching, health endpoints
- **REST API (24.3):** Versioned `/api/v1/` prefix, 70+ endpoints, OpenAPI spec, CORS allowlist
- **Data Export (24.5):** CSV and JSON export endpoints with Content-Disposition headers

#### Capabilities upgraded from not started to partial
- **Reboot Management (8.6):** `reboot_if_needed` flag on patch deployments (no scheduled reboot workflow yet)
- **System Health Monitoring (22.1):** /livez, /readyz probes + Prometheus metrics (no CPU/memory/queue monitoring yet)

### Added (Governance — 2026-03-28)
- 4 governance review agents: happy-path, unhappy-path, consistency-auditor, chaos-injector
- 7-gate governance process (expanded from 5 gates) with mandatory correctness & resilience analysis
- REST API v1 documentation for 25 previously undocumented endpoints (inventory, execution statistics, device tokens, software deployment, license management, topology, fleet statistics, file retrieval, OpenAPI spec)
- Agent reconnect loop with exponential backoff (1s to 5min) on registration or stream failure
- Semver downgrade protection in OTA updater — rejects older/equal versions
- Per-plugin KV namespace isolation — `PluginContextImpl` with correct `plugin_name` per plugin

### Fixed (Full Governance Review — ~380 findings across 492 files)

#### Security — CRITICAL (5 fixed)
- OIDC JWT signature verification via JWKS — forged ID tokens were previously accepted
- 4 SQLite stores had mutexes declared but never locked (tag, discovery, instruction, deployment)

#### Security — HIGH (18 fixed)
- Replaced `std::regex` with RE2 in CEL `.matches()` and scope `MATCHES` operator (ReDoS)
- CEL evaluation wall-clock timeout (prevents infinite loops in policy evaluation)
- 11 SQLite stores gained shared_mutex protection for thread-safe concurrent access
- RBAC permission cache to reduce per-request SQL query amplification
- API token IDs extended from 12-char to 24-char hex (96-bit collision resistance)
- MCP kill switch now evaluated at runtime, not just startup
- ApprovalManager TOCTOU fixed with mutex + atomic WHERE on concurrent approve/reject
- MCP read_only_mode captured by reference for runtime toggle support
- Prometheus histogram `observe()` fixed — was double-counting across all bucket boundaries
- Agent double plugin shutdown prevented on normal exit
- Stagger/delay capped at 5min each to prevent thread pool worker exhaustion

#### Security — MEDIUM (25 fixed)
- Minimum password length enforced (12 characters)
- Expired sessions opportunistically reaped
- Token generation switched from mt19937_64 to CSPRNG (RAND_bytes)
- Security response headers added (X-Frame-Options, HSTS, X-Content-Type-Options)
- CSRF protection via Origin header validation
- RBAC `set_permission` validates effect as "allow" or "deny"
- OIDC pending challenges capped at 1000 entries with expiry cleanup
- MCP `/health` resource now requires RBAC check
- Dead CORS helper removed (was reflecting arbitrary Origin)
- Execution statistics limit clamped to 1000
- CEL recursion depth reduced from 64 to 16; string concatenation capped at 64 KiB
- Unknown characters in CEL lexer return Error token instead of silent skip
- Scope engine NOT recursion protected with DepthGuard
- Response/audit store cleanup threads wrapped in proper mutex locks
- Fleet compliance cache writes corrected from shared_lock to unique_lock
- Non-thread-safe static RNGs made thread_local
- Deleted user sessions now invalidated; session role updated on role change
- Offline agents get 24hr staleness TTL on compliance status
- MCP automation gets separate rate limit bucket from dashboard
- Approval workflow: 7-day TTL and 1000 pending cap
- CEL unresolved variables produce tri-state (true/false/error) instead of silent false

#### Agent & Plugins (10 fixed)
- `SecureZeroMemory` on CNG + CAPI intermediate key blobs after cert store export
- Symlink rejection before plugin dlopen
- OTA updater download size capped at 512 MiB
- Content distribution staging directory set to owner-only permissions
- Hash re-verification before executing staged content
- HTTP client SSRF protection extended to CGNAT (100.64/10) and benchmarking (198.18/15) ranges
- HTTP client response body capped at 100 MiB
- `script_exec` output capped at 16 MiB; `setsid()` + `kill(-pid, SIGKILL)` for process group cleanup
- `script_exec` child environment sanitized (PATH, HOME, USER, LANG, LC_ALL, TERM, TZ only)
- Certificate plugin command injection fixed: hex-only thumbprint validation, safe path checks, temp file for PEM parsing

#### Gateway
- 5 dialyzer warnings resolved (ctx dependency, contract violations, dead code)
- gpb bumped 4.21.2 → 4.21.7 for OTP 28 compatibility
- Gateway proto synced from canonical (added stagger_seconds, delay_seconds)

#### Documentation
- REST API v1 now 100% documented (was 48% undocumented)
- Full governance review document with cross-tier finding register
- Erlang gateway build pitfalls documented in CLAUDE.md

### Fixed (RC Sprint — 52 findings resolved)

#### Security (CRITICAL + HIGH)
- Gateway now uses TLS for upstream gRPC connections (was plaintext)
- Gateway health/readiness endpoints (`/healthz`, gRPC Health Check)
- Gateway circuit breaker with exponential backoff for upstream failures
- AnalyticsEventStore thread safety — mutex protection on query methods
- Proto codegen reproducibility — protoc version validation
- Web UI binds to `127.0.0.1` by default (was `0.0.0.0`)
- HTTPS enabled by default — operators must provide cert/key or use `--no-https`
- `/metrics` requires authentication for remote access (localhost exempt, `--metrics-no-auth` override)
- Private key file permission validation on Unix (refuses group/others-readable)
- Certificate hot-reload with PEM validation, cert/key match, and permission checks
- CORS headers on all `/api/` endpoints via `set_post_routing_handler`

#### Server
- REST API unit test suite (previously 0 tests for 1,355 LOC, 31+ endpoints)
- JSON error envelope on all error responses: `{"error":{"code":N,"message":"..."},"meta":{"api_version":"v1"}}`
- Health probe contract: `/livez` and `/readyz` return `{"status":"..."}`

#### Gateway
- Command duration metrics (was hard-coded to 0)
- Backpressure alerting for agent send buffer
- grpcbox dependency pinned
- Graceful shutdown with in-flight command draining
- .appup files for hot code upgrades

#### Build & Packaging
- Binary signing for Windows (Authenticode) and macOS (codesign + notarization)
- Sanitizer CI jobs (ASan+UBSan, TSan)
- Release workflow artifact validation with SHA256 checksums
- deb/rpm package integration
- Docker health checks in all 3 Dockerfiles
- Docker base images pinned to sha256 digests
- buf lint + breaking change CI job for proto compatibility

#### Agent & Plugins
- Agent UUID generation uses CSPRNG (RAND_bytes/BCryptGenRandom, was Mersenne Twister)
- Plugin ABI runtime version check — sdk_version field, ABI v3
- OIDC client secret moved to Authorization: Basic header (RFC 6749 §2.3.1)

#### Build Hardening
- Compiler hardening flags: `_FORTIFY_SOURCE=2`, `-fstack-protector-strong`, full RELRO, PIE
- MSVC `/DYNAMICBASE /HIGHENTROPYVA /NXCOMPAT` for ASLR + DEP

#### Documentation
- macOS x64 limitation documented in README and user manual
- cliff.toml added for git-cliff changelog automation
