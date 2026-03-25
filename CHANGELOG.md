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
- 29 plugins: hardware, network, security, filesystem, registry, WMI, WiFi, WoL, and more
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

## [Unreleased]
### Added
- Wave 8: Release hardening (schema migrations, env var config, rate limiting, log rotation, health endpoints)
- MCP (Model Context Protocol) server embedded at `/mcp/v1/` with JSON-RPC 2.0 transport
- 22 read-only MCP tools: list_agents, get_agent_details, query_audit_log, list_definitions, get_definition, query_responses, aggregate_responses, query_inventory, list_inventory_tables, get_agent_inventory, get_tags, search_agents_by_tag, list_policies, get_compliance_summary, get_fleet_compliance, list_management_groups, get_execution_status, list_executions, list_schedules, validate_scope, preview_scope_targets, list_pending_approvals
- 5 MCP resources: yuzu://server/health, yuzu://agents/{id}, yuzu://definitions/{id}, yuzu://compliance/fleet, yuzu://audit/recent
- 4 MCP prompts: fleet_overview, investigate_agent, compliance_report, audit_investigation
- Three-tier MCP authorization model (readonly, operator, supervised) enforced before RBAC
- MCP token support via existing API token system with mandatory expiration (max 90 days)
- `--mcp-disable` kill switch and `--mcp-read-only` mode CLI flags (+ YUZU_MCP_DISABLE / YUZU_MCP_READ_ONLY env vars)
- Audit trail integration for all MCP tool calls with `mcp_tool` field on AuditEvent
- MCP unit tests covering JSON-RPC parsing, tier policy, token integration, and store interactions
