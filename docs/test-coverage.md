# Test Coverage Tracking

Last updated: 2026-03-26

## Overview

| Suite | Executable | Test Files | Status |
|-------|-----------|------------|--------|
| Agent unit tests | `yuzu_agent_tests` | 14 files | Active |
| Server unit tests | `yuzu_server_tests` | 34 files | Active (requires `build_server=true`) |

**Totals:** 48 test files. Test case count has grown significantly since the RC sprint added REST API tests, MCP tests, and store tests.

Run all tests: `meson test -C builddir --print-errorlogs`

---

## Agent Tests

### Tested

| File | Component | What's Covered |
|------|-----------|----------------|
| `test_sdk_utilities.cpp` | SDK utilities | split_lines, table_to_json, json_to_table, generate_sequence, C ABI wrappers |
| `test_plugin_loader.cpp` | Plugin loader | Nonexistent/empty directory handling |
| `test_updater.cpp` | OTA updater | current_executable_path, cleanup_old_binary, rollback_if_needed |
| `test_temp_file.cpp` | Temp file API | create_temp_file, create_temp_dir, RAII wrappers, move semantics |
| `test_filesystem_read.cpp` | Filesystem plugin | validate_path, read parameters, CRLF stripping, binary detection, pagination |
| `test_string_utils.cpp` | Shared utilities | icontains, sanitize_utf8, escape_pipes, sanitize_input, format_uptime, split_args, chargen_line |
| `test_vuln_rules.cpp` | Vuln scan rules | compare_versions, CveRule data integrity, CVE matching logic |
| `test_kv_store.cpp` | KV storage | Set/get/delete, namespace isolation, list with prefix, clear, persistence across reopens (30 cases) |
| `test_trigger_engine.cpp` | Trigger engine | Interval triggers, file-change triggers, service-status triggers, event-log triggers, registry triggers, startup triggers, trigger registration/deregistration, concurrent trigger evaluation (28 cases) |
| `test_new_plugins.cpp` | Plugin runtime | Plugin load/init lifecycle, action dispatch, output callback, multi-plugin coexistence, error handling, config access (~40 cases) |
| `test_metrics.cpp` | Prometheus metrics | Metric registration, counter/gauge/histogram operations, label handling |
| `test_metrics_perf.cpp` | Metrics performance | High-throughput metric emission, contention under concurrent writers |
| `test_tar_diff.cpp` | TAR diff engine | Process tree diff, network change detection, service state transitions |
| `test_tar_store.cpp` | TAR store | Timeline event persistence, query by time range, agent scoping |

### Untested Agent Components

| Component | Why Untested | Priority |
|-----------|-------------|----------|
| **Plugin host** (dynamic loading) | Requires .dll/.so artifacts | Low |
| **Trigger engine** | Covered by test_trigger_engine.cpp | Done |
| **gRPC client** | Requires mock server | Medium |
| **Certificate discovery** | Windows-specific CryptoAPI | Low |
| **Cloud identity** | Requires cloud environment | Low |
| **Identity store** | File I/O, low logic density | Low |

### Untested Plugin Runtime Logic

All plugins are loaded as dynamic libraries; their OS-dependent runtime code (subprocess calls, registry queries, WMI, /proc parsing) cannot be unit tested without mocking. The **pure functions** extracted to `string_utils.hpp` (icontains, sanitize_utf8, escape_pipes, etc.) cover the shared logic used by these plugins:

| Plugin | Key Pure Logic Tested Via | OS-Dependent (Not Tested) |
|--------|--------------------------|---------------------------|
| chargen | `chargen_line()` in string_utils | Thread/sleep loop |
| script_exec | `split_args()` in string_utils | CreateProcess/fork/execvp |
| installed_apps | `icontains()`, `sanitize_utf8()` | Registry enum, dpkg, rpm |
| vuln_scan | `compare_versions()`, `icontains()`, `escape_pipes()` | Registry, package queries |
| event_logs | `sanitize_input()` | PowerShell, journalctl, log |
| os_info | `format_uptime()` | uname, sysctl, registry |
| netstat | TCP state enums, IP parsing | GetExtendedTcpTable, /proc/net |
| firewall | Netsh output parsing | netsh, firewall-cmd, ufw |
| services | Service state/startup enums | SCManager, systemctl, launchctl |
| diagnostics | Uptime calculation | Plugin context reads |
| network_config | MAC formatting, IP parsing | GetAdaptersAddresses, ip/ifconfig |
| hardware | Size conversion, CPUID parsing | WMI, dmidecode, sysctl |
| processes | Case-insensitive name matching | CreateToolhelp32Snapshot, /proc |
| users | Wide string conversion, FILETIME formatting | Net API, utmp, dscl |
| procfetch | Pipe escaping | File hashing, process enum |
| tags | Key/value validation | File I/O |
| antivirus | (none) | Get-CimInstance, pgrep |
| bitlocker | (none) | PowerShell |
| status | RSS parsing | Hostname, architecture |
| agent_actions | Log level validation | spdlog state changes |

---

## Server Tests

### Tested

| File | Component | What's Covered |
|------|-----------|----------------|
| `test_auth.cpp` | Auth manager | Crypto primitives, user CRUD, sessions, enrollment tokens, pending agents, config persistence |
| `test_auto_approve.cpp` | Auto-approve | Hostname glob, CIDR subnet, CA fingerprints, rule evaluation (any/all mode), config persistence |
| `test_nvd.cpp` | NVD database | Version comparison, CVE CRUD, batch inserts, match_inventory, metadata, builtin rules |
| `test_update_registry.cpp` | OTA registry | Package CRUD, latest_for version selection, rollout eligibility, binary_path |
| `test_https_config.cpp` | HTTPS config | Default values, cookie security attributes (Secure, HttpOnly, SameSite), retention config |
| `test_response_store.cpp` | Response store | Store/retrieve, query filters (agent_id, status, time range), pagination, TTL, ordering |
| `test_audit_store.cpp` | Audit store | Log/query, filter by principal/action/target, pagination, timestamp ordering |
| `test_tag_store.cpp` | Tag store | CRUD, sync_agent_tags, agents_with_tag, key/value validation |
| `test_scope_engine.cpp` | Scope engine | Parser (equality, AND, OR, NOT, LIKE, IN, CONTAINS, parens, errors), evaluator, performance |
| `test_web_utils.cpp` | Web utilities | base64_decode, html_escape, url_decode, extract_form_value, extract_plugin |
| `test_policy_store.cpp` | Policy store | Policy CRUD, fragment binding, scope expression storage, enable/disable, management group association, trigger configuration, input parameters, cascade delete (42 cases) |
| `test_compliance_eval.cpp` | Compliance evaluator | Status transitions (compliant/non_compliant/unknown/fixing/error), per-agent tracking, fleet summary aggregation, cache invalidation, policy-scoped queries, auto-remediation triggers (35 cases) |
| `test_custom_properties_store.cpp` | Custom properties | Property CRUD, schema validation, allowed-value enforcement, type checking, required-property compliance, scope engine integration via `props.` prefix, bulk operations (34 cases) |
| `test_mcp_server.cpp` | MCP server | JSON-RPC parsing, tier policy enforcement, token integration, tool dispatch, store interactions |
| `test_api_token_store.cpp` | API token store | Token CRUD, expiration, MCP tier assignment |
| `test_agent_health_store.cpp` | Agent health store | Health status tracking, query, TTL |
| `test_analytics_event.cpp` | Analytics events | Event creation, serialization, drain integration |
| `test_approval_manager.cpp` | Approval manager | Approval CRUD, status transitions, role-gated approvals |
| `test_cert_reloader.cpp` | Certificate reloader | PEM reload, validation, permission checks, hot-swap |
| `test_concurrency_manager.cpp` | Concurrency manager | 5 enforcement modes, lock/release |
| `test_error_codes.cpp` | Error taxonomy | Error code ranges (1xxx-4xxx), message formatting |
| `test_execution_tracker.cpp` | Execution tracker | Progress tracking, per-agent status, completion |
| `test_instruction_store.cpp` | Instruction store | Definition CRUD, YAML persistence, denormalized queries |
| `test_legacy_shim.cpp` | Legacy command shim | Raw command-to-instruction translation |
| `test_management_group_store.cpp` | Management groups | Group CRUD, hierarchy, device membership |
| `test_migration_runner.cpp` | Schema migrations | Migration execution, version tracking |
| `test_notification_store.cpp` | Notifications | In-app notification CRUD, read/unread status |
| `test_oidc_provider.cpp` | OIDC SSO | PKCE flow, JWT validation, group claim parsing |
| `test_quarantine_store.cpp` | Quarantine | Device quarantine/release, network isolation state |
| `test_rate_limiter.cpp` | Rate limiting | Token bucket, per-IP/per-token limits |
| `test_rbac_store.cpp` | RBAC store | Role CRUD, permission assignment, deny-override logic |
| `test_result_envelope.cpp` | Result envelope | Structured response formatting |
| `test_schedule_engine.cpp` | Scheduler | Cron scheduling, next-run calculation, scope-based targeting |
| `test_webhook_store.cpp` | Webhooks | Subscription CRUD, HMAC-SHA256 signing, delivery |

### Untested Server Components

| Component | Why Untested | Priority |
|-----------|-------------|----------|
| **EventBus** (SSE) | Needs thread-safe test harness | Medium |
| **AgentRegistry** | Depends on gRPC protobuf types | Medium |
| **AgentServiceImpl** (Register/Subscribe) | Requires mock gRPC streams | Low |
| **GatewayUpstreamServiceImpl** | Requires mock gRPC streams | Low |
| **HTML fragment renderers** | Output is fragile HTML strings | Very Low |
| **Web route handlers** | Requires full httplib mock | Low |
| **TLS credential loading** | Requires filesystem + certs | Low |

---

## Shared Test Infrastructure

| Header | Location | Used By |
|--------|----------|---------|
| `yuzu/string_utils.hpp` | `sdk/include/yuzu/` | Agent tests, plugins |
| `web_utils.hpp` | `server/core/src/` | Server tests |
| `cve_rules.hpp` | `agents/plugins/vuln_scan/src/` | Agent tests (vuln rules) |

---

## Adding New Tests

### Agent tests
1. Add test file to `tests/unit/`
2. Add to `agent_test_exe` sources in `tests/meson.build`
3. Use `[tag]` categories for filtering

### Server tests
1. Add test file to `tests/unit/server/`
2. Add to `server_test_exe` sources in `tests/meson.build`
3. Private headers are accessible via `include_directories('../server/core/src')`

### New plugin tests
If a plugin has pure functions worth testing:
1. Extract pure functions to a header (or `string_utils.hpp`)
2. Add the plugin's `src/` to `include_directories` in `tests/meson.build`
3. Write a test file that includes the header

---

## Future Test Priorities

1. **EventBus** — thread-safe subscribe/publish/unsubscribe
2. **AgentRegistry** — to_json, help_json, evaluate_scope (once protobuf dep is available to tests)
3. **Netstat parsing** — extract Linux parse_ipv4/ipv6/hex_port to a header for testing
4. **Firewall parsing** — extract Windows parse_firewall_state/rules to a header for testing
5. **NvdClient JSON parsing** — mock HTTP responses and test parse_response
6. **Integration tests** — full Register/Subscribe flow with mock gRPC
