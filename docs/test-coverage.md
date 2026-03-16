# Test Coverage Tracking

Last updated: 2026-03-16

## Overview

| Suite | Executable | Test Files | Status |
|-------|-----------|------------|--------|
| Agent unit tests | `yuzu_agent_tests` | 7 files | Active |
| Server unit tests | `yuzu_server_tests` | 10 files | Active (requires `build_server=true`) |

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

### Untested Agent Components

| Component | Why Untested | Priority |
|-----------|-------------|----------|
| **Plugin host** (dynamic loading) | Requires .dll/.so artifacts | Low |
| **Trigger engine** | Not yet implemented | N/A |
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

### Untested Server Components

| Component | Why Untested | Priority |
|-----------|-------------|----------|
| **EventBus** (SSE) | Needs thread-safe test harness | Medium |
| **AgentRegistry** | Depends on gRPC protobuf types | Medium |
| **AgentServiceImpl** (Register/Subscribe) | Requires mock gRPC streams | Low |
| **GatewayUpstreamServiceImpl** | Requires mock gRPC streams | Low |
| **NvdClient** (HTTP) | Requires mock HTTP client | Low |
| **NvdSyncManager** | Background thread orchestration | Low |
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
