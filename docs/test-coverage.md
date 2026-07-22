# Test Coverage Tracking

Last updated: 2026-07-06

## Overview

| Suite | Executable | Test Files | Status |
|-------|-----------|------------|--------|
| Agent unit tests | `yuzu_agent_tests` | 21 files | Active |
| Server unit tests | `yuzu_server_tests` | 38 files | Active (requires `build_server=true`) |

**Totals:** 53 test files (+1: `test_thread_pool.cpp` — the #2037 dispatch-pool exception firewall; +3: `test_spark_disk.cpp`, `test_spark_engine.cpp`, `test_spark_mechanism.cpp` — the ADR-0021 SparkEngine + File/Registry/Service mechanisms). Test case count has grown significantly since the RC sprint added REST API tests, MCP tests, and store tests. Note: these per-suite file counts and the "Tested" tables below have drifted from `tests/meson.build`'s actual source list on prior updates too — treat as directionally accurate, not authoritative; `tests/meson.build` is the source of truth for what's actually compiled.

Run all tests: `meson test -C build-linux --print-errorlogs`

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
| `test_spark_engine.cpp` | SparkEngine core (ADR-0021) | timer wheel + multi-due-tick no-double-lock regression, arm-dedup fan-out, per-subscriber startup one-shot, stuck-consumer isolation, bounded-queue drop-oldest + drop identity, bounded-shutdown detach (UP-1), inline duration watchdog + throw-survival, disarm, disk breach/recovery edges, lifecycle, register_consumer-vs-stop() race — deterministic hook-forced interleaving (Tr3kkR finding, PR #1927 review) + a real-concurrency stress complement (quality-engineer finding, PR #1927 review); wedged-handler sync state heap-allocated so a detached dispatch can't UAF stack locals (#1957); rung 1: stats_by_type per-type snapshot, lifecycle_mu_ completion barrier (stop-vs-~SparkEngine race), started-never-armed teardown, acquire-then-throw mechanism leak regression (B1 shape), teardown-retry contract — a throwing mechanism stop() is swallowed (noexcept), leaves teardown_complete_ unlatched, and the NEXT stop() re-drives the teardown (mutation-proved: early-out on stopped_ goes red) |
| `test_shutdown_pipe.cpp` | POSIX shutdown self-pipe (`ShutdownWatcher`) | fd contract (read end blocking+CLOEXEC `02000000`, write end NONBLOCK+CLOEXEC `02004001`), kSignal byte reaches the teardown callback exactly once, unpublished-agent byte is not consumed, dtor kQuit retires the watcher WITHOUT running teardown, degrade-on-construction-failure leaves ok()==false (POSIX-only TU) |
| `test_spark_disk.cpp` | Disk spark decision fns | latch breach/recovery, invalid-reading-keeps-latch (UP-5), threshold + min-free logic |
| `test_spark_mechanism.cpp` | `ISparkMechanism` seam + File/Registry/Service | arm/dedup/fan-out/disarm-teardown via a FakeMechanism, watch-failure whole-key rollback (B1), pre-start-replay fault, fault-channel transitions (B1), inline re-arm no-deadlock (TRAP 2), unregister_consumer unwatches a watch its removal empties (Tr3kkR finding, PR #1927 review); mechanism-call race fixes — ghost-subscription on arm-vs-unregister (#1994 M1) and late-unwatch-vs-equal-spec-rearm (#1994 M2), each a deterministic hook-forced test + a real-concurrency stress twin; stop()-inside-mechanism-teardown re-entry does not deadlock (#1934 UP-1/F4); Windows-only (`#ifdef _WIN32`) real-mechanism smoke for File/Registry + delete/recreate resilience + inline µs-dispatch latency + disarm-then-rearm watch retention (PR #1927 review) + ancestor-walk termination on a nonexistent drive root (PR #1927 review) + stale-key-registration cleared on a different-dir re-arm (#1981) + retiring_ cap bounded/observable/refused under a wedged-worker flood (#1979/#1982); real-mechanism smoke for Service on both Windows (SCM) and Linux with libsystemd (`#if defined(__linux__) && defined(YUZU_HAVE_LIBSYSTEMD)`) — fd/thread collapse, churn, live-transition, inline latency, key-coalescing (two engine keys folding onto one unit/service each still emit independently) |
| `test_kv_store.cpp` | KV storage | Set/get/delete, namespace isolation, list with prefix, clear, persistence across reopens; the item-7 durable-journal primitives — `list_entries` (byte-exact/NUL-preserving/empty-vs-error), `insert_if_absent` (Inserted vs Exists), `rename_key` (Renamed/NotFound/Conflict), `del_keys` (count via RETURNING, all-or-nothing), `pragma_synchronous` (39 cases) |
| `test_guardian_journal_format.cpp` | Guardian lifecycle-journal on-disk format (item 7 PR-Ag) | Key helpers + prefixes, `validate_record` (clean/NUL/oversized/invalid-UTF-8/valid-multibyte/skewed-clock/clock-before-fields), batch (de)serialization round-trip byte-exact, parse errors (malformed / unknown version / missing-typewrong fields), pathological-nesting depth guard (no stack-overflow; brackets inside a string are not nesting) |
| `test_guardian_lifecycle_journal.cpp` | Engine-owned durable journal (item 7 PR-Ag) | persist() batching + round-trip + circuit-break + committed-prefix-on-failure; retention (age/count/byte caps, oldest-by-(ts_ms,key)), quarantine of unparseable batches + bounded quarantine set, sent-label GC, paging token bucket; fault injection (injected read failure → fail-safe/counted/retried; injected delete failure → M4 intact-and-retried); hard write ceiling refuses runaway growth + resumes after prune (UP-1); over-cap quarantine eviction counted (UP-7); live size gauges track persist + prune |
| `test_guardian_outbox_drain_worker.cpp` | Guardian outbox drain worker (ADR-0021 rung 7, F6) | drain_once ships everything pending; a throwing send is counted, not fatal (item 4); wake-on-enqueue beats the periodic bound and the bound drains without a wake; stop() idempotent + destructor-driven; a copied waker outliving the worker is a safe no-op. Journal maintenance relocated onto this worker (C0 #2298): paging a durable batch and shipping it in ONE wake (the post-page re-drain), `notify()` as the reconnect kick (prompt, and inert after stop()), the TIME-based maintenance cadence (real journal scans counted through the pre-scan hook while a running worker is hammered with 200 wakes - the regression guard against tying a full-journal scan to wake count), an enqueue-driven wake shipping entries WITHOUT rescanning the journal, `request_stop()` making a whole pass a no-op, a stop fired from INSIDE a scan being honoured mid-pass (not merely at the entry gate), stop()-during-maintenance joining cleanly, the drain and maintenance firewalls not starving each other, maintenance-pass exceptions counted and survived, a bounded drain's truncation/re-drain and its guaranteed compliance share, a drain starting no further sends once stop is requested, a prune failure not swallowing a forced reconnect page, the joined-thread role marker the mtx_ abort keys off, a jammed lifecycle head plus live compliance traffic NOT re-arming the page (the scan-amplification guard), REAL Retain send semantics across a link-down/reconnect cycle and a mid-drain link drop, and a `[tsan]` checkpoint racing worker maintenance against the production phase-1 persist path and reconnect kicks. `[chaos]` (#2345 Gate 5), each observed RED against the unfixed code and each targeting a way a durably-written audit record is deleted without ever being sent: required headroom counted as net-new rather than raw batch size (and a fully-windowed batch reporting neither work nor a blockage), a forward wall-clock step neither wiping the trail in one pass nor ageing it out faster than a capped rate, and a maximum-size batch not being starved out indefinitely by a drip of small ones |
| `test_guardian_engine_spark_reconcile.cpp` | Guardian engine spark reconcile + durable journal wiring | Per-rule spark-vs-legacy mutual exclusion, disable/re-enable re-arm, prefer_spark inertness (no journal write, no paging pass, all-zero telemetry), the maintenance tick retrying a failed persist, stop()'s final flush, `page_journal` KICKING the drain worker (backstop pinned out via the timing seam so only the kick can page), PRODUCTION boot order (wire_spark_engine before start_local, racing the boot maintenance scan against the pre-network re-arm), and a forked-child DEATH TEST proving a worker-thread `mtx_` acquisition aborts rather than deadlocking |
| `test_guardian_journal_heartbeat.cpp` | Journal fleet telemetry (item 7 PR-Ag) | Sparse-emit rule (quiescent journal emits no tags), pinned key names + non-zero-only emission, every field has a distinct key (22), the capacity/size gauges emit under their keys, and a doc/emitter cross-check binding every `yuzu.guardian_*` name in `docs/user-manual/metrics.md` to a name the emitter actually emits |
| `test_trigger_engine.cpp` | Trigger engine | Interval triggers, file-change triggers, service-status triggers, event-log triggers, registry triggers, startup triggers, trigger registration/deregistration, concurrent trigger evaluation (28 cases) |
| `test_new_plugins.cpp` | Plugin runtime | Plugin load/init lifecycle, action dispatch, output callback, multi-plugin coexistence, error handling, config access (~40 cases) |
| `test_metrics.cpp` | Prometheus metrics | Metric registration, counter/gauge/histogram operations, label handling |
| `test_metrics_perf.cpp` | Metrics performance | High-throughput metric emission, contention under concurrent writers |
| `test_tar_diff.cpp` | TAR diff engine | Process tree diff, network change detection, service state transitions |
| `test_tar_store.cpp` | TAR store | Timeline event persistence, query by time range, agent scoping |
| `test_fleet_snapshot.cpp` | TAR fleet_snapshot.v1 JSON builder | Envelope shape, processes/connections round-trip with `remote_host`, default + custom redaction patterns, truncation flags, `process_source_paused` / `tcp_source_paused` markers, `schema_minor` field, payload size bound at full cap (12 cases) |
| `test_inventory_sync.cpp` | Agent daily-sync (ADR-0016): `sync_scheduler`, `sync_source_installed_software` | Canonical-hash cross-pin (blob contract v2, 12 fields); SyncScheduler first-run jitter / hash-skip / change / need_full / phase-spread / weekly full-floor / consecutive-need_full backoff; `inv|` row parse incl. short/over-long-row tolerance; `clamp_field` separator-strip + codepoint-boundary truncation (UP-10) + invalid-UTF-8 scrub to U+FFFD (UP-IN1); empty-name drop (UP-1); empty-inventory skip (UP-IN6); invalid-UTF-8 parity vector (16 cases); `LocalDispatcher` `capture_cap` plumbing regression (default-cap truncates / explicit larger cap doesn't) |
| `test_installed_apps_inventory.cpp` | `installed_apps_inventory.hpp` pure helpers (blob contract v2) | Per-ecosystem line parsers (`parse_dpkg_inv_line`/`parse_rpm_inv_line`/`parse_pacman_inv_line`/`parse_apk_inv_line`) incl. held-package/native-package/epoch-only/wrong-token-count edge cases; EVR splitters (deb/pacman `[epoch:]ver-rel`, apk `name-ver-rN`); rpm `(none)`→empty mapping; `/etc/os-release` quote/comment/CRLF handling; `pipe_safe`; `format_inv_row` 13-token layout |
| `test_win_str_utils.cpp` _(Windows-only)_ | Shared `yuzu::win` wide<->UTF-8 helpers (#1681): `agents/shared/win_str.hpp` | `to_wide`/`from_wide` round-trip preserving "Café"; empty + null input; 512-wchar value with no terminator (#652); lone surrogate → U+FFFD; `reg_sz_to_utf8` trailing-NUL strip (none/one/two), embedded-NUL first-stop (#1682 R6), entry-level full-512 no-terminator, non-wchar-multiple size floor, null buffer + empty payload |
| `test_service_binpath.cpp` _(Windows-only)_ | SCM `--service` binPath quoting (#1822): `agents/core/src/service_win.hpp` `make_service_binpath` | Spaceless path; `Program Files`-style path (exe-only quoting); exact ` --service` suffix (3 cases) |

### Untested Agent Components

| Component | Why Untested | Priority |
|-----------|-------------|----------|
| **Plugin host** (dynamic loading) | Requires .dll/.so artifacts | Low |
| **Trigger engine** | Covered by test_trigger_engine.cpp | Done |
| **gRPC client** | Requires mock server | Medium |
| **Certificate discovery** | Windows-specific CryptoAPI | Low |
| **Cloud identity** | Requires cloud environment | Low |
| **Identity store** | File I/O, low logic density | Low |
| **SCM dispatcher** (#1822, `service_win.cpp` `service_main`/`handler_ex`/`run_service`) | Requires a real SCM-launched process (`StartServiceCtrlDispatcherW`); verified via live Windows-service testing instead (install/start/stop/crash-recovery/fail-closed-exit, documented on issue #1822) — see #1840 for a proposed testable-seam extraction | Low |
| **`win_sc_handle.hpp` `ScHandle`** (RAII SC_HANDLE, move-only) | No dedicated move-semantics unit test yet (same gap as the pre-existing local copy in `guard_service.cpp`) — see #1840 | Low |

### Untested Plugin Runtime Logic

All plugins are loaded as dynamic libraries; their OS-dependent runtime code (subprocess calls, registry queries, WMI, /proc parsing) cannot be unit tested without mocking. The **pure functions** extracted to `string_utils.hpp` (icontains, sanitize_utf8, escape_pipes, etc.) cover the shared logic used by these plugins:

| Plugin | Key Pure Logic Tested Via | OS-Dependent (Not Tested) |
|--------|--------------------------|---------------------------|
| chargen | `chargen_line()` in string_utils | Thread/sleep loop |
| script_exec | `split_args()` in string_utils | CreateProcess/fork/execvp |
| installed_apps | `icontains()`, `sanitize_utf8()`, and (blob v2) the full `installed_apps_inventory.hpp` parse/format surface — see `test_installed_apps_inventory.cpp` above | Registry enum, dpkg/rpm/pacman/apk subprocess invocation, `/etc/os-release` file I/O |
| vuln_scan | `compare_versions()`, `icontains()`, `escape_pipes()` | Registry, package queries |
| event_logs | `sanitize_input()` | PowerShell, journalctl, log |
| os_info | `format_uptime()` | uname, sysctl, registry |
| netstat | TCP state enums, IP parsing | GetExtendedTcpTable, /proc/net |
| firewall | Netsh output parsing; macOS parsers (`firewall_parsers.hpp` — socketfilterfw global state, pfctl status) in `test_firewall_parsers.cpp` | netsh, firewall-cmd, ufw, socketfilterfw, pfctl |
| services | Service state/startup enums | SCManager, systemctl, launchctl |
| diagnostics | Uptime calculation | Plugin context reads |
| network_config | MAC formatting, IP parsing | GetAdaptersAddresses, ip/ifconfig |
| hardware | Size conversion, CPUID parsing | WMI, dmidecode, sysctl |
| processes | Case-insensitive name matching | CreateToolhelp32Snapshot, /proc |
| users | Wide string conversion, FILETIME formatting | Net API, utmp, dscl |
| procfetch | Pipe escaping | File hashing, process enum |
| tags | Key/value validation | File I/O |
| antivirus | macOS parsers (`antivirus_parsers.hpp` — PlistBuddy version, `systemextensionsctl list`) in `test_antivirus_parsers.cpp` | Get-CimInstance, pgrep, PlistBuddy, systemextensionsctl |
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
| `test_nvd.cpp` | NVD database | Version comparison, CVE CRUD, batch inserts, match_inventory, metadata, builtin rules, assess() coverage-aware matching, vendor composite index (EXPLAIN plans), products_for_cves CVE→product inversion, upsert_cves changed_ids delta |
| `test_cpe_identity_resolver.cpp` | CPE identity resolver (PR 3) | Lane gate (os-native / unsupported ecosystem, case-insensitive), no-identity / no-version decision ordering, curated exact-High hit + global-vs-distro-override precedence, `normalize_product` table (interpreter-prefix, SAFE-suffix, lib-dot soname, prefix-then-no-suffix, prefix floor), display-only vendor contract, fail-closed floor (12 vs 13 exact boundary), and adversarial regressions (13-malformed-lines → 0 rows, empty-product row dropped, uncurated dotted-lib e2e dot-strip). Untested / PR-4-owed: seed cpe_product-vs-NVD-mirror validation (DB-free in PR 3 — a wrong token silently yields zero coverage until PR 4 asserts each seed product hits ≥ 1 real `cve_match` row). |
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
| `test_agent_health_store.cpp` | Agent health store | Health status tracking, query, TTL; spark fleet rollup against the REAL store + recompute_metrics (four postures, inert exclusion, absent-not-zero — mutation-proved: deleting the disabled/failed emit loops goes red while the mirror-based cases stay green) |
| `test_spark_fleet_tags.cpp` | Spark fleet-tag contract (server↔agent pin) | static_assert key pins (all 7 fixed keys), writer↔reader runtime bind against the agent's real emitter (spark_heartbeat.hpp), four-posture wire contract, mechanism-CSV closed-set/dedup/64-byte cap, count-parse forged-value posture (full-token, negative/overflow/1e9-plausibility, 10-digit length cap incl. a 4 MiB token) |
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
| `test_software_inventory_store.cpp` | `SoftwareInventoryStore` + `inventory_ingestion` seam (ADR-0016) | Canonical-hash cross-pin (blob contract v2, 12 fields), hash-skip ingest (full/touched/need_full/drift/cold-cache), atomic full-replace, invalid-UTF-8 scrub-to-U+FFFD store + agent hash coordination (UP-IN1), codepoint-boundary truncation (UP-10), oversized-blob drop+nack (UP-2/UP-4), kError→need_full nack (UP-2), fleet query (live PostgreSQL); v2 12-field round-trip through store + ingest seam; v1→v2 mixed-version compat (bounded need_full loop, not infinite); migration v5 upgrade (pre-v5 rows read `''` in new columns) |
| `test_vuln_finding_store.cpp` + `test_vuln_finding_store_adversarial.cpp` | `VulnFindingStore` (born-on-PG, ADR-0023 M1a) | Fail-closed ctor + idempotent migration, reconcile sequence (upsert-always / authoritative-gated sweep + `disposed_clean` delete + coverage clobber), monotonic in-txn `run_ts` + NTP-step-back safety, re-observe/status-upgrade in place, three-way coverage read (Ok/NotFound/Degraded under real pool exhaustion), authoritative `fleet_summary` (nullopt-on-degrade, excludes resolved), nullable cvss/fixed_in NULL round-trip, non-finite cvss (NaN/+Inf)→NULL no-abort (FIX 2), UP-2 mass-resolve backstop arm/narrow (FIX 3), NUL-in-identity reject (FIX 4), mixed-case severity/status query-filter normalization (FIX 6), whole-batch rollback on a bad row (mid-batch), duplicate-key-in-batch upsert, per-agent advisory-lock serialization + cross-store namespace isolation (deterministic `pg_try_advisory_xact_lock` proof), SQL-metacharacter parameterization; also exercises `SoftwareInventoryStore::list_agent_ids` keyset pager (live PostgreSQL) |
| `test_notification_store.cpp` | Notifications | In-app notification CRUD, read/unread status |
| `test_oidc_provider.cpp` | OIDC SSO | PKCE flow, JWT validation, group claim parsing (present/empty/absent, Entra `_claim_names`/`_claim_sources` group-overage detection, `groups_claim_reconcilable` gate) |
| `test_quarantine_store.cpp` | Quarantine | Device quarantine/release, network isolation state |
| `test_rate_limiter.cpp` | Rate limiting | Token bucket, per-IP/per-token limits |
| `test_rbac_store.cpp` | RBAC store | Role CRUD, permission assignment, deny-override logic; IdP-group reconciliation (#1832): namespacing/confused-deputy, add/remove diff, empty-asserted full deprovisioning (incl. a local-role-grant-survives regression guard), group-count cap (boundary + over-cap), reserved-prefix guard on `create_group`, `reconcile_idp_memberships` source-verify against a pre-existing differently-sourced namespaced row, `source=="local"`/empty rejection, blank/oversized `external_id` skip, `{added,removed}` count reporting, v1→v2 schema migration (indices + no data loss) |
| `test_result_envelope.cpp` | Result envelope | Structured response formatting |
| `test_schedule_engine.cpp` | Scheduler | Cron scheduling, next-run calculation, scope-based targeting |
| `test_webhook_store.cpp` | Webhooks | Subscription CRUD, HMAC-SHA256 signing, delivery |
| `test_security_headers.cpp` | HTTP security headers (SOC2-C1) | `validate_csp_extra_sources` accept/reject grammar (control bytes, semicolons, unsafe keywords, hash/nonce expressions, quoted/unquoted tokens, position tracking), `build_csp` directives + extras + `upgrade-insecure-requests` gating, `build_permissions_policy` deny-all baseline, `build_referrer_policy`, `HeaderBundle::apply` six-header emission, end-to-end integration via `httplib::Server`/`httplib::Client` (38 cases) |
| `test_fleet_topology_store.cpp` | FleetTopologyStore + process_category | `classify()` over ~70 known basenames (case-insensitive, `.exe`/path stripping), cross-machine IP resolution to `dst_agent_id`, scope classification (Local/InternalFleet/External), 0.0.0.0/:: + loopback + link-local skip from `ip_to_agent`, IPv6 bracket and zone-id normalization, no-remote-endpoint drop, agent self-connection scope, stale-agent passthrough, vuln-overlay-disabled-when-nvd-null, JSON shape (`fleet_topology.v1`), cache hit/miss/TTL, invalidate, `include_vuln` slot independence, single-flight, fetcher exception returns empty sentinel, oversized snapshot returned but not cached (27 cases) |
| `test_viz_routes.cpp` | VizRoutes (`/api/v1/viz/fleet/topology` + `/fragments/...`) | 200 JSON envelope shape with strict `REQUIRE` on schema/schema_minor/machines, fragment wraps same JSON in `<script type="application/json" id="viz-data">`, fragment escapes `</script>` injection in agent-controlled hostname/cmdline (sec-M2 regression), tier-before-permission (kill switch precedes RBAC even when caller would be denied), 403 perm-denied short-circuit with no audit row, 503 kill-switch with `denied`/`kill_switch` audit (DEP-1), 503 store-null with `failure`/`store_null` audit, 500/200 on fetcher-throw (UP-9 sentinel path), 413 + `denied`+`oversize machines=N cap=M` audit + metric increment when count exceeds `machines_max` (M-1), 400 on non-numeric / above-ceiling / zero / `std::out_of_range` overflow `machines_max` (QA-S2), `?fresh=1` emits separate `viz.fleet_topology.invalidate`+`success` audit before the get, cache-miss/cache-hit metric increments observed across two sequential calls, histogram receives an observation on success (QA-S3), `include_vuln=1` flips JSON `include_vuln` field (18 cases) |

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
