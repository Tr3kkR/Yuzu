if host_os == 'windows'
  # Same #375-class IMPORTED_LOCATION_RELEASE problem as protobuf/grpc/cli11
  # in the top-level meson.build: meson's cmake dep translator picks
  # the release-CRT Catch2 lib for both debug and release consumers,
  # so a debug test binary linking with /MDd against release Catch2
  # trips dozens of LNK2038 _ITERATOR_DEBUG_LEVEL mismatches.
  #
  # Catch2's vcpkg layout (verified against vcpkg_installed/x64-linux/
  # — same convention on Windows with .lib instead of .a):
  #
  #   lib/Catch2.lib                              <- base lib
  #   lib/manual-link/Catch2Main.lib              <- defines main()
  #   debug/lib/Catch2d.lib                       <- debug, `d` suffix
  #   debug/lib/manual-link/Catch2Maind.lib
  #
  # Three quirks:
  #   1. Two libs in two directories. Catch2 is in plain lib/; only
  #      Catch2Main lives in lib/manual-link/. (vcpkg convention:
  #      libs that define main() — that the consumer must explicitly
  #      opt into linking — go in manual-link/.)
  #   2. The lib file is named Catch2Main, NOT Catch2WithMain. The
  #      cmake TARGET is Catch2::Catch2WithMain but the underlying
  #      filename omits the "With".
  #   3. Same `d` suffix convention as protobuf for the debug variant.
  #      _pbd is established in the top-level Windows block ('' for
  #      release, 'd' for debug).
  _cxx_tests = meson.get_compiler('cpp')
  _libcatch2     = _cxx_tests.find_library('Catch2'     + _pbd, dirs: [_vcpkg_lib_win],                 required: true)
  _libcatch2main = _cxx_tests.find_library('Catch2Main' + _pbd, dirs: [_vcpkg_lib_win / 'manual-link'], required: true)
  catch2_dep = declare_dependency(
    # Reuse the project-root-anchored IncludeDirs object from the top-level
    # meson.build. Recreating it here with include_directories() would resolve
    # the relative path against tests/ and fail with "vcpkg_installed/...
    # does not exist".
    include_directories: _vcpkg_inc_win,
    # Order matters: Catch2Main defines main() and references symbols
    # from Catch2. List Main first so the linker pulls it in, then
    # Catch2 satisfies the leftover refs.
    dependencies: [_libcatch2main, _libcatch2],
  )
  # No-main variant for yuzu_agent_tests (#1648 diagnostic): the suite
  # supplies its own main() via unit/test_runner_main.cpp so it can log
  # Catch2's real return code, so it must NOT also pull in Catch2Main.
  catch2_nomain_dep = declare_dependency(
    include_directories: _vcpkg_inc_win,
    dependencies: [_libcatch2],
  )
else
  catch2_dep = dependency('Catch2', modules: ['Catch2::Catch2WithMain'], method: 'cmake', required: true, include_type: 'system')
  catch2_nomain_dep = dependency('Catch2', modules: ['Catch2::Catch2'], method: 'cmake', required: true, include_type: 'system')
endif

# ── Test fixture: plugin with a reserved name (#453) ─────────────────────────
# Built only when tests are enabled; test_plugin_loader.cpp scans against this
# shared library to verify the reserved-name rejection path.
reserved_name_fixture_plugin = shared_library(
  'reserved_name_fixture_plugin',
  files('unit/fixtures/reserved_name_plugin.cpp'),
  name_prefix: '',
  dependencies: [yuzu_sdk_dep, yuzu_agent_core_dep],
  install: false,
)

# ── Test fixture: plugin with a malformed name (#822) ────────────────────────
# Declares a name outside the [A-Za-z0-9_] identifier set; test_plugin_loader.cpp
# scans against it to verify the invalid-name rejection path.
invalid_name_fixture_plugin = shared_library(
  'invalid_name_fixture_plugin',
  files('unit/fixtures/invalid_name_plugin.cpp'),
  name_prefix: '',
  dependencies: [yuzu_sdk_dep, yuzu_agent_core_dep],
  install: false,
)

# ── Agent unit tests ──────────────────────────────────────────────────────────
#
# Proto-dep choice is platform-conditional (#572 + Windows MSVC follow-up):
#
#   * Linux + macOS: yuzu_proto_headers_dep (no link_with). The proto
#     symbols are baked into libyuzu_agent_core.so as `.dynsym` entries
#     because proto/meson.build compiles with -fvisibility=default. The
#     test binary resolves them dynamically at runtime → single
#     descriptor registration → ASan-clean.
#
#   * Windows MSVC: yuzu_proto_dep (with link_with). MSVC shared_library
#     does NOT export symbols by default — there's no equivalent of
#     -fvisibility=default that lets every symbol cross the DLL boundary
#     without __declspec(dllexport). So libyuzu_agent_core.dll's import
#     lib does not surface proto symbols and the test binary must link
#     yuzu_proto.lib directly. Same proto archive, double-registered —
#     but ASan isn't part of the Windows MSVC build matrix, so the
#     duplicate-descriptor CHECK that drove #572 doesn't fire here.
#
# Without this split, Windows MSVC fails LNK2019 on every .pb.o symbol
# in test_guardian_engine.cpp (the canary that surfaces the broken link).
if host_machine.system() == 'windows'
  agent_test_proto_dep = yuzu_proto_dep
else
  agent_test_proto_dep = yuzu_proto_headers_dep
endif

# test_plugin_loader.cpp uses OpenSSL CMS APIs to mint test fixtures
# (CA + signing cert + detached PEM signature) so the verifier tests do not
# depend on `openssl(1)` at runtime or pre-baked .pem files that drift.
agent_test_openssl_dep = dependency('openssl', required: true, include_type: 'system')

# Test fixtures deliberately partial-aggregate-init wide inventory structs
# (SwEntry / SoftwareEntry are 12 fields since blob contract v2; a 4-field
# init IS the contract — "the rest stays empty"). -Wextra's
# missing-field-initializers would flag every such fixture; suppress it for
# the TEST targets only — production code stays fully warned.
if cxx.get_id() == 'msvc'
  test_partial_init_args = []
else
  test_partial_init_args = ['-Wno-missing-field-initializers']
endif

agent_test_exe = executable(
  'yuzu_agent_tests',
  files(
    # Custom Catch2 entry point (#1648 diagnostic) — logs Session::run()'s
    # real return value; see unit/test_runner_main.cpp and catch2_nomain_dep
    # above.
    'unit/test_runner_main.cpp',
    'unit/test_plugin_loader.cpp',
    'unit/test_sdk_utilities.cpp',
    'unit/test_temp_file.cpp',
    'unit/test_updater.cpp',
    'unit/test_filesystem_read.cpp',
    'unit/test_filesystem_actions.cpp',
    'unit/test_string_utils.cpp',
    'unit/test_vuln_rules.cpp',
    'unit/test_metrics.cpp',
    'unit/test_metrics_perf.cpp',
    'unit/test_kv_store.cpp',
    'unit/test_trigger_engine.cpp',
    'unit/test_guardian_engine.cpp',
    'unit/test_guardian_journal_format.cpp',
    'unit/test_guardian_lifecycle_journal.cpp',
    'unit/test_guardian_journal_heartbeat.cpp',
    'unit/test_guardian_health_heartbeat.cpp',
    'unit/test_guard_registry.cpp',
    'unit/test_guard_file.cpp',
    'unit/test_guard_service.cpp',
    'unit/test_guard_systemd.cpp',
    'unit/test_dex_signals.cpp',
    'unit/test_dex_macos.cpp',
    'unit/test_dex_win_poll.cpp',
    'unit/test_dex_perf_breach.cpp',
    'unit/test_net_quality_sampler.cpp',
    'unit/test_dex_linux_proc.cpp',
    'unit/test_dex_linux_journal.cpp',
    'unit/test_dex_linux_kmsg.cpp',
    'unit/test_dex_linux_sysfs.cpp',
    'unit/test_dex_rate_limiter.cpp',
    'unit/test_resilience_strategy.cpp',
    'unit/test_thread_pool.cpp',
    'unit/test_shutdown_pipe.cpp',
    'unit/test_hard_exit.cpp',
    'unit/test_spark_disk.cpp',
    'unit/test_spark_engine.cpp',
    'unit/test_spark_key_rule_index.cpp',
    'unit/test_spark_mechanism.cpp',
    'unit/test_guardian_spark_bridge.cpp',
    'unit/test_guardian_spark_backend.cpp',
    'unit/test_guardian_emit_decider.cpp',
    'unit/test_guardian_rule_eval.cpp',
    'unit/test_guardian_drift_event.cpp',
    'unit/test_guardian_scope_guard.cpp',
    'unit/test_guardian_outbox.cpp',
    'unit/test_guardian_spark_send.cpp',
    'unit/test_guardian_spark_runtime.cpp',
    'unit/test_guardian_state_reader.cpp',
    'unit/test_guardian_convergence_scheduler.cpp',
    'unit/test_guardian_io_executor.cpp',
    'unit/test_guardian_outbox_drain_worker.cpp',
    'unit/test_guardian_engine_spark_reconcile.cpp',
    'unit/test_new_plugins.cpp',
    'unit/test_netprobe_stats.cpp',
    'unit/test_antivirus_parsers.cpp',
    'unit/test_firewall_parsers.cpp',
    'unit/test_agent_csr.cpp',
    'unit/test_cert_discovery.cpp',
    'unit/test_env_util.cpp',
    'unit/test_inventory_sync.cpp',
    'unit/test_device_ci_sync.cpp',
    'unit/test_sync_source_app_perf.cpp',
    'unit/test_win_str_utils.cpp',
    'unit/test_installed_apps_registry_utf8.cpp',
    'unit/test_service_binpath.cpp',
    'unit/test_installed_apps_inventory.cpp',
    'unit/test_licensing_parsers.cpp',
    'unit/test_licensing_sync.cpp',
    'unit/test_wifi_corewlan.cpp',
    'unit/test_interaction_parsers.cpp',
    'unit/test_hardware_disks_macos.cpp',
    'unit/test_certificates_macos.cpp',  # A-1.11 (INT-2 handoff): existed unregistered on the branch;
                                          # macos_console_user.hpp already reachable via the agents/shared
                                          # include_directories entry below.
    'unit/agent/test_services_macos.cpp',     # C-1.12: launchctl print-disabled parser (P8)
    'unit/agent/test_msi_macos.cpp',          # C-1.21: pkgutil --pkg-info parser (P8)
    'unit/agent/test_bitlocker_macos.cpp',    # A-1.16: diskutil apfs list parser (P8)
    'unit/test_subprocess_runner.cpp',        # #2273: agent-core bounded subprocess runner (POSIX deadline/reap)
    'unit/test_filesystem_macos_sig.cpp',     # #2273/1.14: pure codesign/plutil classifiers
    'unit/test_event_logs_macos.cpp',         # BR-08: pure `log show` SubprocessResult classifier
    'unit/test_users_macos_last.cpp',         # qe-M1: pure `last -y` timestamp/weekday parsers
  ),
  include_directories: [
    include_directories('../agents/plugins/vuln_scan/src'),  # cve_rules.hpp
    include_directories('../agents/plugins/netprobe/src'),   # netprobe_stats.hpp (pure helpers)
    include_directories('../agents/plugins/antivirus/src'),  # antivirus_parsers.hpp (pure helpers)
    include_directories('../agents/plugins/firewall/src'),   # firewall_parsers.hpp (pure helpers)
    include_directories('../agents/plugins/installed_apps/src'),  # installed_apps_registry_utf8.hpp (#1662 test)
    include_directories('../agents/plugins/license_scan/src'),    # licensing_parsers.hpp / licensing_record.hpp (pure, SLE PR1)
    include_directories('../agents/plugins/wifi/src'),            # wifi_corewlan.hpp (pure connected-record formatter)
    include_directories('../agents/plugins/interaction/src'),     # interaction_parsers.hpp (pure helpers)
    include_directories('../agents/core/src'),               # dex_event.hpp (proto-aware mapping)
    include_directories('../agents/shared'),         # win_str.hpp (#1681, _WIN32-gated); also macos_console_user.hpp (test_certificates_macos.cpp)
    include_directories('../agents/plugins/hardware/src'),  # hardware_disks_macos.hpp (pure parser, PR1.8)
    include_directories('../agents/plugins/services/src'),      # services_macos_launchd.hpp (P8 test)
    include_directories('../agents/plugins/msi_packages/src'),  # msi_packages_macos.hpp (P8 test)
    include_directories('../agents/plugins/bitlocker/src'),     # bitlocker_macos_apfs.hpp (P8 test)
    include_directories('../agents/plugins/filesystem/src'),    # filesystem_macos_sig.hpp (#2273/1.14)
    include_directories('../agents/plugins/event_logs/src'),    # event_logs_macos.hpp (BR-08)
    include_directories('../agents/plugins/certificates/src'),  # certificates_macos_parsers.hpp (Gate-7 FIX A: pure helpers shared with the plugin)
    include_directories('../agents/plugins/users/src'),         # users_macos_last.hpp (qe-M1 pure parser)
  ],
  # agent_platform_args carries -DYUZU_HAVE_LIBSYSTEMD (Linux + libsystemd found)
  # so Linux real-mechanism Service spark tests can compile-gate on it, exactly
  # as agents/core/meson.build gates guard_systemd.cpp/spark_service.cpp.
  cpp_args: test_partial_init_args + agent_platform_args,
  # catch2_nomain_dep (#1648 diagnostic): yuzu_agent_tests supplies its own main()
  # via unit/test_runner_main.cpp, so it links Catch2 without Catch2Main.
  # spdlog_dep (brings fmt): test_thread_pool.cpp instantiates spdlog logging in
  # thread_pool.hpp directly in the test TU, so it needs fmt symbols linked here.
  # sqlite3_dep: test_kv_store.cpp opens a SECOND raw connection to the same file to
  # provoke a genuine SQLite failure (dropping the table so prepare fails), which is the
  # only way to exercise KvStore's fallible-read branches end to end rather than through
  # an injected stand-in. Already a transitive dep of yuzu_agent_core; naming it here is
  # what puts sqlite3.h on the test TU's include path (same shape as tar_test_deps).
  dependencies: [yuzu_agent_core_dep, yuzu_sdk_dep, agent_test_proto_dep, nlohmann_dep, catch2_nomain_dep, agent_test_openssl_dep, spdlog_dep, sqlite3_dep],
  # Ensure the fixture plugins are built before the test runs so the lookups
  # inside test_plugin_loader.cpp find them under MESON_BUILD_ROOT/tests/.
  link_depends: [reserved_name_fixture_plugin, invalid_name_fixture_plugin],
)
# Two agent tests are [tsan-heavy]: concurrency STRESS checkpoints that spin four to five
# threads on real SQLite I/O with no throttle. Their wall time is contention-dominated - it
# ballooned under Big Tam filesystem contention (four CI jobs sharing one host's /tmp), where
# one stalled ~8 minutes and timed the whole agent suite out (#2345). In a PLAIN build they
# detect nothing (no instrumentation), so that cost buys no signal there - skip them. A
# sanitizer build runs everything (ASan for use-after-free in the concurrent teardown, TSan
# for the races they exist for), where the ~10x-larger job budget absorbs their cost as it did
# before this change. The OTHER four [tsan] tests are cheap and bounded (no real SQLite, or a
# fixed sleep) and stay in every build. A coverage build (b_coverage, no sanitizer) also skips
# the two heavy tests; their concurrent code paths are line-covered by the sequential
# prune/page/gauge tests and the cheap concurrent tests, so no meaningful line coverage is lost.
# The residual risk that these two balloon on the shared Big Tam pool even under the sanitizer
# budget is tracked in #2373 (split/redesign), not papered over with a wall-clock cap here -
# that route introduced its own flakiness (a busy main thread starving the workers it waited on)
# and was backed out.
agent_test_args = (get_option('b_sanitize') == 'none') ? ['~[tsan-heavy]'] : []
test(
  'agent unit tests',
  agent_test_exe,
  args: agent_test_args,
  suite: 'agent',
  timeout: 240, # restored after moving the two [tsan-heavy] spin-loop tests to sanitizer-only (#2345): plain suite is ~28s, so 240s is ~8x headroom and surfaces a genuine hang rather than absorbing it into a loose ceiling.
  depends: [reserved_name_fixture_plugin, invalid_name_fixture_plugin],
)

# ── cert_store macOS honest-unsupported unit test (A-1.20 / P8; BR-001/BR-003
#    branch-review fix) ────────────────────────────────────────────────────
# cert_store.cpp's __APPLE__ branch unconditionally returns an honest
# "unsupported" CertStoreResult (the macOS agent runs as a root LaunchDaemon
# with no user login keychain — see the file header comment on
# read_cert_from_store() there). This dedicated executable recompiles that
# SAME cert_store.cpp source standalone — no Security/CoreFoundation
# frameworks, not linked against the rest of yuzu_agent_core — purely to
# check the contract in isolation. macOS only: on Linux/Windows
# cert_store.cpp's OTHER branches are the real (non-stub) implementations,
# which this target is not meant to probe.
if host_machine.system() == 'darwin'
  cert_store_fallback_test_exe = executable(
    'yuzu_cert_store_fallback_tests',
    files(
      'unit/agent/test_cert_store_fallback.cpp',
      '../agents/core/src/cert_store.cpp',
    ),
    include_directories: [
      include_directories('../agents/core/include'),  # yuzu/agent/cert_store.hpp
    ],
    # spdlog_dep only for the header include path (cert_store.cpp's
    # unconditional #include <spdlog/spdlog.h>); the macOS stub never
    # actually calls into it.
    dependencies: [yuzu_sdk_dep, spdlog_dep, catch2_dep],
  )
  test('cert_store macOS honest-unsupported', cert_store_fallback_test_exe, suite: 'agent', timeout: 30)
endif

# ── TAR plugin unit tests ────────────────────────────────────────────────────
tar_test_deps = [yuzu_agent_core_dep, yuzu_sdk_dep, nlohmann_dep, spdlog_dep, sqlite3_dep, catch2_dep]
tar_test_cpp_args = []
if host_machine.system() == 'windows'
  # tar_perf.cpp (compiled directly into this exe) → GetIfTable2 / FreeMibTable
  tar_test_deps += cxx.find_library('iphlpapi')
  tar_test_deps += cxx.find_library('tdh') # tar_proc_etw.cpp / tar_module_etw.cpp ETW decode
  tar_test_deps += cxx.find_library('wintrust') # tar_module_etw.cpp WinVerifyTrust
  tar_test_deps += cxx.find_library('crypt32')  # tar_module_etw.cpp CryptQueryObject
  tar_test_deps += cxx.find_library('version')  # tar_proc_perf.cpp GetFileVersionInfoW
  tar_test_deps += cxx.find_library('wevtapi')  # tar_netconn_win.cpp EvtQuery/EvtRender
  tar_test_deps += cxx.find_library('ws2_32')   # winsock2 symbols the iphlpapi/netioapi headers in tar_netqual_boot.cpp pull in
  tar_test_deps += cxx.find_library('mpr')      # tar_mapdrive_collector.cpp WNet outbound
  tar_test_deps += cxx.find_library('netapi32') # tar_mapdrive_collector.cpp NetSessionEnum inbound
elif host_machine.system() == 'darwin'
  # tar_proc_es.cpp (compiled directly into this exe) → Endpoint Security client +
  # audit-token helpers, gated on the framework being present (full Xcode SDK).
  # The live client never starts in CI (unentitled) so the pure-mapping + clean-
  # fallback tests run regardless; the ES TU only links the framework where it
  # exists. Mirror the plugin's capability detection (docs/darwin-compat.md).
  es_test_dep = dependency('appleframeworks', modules: ['EndpointSecurity'], required: false, include_type: 'system')
  if es_test_dep.found()
    tar_test_deps += es_test_dep
    tar_test_deps += cxx.find_library('bsm')
    # -fblocks required for the ES block literal in tar_proc_es.cpp (see plugin meson).
    tar_test_cpp_args += ['-DYUZU_HAVE_ENDPOINT_SECURITY', '-fblocks']
  endif
endif

tar_test_exe = executable(
  'yuzu_tar_tests',
  files(
    'unit/test_tar_diff.cpp',
    'unit/test_tar_netconn.cpp',
    'unit/test_tar_software.cpp',
    'unit/test_tar_store.cpp',
    'unit/test_tar_schema_registry.cpp',
    'unit/test_tar_warehouse.cpp',
    'unit/test_tar_aggregator.cpp',
    'unit/test_tar_perf.cpp',
    'unit/test_tar_proc_perf.cpp',
    'unit/test_app_perf_rollup_query.cpp',
    'unit/test_tar_proc_etw.cpp',
    'unit/test_tar_proc_es.cpp',
    'unit/test_tar_netqual_nstat.cpp',
    'unit/test_tar_module_stream.cpp',
    'unit/test_tar_module_etw.cpp',
    'unit/test_tar_mapdrive.cpp',
    'unit/test_fleet_snapshot.cpp',
    '../agents/plugins/tar/src/tar_db.cpp',
    '../agents/plugins/tar/src/tar_sql_executor.cpp',
    '../agents/plugins/tar/src/tar_diff.cpp',
    '../agents/plugins/tar/src/tar_software_core.cpp',
    '../agents/plugins/tar/src/tar_schema_registry.cpp',
    '../agents/plugins/tar/src/tar_aggregator.cpp',
    '../agents/plugins/tar/src/tar_perf.cpp',
    '../agents/plugins/tar/src/tar_proc_perf.cpp',
    '../agents/plugins/tar/src/tar_proc_stream.cpp',
    '../agents/plugins/tar/src/tar_module_stream.cpp',
    '../agents/plugins/tar/src/tar_proc_etw.cpp',
    '../agents/plugins/tar/src/tar_proc_es.cpp',
    '../agents/plugins/tar/src/tar_module_etw.cpp',
    '../agents/plugins/tar/src/tar_netqual_boot.cpp',
    '../agents/plugins/tar/src/tar_netqual_nstat.cpp',
    '../agents/plugins/tar/src/tar_netconn_win.cpp',
    '../agents/plugins/tar/src/tar_mapdrive_collector.cpp',
    '../agents/plugins/tar/src/tar_fleet_snapshot.cpp',
  ),
  include_directories: [
    include_directories('../agents/plugins/tar/src'),
    include_directories('../agents/shared'),  # win_str.hpp — tar_module_etw.cpp is compiled into this test exe (#1681, relocated plugins/shared -> agents/shared)
    include_directories('../agents/core/src'),        # sync_source_app_perf.hpp — app_perf rollup-query integration test
  ],
  cpp_args: tar_test_cpp_args,
  dependencies: tar_test_deps,
)
test('tar unit tests', tar_test_exe, suite: 'tar', timeout: 90)

# ── Server unit tests ─────────────────────────────────────────────────────────
if build_server
  server_test_exe = executable(
    'yuzu_server_tests',
    files(
      'unit/server/test_auth.cpp',
      'unit/server/test_auth_routes.cpp',
      'unit/server/test_auth_routes_mfa.cpp',
      'unit/server/test_auth_jit_elevation.cpp',
      'unit/server/test_auth_sso_identity.cpp',
      'unit/server/test_auth_routes_hardened.cpp',
      'unit/server/test_settings_routes_mfa.cpp',
      'unit/server/test_totp.cpp',
      'unit/server/test_mfa_step_up.cpp',
      'unit/server/test_mfa_qr.cpp',
      'unit/server/test_mfa_store.cpp',
      'unit/server/test_auth_lockout.cpp',
      'unit/server/test_auth_break_glass.cpp',
      'unit/server/test_auth_db_pg.cpp',
      'unit/server/test_auto_approve.cpp',
      'unit/server/test_cidr_match.cpp',
      'unit/server/test_nvd.cpp',
      'unit/server/test_cpe_identity_resolver.cpp',
      'unit/server/test_update_registry.cpp',
      'unit/server/test_https_config.cpp',
      'unit/server/test_response_store.cpp',
      'unit/server/test_preflight_parse.cpp',
      'unit/server/test_preflight_eval.cpp',
      'unit/server/test_preflight_run_store.cpp',
      'unit/server/test_deployment_parse.cpp',
      'unit/server/test_deployment_run_store.cpp',
      'unit/server/test_deployment_engine.cpp',
      'unit/server/test_bundle_service.cpp',
      'unit/server/test_bundle_orchestrator.cpp',
      'unit/server/test_rest_bundle.cpp',
      'unit/server/test_audit_store.cpp',
      'unit/server/test_rest_audit_sample.cpp',
      'unit/server/test_rest_audit_helper.cpp',
      'unit/server/test_tag_store.cpp',
      'unit/server/test_scope_engine.cpp',
      'unit/server/test_web_utils.cpp',
      'unit/server/test_mcp_body_cap.cpp',
      'unit/server/test_dispatch_target_shape.cpp',
      'unit/server/test_workflow_routes.cpp',
      'unit/server/test_agent_service_impl.cpp',
      'unit/server/test_analytics_event.cpp',
      'unit/server/test_agent_health_store.cpp',
      'unit/server/test_instruction_store.cpp',
      'unit/server/test_instruction_store_signing.cpp',
      'unit/server/test_instruction_yaml.cpp',
      'unit/server/test_execution_tracker.cpp',
      'unit/server/test_execution_event_bus.cpp',
      'unit/server/test_approval_manager.cpp',
      'unit/server/test_schedule_engine.cpp',
      'unit/server/test_schedule_routes.cpp',
      'unit/server/test_schedule_runner.cpp',
      'unit/server/test_rbac_store.cpp',
      'unit/server/test_oidc_principal_key.cpp',
      'unit/server/test_oidc_provider.cpp',
      'unit/server/test_oidc_routes.cpp',
      'unit/server/test_saml_provider.cpp',
      'unit/server/test_saml_routes.cpp',
      'unit/server/test_error_codes.cpp',
      'unit/server/test_result_envelope.cpp',
      'unit/server/test_concurrency_manager.cpp',
      'unit/server/test_legacy_shim.cpp',
      'unit/server/test_management_group_store.cpp',
      'unit/server/test_dashboard_tar_retention.cpp',
      'unit/server/test_dashboard_tar_fragments.cpp',
      'unit/server/test_route_sink_harness.cpp',
      'unit/server/test_rest_tar_purge.cpp',
      'unit/server/test_api_token_store.cpp',
      'unit/server/test_engine_principal_store.cpp',
      'unit/server/test_engine_principal_integration.cpp',
      # #2367: test-only definition of EngineLivenessTestAccess::revalidate,
      # kept OFF the production link line so the private cached path has no
      # public trampoline in server_core.
      'unit/server/engine_liveness_test_access.cpp',
      'unit/server/test_rest_engine_principal_roles.cpp',
      'unit/server/test_mcp_engine_principal_roles.cpp',
      'unit/server/test_engine_principal_lifecycle.cpp',
      'unit/server/test_engine_store_error_class.cpp',
      'unit/server/test_rotation_confirm_state.cpp',
      'unit/server/test_access_review_model.cpp',
      'unit/server/test_access_review_store.cpp',
      'unit/server/test_rest_access_review.cpp',
      'unit/server/test_secure_random.cpp',
      'unit/server/test_quarantine_store.cpp',
      'unit/server/test_result_set_store.cpp',
      'unit/server/test_result_set_matcher.cpp',
      'unit/server/test_rest_result_sets_async.cpp',
      'unit/server/test_chrome_ir_chain.cpp',
      'unit/server/test_result_sets_ui.cpp',
      'unit/server/test_scope_walking_authz.cpp',
      'unit/server/test_scope_yaml.cpp',
      'unit/server/test_yaml_scan.cpp',
      'unit/server/test_policy_store.cpp',
      'unit/server/test_policy_evaluator.cpp',
      'unit/server/test_guaranteed_state_store.cpp',
      'unit/server/test_guardian_ingest.cpp',
      'unit/server/test_baseline_store.cpp',
      'unit/server/test_guardian_push_builder.cpp',
      'unit/server/test_guardian_resilience_schema.cpp',
      'unit/server/test_guardian_routes.cpp',
      'unit/server/test_dex_routes.cpp',
      'unit/server/test_device_ui.cpp',
      'unit/server/test_device_routes.cpp',
      'unit/server/test_inventory_routes.cpp',
      'unit/server/test_sle_routes.cpp',
      'unit/server/test_inventory_ci_join.cpp',
      'unit/server/test_software_catalog_rollup.cpp',
      'unit/server/test_tar_process_tree.cpp',
      'unit/server/test_tar_tree_routes.cpp',
      'unit/server/test_dex_perf_model.cpp',
      'unit/server/test_dex_app_perf_model.cpp',
      'unit/server/test_app_perf_compare.cpp',
      'unit/server/test_dex_app_perf_ui.cpp',
      'unit/server/test_network_perf_model.cpp',
      'unit/server/test_spark_fleet_tags.cpp',
      'unit/server/test_guardian_journal_fleet_tags.cpp',
      'unit/server/test_dex_alert_router.cpp',
      'unit/server/test_dex_blast_radius.cpp',
      'unit/server/test_guardian_form_render.cpp',
      'unit/server/test_heartbeat_ingestion.cpp',
      'unit/server/test_compliance_eval.cpp',
      'unit/server/test_cel_eval.cpp',
      'unit/server/test_custom_properties_store.cpp',
      'unit/server/test_notification_store.cpp',
      'unit/server/test_webhook_store.cpp',
      'unit/server/test_migration_runner.cpp',
      'unit/server/test_rate_limiter.cpp',
      'unit/server/test_cert_reloader.cpp',
      'unit/server/test_x509_ca.cpp',
      'unit/server/test_ca_store.cpp',
      'unit/server/test_ca_routes.cpp',
      'unit/server/test_kek_routes.cpp', # #2395 track D — KEK rotation REST surface
      'unit/server/test_key_provider.cpp',
      'unit/server/test_default_certs.cpp',
      'unit/server/test_mcp_server.cpp',
      'unit/server/test_mcp_session.cpp',
      'unit/server/test_mcp_stream.cpp',
      'unit/server/test_mcp_stream_bridge.cpp',
      'unit/server/test_sse_saturation.cpp',
      'unit/server/test_mcp_transport.cpp',
      'unit/server/test_process_health.cpp',
      'unit/server/test_patch_manager.cpp',
      'unit/server/test_inventory_eval.cpp',
      'unit/server/test_execution_statistics.cpp',
      'unit/server/test_device_token_store.cpp',
      'unit/server/test_device_token_rejection.cpp',
      'unit/server/test_agent_registry_token_revocation.cpp',
      'unit/server/test_software_deployment_store.cpp',
      'unit/server/test_license_store.cpp',
      'unit/server/test_rest_api_t2.cpp',
      'unit/server/test_rest_api_tokens.cpp',
      'unit/server/test_rest_api_events.cpp',
      'unit/server/test_rest_software_packages.cpp',
      'unit/server/test_rest_inventory_software.cpp',
      'unit/server/test_rest_sessions.cpp',
      'unit/server/test_rest_guaranteed_state.cpp',
      'unit/server/test_discovery_routes.cpp', # A2 discovery surface (Issue 17.1)
      'unit/server/test_security_headers.cpp',
      'unit/server/test_on_behalf_guard.cpp', # ADR-1005 PR 1.1 reserved-key guard
      'unit/server/test_principal_quota.cpp', # PR 4.4 per-principal quota cap primitive
      'unit/server/test_principal_quota_denial.cpp', # PR 4.4 dual-transport classifier lock (#2291)
      'unit/server/test_principal_quota_chokepoint.cpp', # PR 4.4 chokepoint wiring coverage
      'unit/server/test_grpc_on_behalf_enforce.cpp', # ADR-1005 PR 1.1 gRPC end-to-end enforcement
      'unit/server/test_principal_class.cpp', # ADR-1005 PR 1.2 actor-class label
      'unit/server/test_insecure_tls_gate.cpp',
      'unit/server/test_settings_routes_users.cpp',
      'unit/server/test_settings_routes_dex_alerts.cpp',
      'unit/server/test_plugin_signing_helpers.cpp',
      'unit/server/test_store_errors.cpp',
      'unit/server/test_static_js_bundle.cpp',
      'unit/server/test_result_parsing.cpp',
      'unit/server/test_visualization_engine.cpp',
      'unit/server/test_rest_visualization.cpp',
      'unit/server/test_response_templates_engine.cpp',
      'unit/server/test_rest_response_templates.cpp',
      'unit/server/test_offload_target_store.cpp',
      'unit/server/test_rest_offload_targets.cpp',
      'unit/server/test_fleet_topology_store.cpp',
      'unit/server/test_viz_routes.cpp',
      'unit/server/test_product_pack_store.cpp',
      'unit/server/test_pg_raii.cpp',
      'unit/server/test_pg_pool.cpp',
      'unit/server/test_pg_migration_runner.cpp',
      'unit/server/test_pg_hardening.cpp',
      'unit/server/test_pg_template_cleanup.cpp',
      'unit/server/test_offline_endpoint_store.cpp',
      'unit/server/test_secret_codec.cpp',
      'unit/server/test_software_inventory_store.cpp',
      'unit/server/test_vuln_finding_store.cpp',
      'unit/server/test_vuln_finding_store_adversarial.cpp',
      'unit/server/test_product_normalize.cpp',
      'unit/server/test_product_registry_store.cpp',
      'unit/server/test_software_licensing_store.cpp',
      'unit/server/test_software_licensing_ingestion.cpp',
      'unit/server/test_device_inventory_store.cpp',
      'unit/server/test_agent_decommission.cpp',
      'unit/server/test_app_perf_daily_store.cpp',
      'unit/server/test_app_perf_ingestion.cpp',
      'unit/server/test_app_perf_rollup.cpp',
      'unit/server/test_app_perf_group_reader.cpp',
      'unit/server/test_app_perf_cohort_reader.cpp',
      'unit/server/test_pg_array.cpp',
      'unit/server/test_scim_store.cpp',
      'unit/server/test_scim_store_pg.cpp',
      'unit/server/test_scim_json.cpp',
      'unit/server/test_scim_routes.cpp',
    ),
    include_directories: [
      include_directories('../server/core/src'),  # private headers (nvd_db.hpp, web_utils.hpp, etc.)
      # C3b cross-check: test_guardian_resilience_schema.cpp includes the agent's
      # resilience_strategy.hpp for resilience_keys to assert the server param-spec
      # table matches the agent parser (contract G9 drift guard). Header-only
      # constexpr — no link to yuzu_agent_core, just the include path.
      include_directories('../agents/core/include'),
      # Tag-key pins: test_spark_fleet_tags.cpp includes the agent's
      # spark_heartbeat.hpp (emit_spark_heartbeat_tags), and
      # test_guardian_journal_fleet_tags.cpp includes guardian_journal_heartbeat.hpp
      # (emit_guardian_journal_heartbeat_tags), each asserting the agent's actual
      # emitted keys equal the matching server-side *_fleet_tags.hpp table - a full
      # writer↔reader compile/run bind, no silent zero-reporting drift. Header-only
      # templates - no link to yuzu_agent_core, just the include path.
      #
      # CONSTRAINT (governance Gate-3 architect). This puts 47 PRIVATE agent headers on
      # the include path of every server test TU. It is safe TODAY only because there is
      # zero CASE-INSENSITIVE basename collision (APFS/NTFS resolve case-insensitively,
      # so a Linux-only case-sensitive check under-detects) between agents/core/src/*.hpp
      # and server/core/src/*.hpp,
      # and because server/core/src is listed FIRST so it would win a future clash. A
      # same-named header added on both sides later SILENTLY SHADOWS — there is no
      # diagnostic. Do NOT add a private-agent-src include for any other target, and do
      # NOT solve a future collision by having server PRODUCTION code include an agent
      # header: that would be an upward dependency edge (server → agent), which the build
      # graph does not have and must not gain. The durable fix is to hoist the shared tag
      # keys into one source of truth. NOTE THE SCOPE: that hoist is triggered by spark's
      # rung 2, "when the wire contract changes anyway" - but the GUARDIAN JOURNAL keys
      # are not part of that wire-contract change, so a rung-2 hoist sweeping only spark
      # would leave the 22 yuzu.guardian_journal_* literals behind while this comment
      # still read as though it covered them. Both key families must move together; the
      # journal side must be added to #2298's cutover-gate list (not yet filed there as of
      # this commit). Concrete target when it
      # happens: a hand-written header carried by proto/meson.build's
      # yuzu_proto_headers_dep - a DOWNWARD edge for both server and agent, no cycle, no
      # new build-graph node. NOT sdk/, which is the public plugin ABI surface.
      include_directories('../agents/core/src'),
    ],
    # httplib.h is header-only and its Client/Server class layout depends on
    # CPPHTTPLIB_OPENSSL_SUPPORT — yuzu_server_core compiles every TU with
    # https_cpp_args, so any test TU that includes <httplib.h> (directly or
    # via test_route_sink.hpp / workflow_routes.hpp) MUST match or MSVC emits
    # C4743 (vtable size mismatch) and the linked binary crashes with
    # STATUS_STACK_BUFFER_OVERRUN (0xC0000409) on first httplib::Server /
    # ::Client construction. LISTEN_BACKLOG kept aligned for completeness.
    #
    # YUZU_TEST_ENABLE_PG exposes the PostgresTestDb fixture in
    # test_helpers.hpp — only the server suite links libpq, so the guard
    # keeps the agent/tar suites (which share the header) libpq-free.
    cpp_args: https_cpp_args + test_partial_init_args +
              ['-DCPPHTTPLIB_LISTEN_BACKLOG=128', '-DYUZU_TEST_ENABLE_PG'],
    # Server unit tests #include <openssl/...> directly (e.g.
    # test_plugin_signing_helpers.cpp). yuzu_server_core_dep does not
    # propagate the OpenSSL include path, so declare it explicitly here
    # rather than relying on the transitive declare_dependency carry —
    # makes the dependency visible to Meson's graph and survives a
    # future static-merge refactor of yuzu_server_core (governance
    # hardening round 1, qe-B2).
    dependencies: [yuzu_server_core_dep, catch2_dep, dependency('openssl', required: true, include_type: 'system')],
  )
  # Sharded 2026-07-13 (#2092 — the split the 2026-07-12 recalibration comment
  # promised): test() entries over the SAME binary, partitioned by Catch2
  # tag filter. '~[pg]' is everything not Postgres-backed; '[pg]' is the
  # Postgres-substrate cases. The complement is exact: every Postgres-touching
  # test carries [pg] and no [pg] test is hidden ([.]), so the shards partition
  # the visible case set with nothing lost or run twice (guard: --list-tests
  # counts, N_all == N_nonpg + N_pg).
  #
  # RE-SHARDED 2026-07-16 (auth.db -> Postgres migration, ADR-0006): that cutover
  # moved the entire auth/scim/mfa/route surface onto Postgres, ~doubling [pg]
  # from ~330 to ~660 cases. Two failure modes surfaced and are fixed here:
  #   (1) ~180 newly-Postgres route/store tests had been left UNTAGGED, so they
  #       ran in the ~[pg] shard — a partition violation (they only skip-not-run
  #       there when a DSN is absent; with a DSN, e.g. every CI leg, they RUN and
  #       inflate ~[pg]). Empirical fix: every case that skips a no-DSN run via
  #       the PG helper now carries [pg] (verified: ~[pg] no-DSN POSTGRES-skips == 0).
  #   (2) the single ~660-case [pg] entry blew the 900s budget on the slow
  #       GHA-hosted macos-15 runner. [pg] is now SPLIT into two balanced shards
  #       by a count-based discriminator (per-case CREATE DATABASE ... TEMPLATE
  #       clone cost is near-uniform, so case-count tracks wall time):
  #         shard A = [pg] AND (routes|store|token)   ~321 cases
  #         shard B = [pg] AND NOT (routes|store|token) ~338 cases
  #       Exact-partition guard: N([pg]) == N(A) + N(B). meson runs all three
  #       entries in parallel, so suite wall time is max(shard).
  # Budgets are sized for the *contended* Wee Tam box, not per-op cost:
  # ~[pg] = 600s (quiet Windows ~231s); each [pg] half = 600s (each is ~half the
  # old 900s full-[pg] load, so 600s is generous even under Wee Tam c4 contention).
  #
  # HISTORY / do-not-regress: [pg] was raised 600->900 on 2026-07-14 when the
  # fsync-bound CREATE DATABASE ... TEMPLATE + DROP DATABASE WITH (FORCE) (~20x
  # costlier on Windows) hit exactly-600s TIMEOUTs. The two fixes that pattern
  # blamed have since LANDED and are verified live on Wee Tam (2026-07-21):
  # per-agent Postgres (#2094; 4 clusters :5433-:5436) AND durability-off
  # (fsync/synchronous_commit/full_page_writes; scripts/ci/ensure-postgres.sh +
  # deploy/windows/Provision-Windows-Runner.ps1). Do NOT "return [pg] to 600":
  # the residual is NOT Postgres durability — it is box-wide concurrency
  # contention. Wee Tam runs 4 CCD-pinned runners on ONE host; affinity partitions
  # cores but not DRAM bandwidth, the shared disk, or the Defender minifilter, so
  # every heavy suite's wall time scales with how many Windows jobs share the box
  # (measured server ~[pg]: c0 289s -> c4 603s; [pg] up to 816s at c4). The real
  # fix is the Test-phase concurrency gate in ci.yml (scripts/ci/with-test-slot.sh
  # caps concurrent heavy Windows test phases per box), NOT a bigger budget —
  # raising a number just moves the cliff. A real hang is still bounded by the
  # job-level timeouts (90-120 min in ci.yml, 60 min in nightly.yml). The Catch2
  # cleanup/sweep listener (test_pg_template_cleanup.cpp) fires in all shards —
  # idempotent, harmless without a DSN. Constraints the shards must keep:
  #   - only tag-filter specs may appear in args (flake-retry.py strips
  #     positional tag specs before an isolated case retry — Catch2 ORs
  #     positional specs). Each [pg] half is ONE comma-OR spec (Catch2 ORs
  #     inside a single arg; multiple positional args would AND, not OR);
  #   - no entry name may be a substring of another (flake-retry maps
  #     meson-junit names by longest substring match) — 'shard A'/'shard B'
  #     and 'server unit tests' are pairwise non-substring.
  # If a quiet leg pushes a shard past the #2093 80%-of-budget warning, the first
  # move is the concurrency gate / per-op cost (Defender TEMP exclusion, RAM disk),
  # then split or rebalance — raising the number is the last resort, not the first.
  test('server unit tests', server_test_exe, args: ['~[pg]'], suite: 'server', timeout: 600)
  test('server pg unit tests shard A', server_test_exe,
       args: ['[pg][routes],[pg][store],[pg][token]'], suite: 'server', timeout: 600)
  test('server pg unit tests shard B', server_test_exe,
       args: ['[pg]~[routes]~[store]~[token]'], suite: 'server', timeout: 600)
endif

# ── Proto codegen tests ────────────────────────────────────────────────────
_python3_test = find_program('python3', 'python')
test('proto gen_proto version check',
  _python3_test,
  args: [files('test_gen_proto_version.py')],
  suite: 'proto',
  timeout: 30,
)

# ── Repo hygiene tests ─────────────────────────────────────────────────────
test('changelog order',
  _python3_test,
  args: [files('test_changelog_order.py')],
  suite: 'docs',
  timeout: 10,
)

# Tracker close-automation regression corpus (ADR-3001 A1 §11-§12): the frozen
# parser fixtures (incl. PR #1711, the canonical negated close) + the decision
# ladder's never-close/fail-closed/cap contracts. No network. scripts/ changes
# always run the heavy platform jobs, so meson coverage alone is sufficient.
test('close automation logic',
  _python3_test,
  args: [files('test_close_automation.py')],
  suite: 'docs',
  timeout: 30,
)

# flake-retry's pure-logic selftest (tag-spec surgery, suite matching, junit
# parsing, budget rows). Wired here (#2092) so the shard-retry contract the
# server entries above rely on is enforced on every platform, not just when
# someone remembers to run it by hand.
test('flake-retry selftest',
  _python3_test,
  args: [files('../scripts/ci/flake-retry.py'), '--selftest'],
  suite: 'docs',
  timeout: 30,
)

# Issue-lifecycle hygiene (ADR-3001 A1): CLAUDE.md character budget,
# do-not-close.txt parses clean (the never-close guard every automated close
# path reads), and issue-standard.md keeps its never-close section.
test('issue lifecycle docs',
  _python3_test,
  args: [files('test_issue_docs.py')],
  suite: 'docs',
  timeout: 10,
)

# Runner-local CI telemetry contract: v2->v3 migration preserves history,
# GitHub reruns remain distinct, and Meson suite durations/timeouts plus known
# flake recoveries land in the persistent per-runner test-runs.db.
test('ci telemetry selftest',
  _python3_test,
  args: [files('../scripts/ci/test_ci_telemetry.py')],
  suite: 'docs',
  timeout: 30,
)

# The nightly TSan gdb capture's pure-logic selftest (#1038): junit -> failing
# entries, testlog.txt -> per-entry Catch2 seed, introspect -> binary + args, and
# the cancelled-path "which entry never finished" inference. It reuses
# flake-retry.py's junit-name -> introspected-entry mapping rather than keeping a
# second copy, so the shard-naming contract documented above now has two
# consumers — and this selftest is what makes a break in it loud. Wired here for
# the same reason flake-retry's is: the alternative to failing in `meson test` is
# failing silently at 06:00 UTC, in the one nightly that needed a stack trace.
test('tsan-gdb-capture selftest',
  _python3_test,
  args: [files('../scripts/ci/tsan-gdb-capture.py'), '--selftest'],
  suite: 'docs',
  timeout: 30,
)
