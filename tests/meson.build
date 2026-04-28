if host_os == 'windows'
  # Same #375-class IMPORTED_LOCATION_RELEASE problem as protobuf/grpc/cli11
  # in the top-level meson.build: meson's cmake dep translator picks
  # lib/Catch2.lib (release CRT) for both debug and release consumers,
  # so a debug test binary linking with /MDd against release Catch2.lib
  # trips dozens of LNK2038 _ITERATOR_DEBUG_LEVEL mismatches. Hand-wire
  # to the buildtype-specific _vcpkg_lib_win directory established in
  # the top-level Windows block. Catch2's vcpkg port keeps the same
  # name in both lib/ and debug/lib/ — no `d` suffix.
  _cxx_tests = meson.get_compiler('cpp')
  _libcatch2     = _cxx_tests.find_library('Catch2',     dirs: [_vcpkg_lib_win], required: true)
  _libcatch2main = _cxx_tests.find_library('Catch2Main', dirs: [_vcpkg_lib_win], required: true)
  catch2_dep = declare_dependency(
    include_directories: include_directories(_vcpkg_include_win_rel, is_system: true),
    dependencies: [_libcatch2main, _libcatch2],
  )
else
  catch2_dep = dependency('Catch2', modules: ['Catch2::Catch2WithMain'], method: 'cmake', required: true, include_type: 'system')
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

agent_test_exe = executable(
  'yuzu_agent_tests',
  files(
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
    'unit/test_new_plugins.cpp',
  ),
  include_directories: [
    include_directories('../agents/plugins/vuln_scan/src'),  # cve_rules.hpp
  ],
  dependencies: [yuzu_agent_core_dep, yuzu_sdk_dep, agent_test_proto_dep, nlohmann_dep, catch2_dep],
  # Ensure the fixture plugin is built before the test runs so the lookup
  # inside test_plugin_loader.cpp finds it under MESON_BUILD_ROOT/tests/.
  link_depends: reserved_name_fixture_plugin,
)
test(
  'agent unit tests',
  agent_test_exe,
  suite: 'agent',
  timeout: 240,
  depends: reserved_name_fixture_plugin,
)

# ── TAR plugin unit tests ────────────────────────────────────────────────────
tar_test_deps = [yuzu_agent_core_dep, yuzu_sdk_dep, nlohmann_dep, spdlog_dep, sqlite3_dep, catch2_dep]

tar_test_exe = executable(
  'yuzu_tar_tests',
  files(
    'unit/test_tar_diff.cpp',
    'unit/test_tar_store.cpp',
    'unit/test_tar_schema_registry.cpp',
    'unit/test_tar_warehouse.cpp',
    'unit/test_tar_aggregator.cpp',
    '../agents/plugins/tar/src/tar_db.cpp',
    '../agents/plugins/tar/src/tar_diff.cpp',
    '../agents/plugins/tar/src/tar_schema_registry.cpp',
    '../agents/plugins/tar/src/tar_aggregator.cpp',
  ),
  include_directories: [
    include_directories('../agents/plugins/tar/src'),
  ],
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
      'unit/server/test_auto_approve.cpp',
      'unit/server/test_nvd.cpp',
      'unit/server/test_update_registry.cpp',
      'unit/server/test_https_config.cpp',
      'unit/server/test_response_store.cpp',
      'unit/server/test_audit_store.cpp',
      'unit/server/test_tag_store.cpp',
      'unit/server/test_scope_engine.cpp',
      'unit/server/test_web_utils.cpp',
      'unit/server/test_analytics_event.cpp',
      'unit/server/test_agent_health_store.cpp',
      'unit/server/test_instruction_store.cpp',
      'unit/server/test_execution_tracker.cpp',
      'unit/server/test_approval_manager.cpp',
      'unit/server/test_schedule_engine.cpp',
      'unit/server/test_rbac_store.cpp',
      'unit/server/test_oidc_provider.cpp',
      'unit/server/test_error_codes.cpp',
      'unit/server/test_result_envelope.cpp',
      'unit/server/test_concurrency_manager.cpp',
      'unit/server/test_legacy_shim.cpp',
      'unit/server/test_management_group_store.cpp',
      'unit/server/test_api_token_store.cpp',
      'unit/server/test_quarantine_store.cpp',
      'unit/server/test_policy_store.cpp',
      'unit/server/test_guaranteed_state_store.cpp',
      'unit/server/test_compliance_eval.cpp',
      'unit/server/test_cel_eval.cpp',
      'unit/server/test_custom_properties_store.cpp',
      'unit/server/test_notification_store.cpp',
      'unit/server/test_webhook_store.cpp',
      'unit/server/test_migration_runner.cpp',
      'unit/server/test_rate_limiter.cpp',
      'unit/server/test_cert_reloader.cpp',
      'unit/server/test_mcp_server.cpp',
      'unit/server/test_process_health.cpp',
      'unit/server/test_patch_manager.cpp',
      'unit/server/test_inventory_eval.cpp',
      'unit/server/test_execution_statistics.cpp',
      'unit/server/test_device_token_store.cpp',
      'unit/server/test_software_deployment_store.cpp',
      'unit/server/test_license_store.cpp',
      'unit/server/test_rest_api_t2.cpp',
      'unit/server/test_rest_api_tokens.cpp',
      'unit/server/test_rest_guaranteed_state.cpp',
      'unit/server/test_security_headers.cpp',
      'unit/server/test_insecure_tls_gate.cpp',
      'unit/server/test_settings_routes_users.cpp',
      'unit/server/test_store_errors.cpp',
      'unit/server/test_static_js_bundle.cpp',
      'unit/server/test_visualization_engine.cpp',
      'unit/server/test_rest_visualization.cpp',
    ),
    include_directories: [
      include_directories('../server/core/src'),  # private headers (nvd_db.hpp, web_utils.hpp, etc.)
    ],
    dependencies: [yuzu_server_core_dep, catch2_dep],
  )
  test('server unit tests', server_test_exe, suite: 'server', timeout: 120)
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
