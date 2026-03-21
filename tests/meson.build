catch2_dep = dependency('Catch2', modules: ['Catch2::Catch2WithMain'], method: 'cmake', required: true)

# ── Agent unit tests ──────────────────────────────────────────────────────────
agent_test_exe = executable(
  'yuzu_agent_tests',
  files(
    'unit/test_plugin_loader.cpp',
    'unit/test_sdk_utilities.cpp',
    'unit/test_temp_file.cpp',
    'unit/test_updater.cpp',
    'unit/test_filesystem_read.cpp',
    'unit/test_string_utils.cpp',
    'unit/test_vuln_rules.cpp',
    'unit/test_metrics.cpp',
    'unit/test_metrics_perf.cpp',
    'unit/test_kv_store.cpp',
    'unit/test_trigger_engine.cpp',
    'unit/test_new_plugins.cpp',
  ),
  include_directories: [
    include_directories('../agents/plugins/vuln_scan/src'),  # cve_rules.hpp
  ],
  dependencies: [yuzu_agent_core_dep, yuzu_sdk_dep, nlohmann_dep, catch2_dep],
)
test('agent unit tests', agent_test_exe)

# ── TAR plugin unit tests ────────────────────────────────────────────────────
tar_test_deps = [yuzu_agent_core_dep, yuzu_sdk_dep, nlohmann_dep, spdlog_dep, sqlite3_dep, catch2_dep]

tar_test_exe = executable(
  'yuzu_tar_tests',
  files(
    'unit/test_tar_diff.cpp',
    'unit/test_tar_store.cpp',
    '../agents/plugins/tar/src/tar_db.cpp',
    '../agents/plugins/tar/src/tar_diff.cpp',
  ),
  include_directories: [
    include_directories('../agents/plugins/tar/src'),
  ],
  dependencies: tar_test_deps,
)
test('tar unit tests', tar_test_exe)

# ── Server unit tests ─────────────────────────────────────────────────────────
if build_server
  server_test_exe = executable(
    'yuzu_server_tests',
    files(
      'unit/server/test_auth.cpp',
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
      'unit/server/test_compliance_eval.cpp',
      'unit/server/test_custom_properties_store.cpp',
      'unit/server/test_notification_store.cpp',
      'unit/server/test_webhook_store.cpp',
    ),
    include_directories: [
      include_directories('../server/core/src'),  # private headers (nvd_db.hpp, web_utils.hpp, etc.)
    ],
    dependencies: [yuzu_server_core_dep, catch2_dep],
  )
  test('server unit tests', server_test_exe, timeout: 120)
endif
