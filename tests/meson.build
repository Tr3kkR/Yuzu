catch2_dep = dependency('Catch2', modules: ['Catch2::Catch2WithMain'], method: 'cmake', required: true)

# ── Agent unit tests ──────────────────────────────────────────────────────────
agent_test_exe = executable(
  'yuzu_agent_tests',
  files('unit/test_plugin_loader.cpp', 'unit/test_sdk_utilities.cpp', 'unit/test_temp_file.cpp', 'unit/test_updater.cpp',
        'unit/test_filesystem_read.cpp'),
  dependencies: [yuzu_agent_core_dep, yuzu_sdk_dep, nlohmann_dep, catch2_dep],
)
test('agent unit tests', agent_test_exe)

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
    ),
    include_directories: [
      include_directories('../server/core/src'),  # private headers (nvd_db.hpp, response_store.hpp, etc.)
    ],
    dependencies: [yuzu_server_core_dep, catch2_dep],
  )
  test('server unit tests', server_test_exe)
endif
