# Platform-specific crypto for auth module
# Windows: bcrypt.lib + winhttp.lib linked via #pragma comment(lib) in source
if host_machine.system() == 'windows'
  auth_crypto_deps = []
else
  openssl_dep = dependency('openssl', required: true, include_type: 'system')
  auth_crypto_deps = [openssl_dep]
endif

# OpenSSL for HTTPS (cpp-httplib SSLServer support)
# On Linux/macOS, openssl_dep is already declared above.
# On Windows, OpenSSL is available transitively via gRPC/vcpkg.
if host_machine.system() == 'windows'
  openssl_dep = dependency('openssl', method: 'cmake', modules: ['OpenSSL::SSL', 'OpenSSL::Crypto'], required: false, include_type: 'system')
  if not openssl_dep.found()
    # Fallback: try pkg-config or find_library
    _ssl_lib = cxx.find_library('libssl', required: false)
    _crypto_lib = cxx.find_library('libcrypto', required: false)
    if _ssl_lib.found() and _crypto_lib.found()
      openssl_dep = declare_dependency(dependencies: [_ssl_lib, _crypto_lib])
    else
      openssl_dep = disabler()
    endif
  endif
endif

https_cpp_args = []
https_deps = []
if not is_disabler(openssl_dep) and openssl_dep.found()
  https_cpp_args = ['-DCPPHTTPLIB_OPENSSL_SUPPORT']
  https_deps = [openssl_dep]
endif

sqlite3_dep = dependency('sqlite3', required: false, include_type: 'system')
if not sqlite3_dep.found()
  sqlite3_dep = dependency('unofficial-sqlite3', method: 'cmake', modules: ['unofficial::sqlite3::sqlite3'], required: false, include_type: 'system')
endif
if not sqlite3_dep.found()
  sqlite3_dep = cxx.find_library('sqlite3')
endif
nlohmann_json_dep = dependency('nlohmann_json', required: true, include_type: 'system')

# RE2 for linear-time regex (replaces std::regex to prevent ReDoS)
re2_dep = dependency('re2', method: 'cmake', modules: ['re2::re2'], required: false, include_type: 'system')
if not re2_dep.found()
  re2_dep = dependency('re2', required: false, include_type: 'system')
endif
if not re2_dep.found()
  re2_dep = cxx.find_library('re2')
endif

yuzu_server_core_lib = static_library(
  'yuzu_server_core',
  files(
    'src/server.cpp',
    'src/agent_registry.cpp',
    'src/agent_service_impl.cpp',
    'src/gateway_service_impl.cpp',
    'src/auth.cpp',
    'src/auth_routes.cpp',
    'src/auto_approve.cpp',
    'src/dashboard_ui.cpp',
    'src/chargen_ui.cpp',
    'src/procfetch_ui.cpp',
    'src/login_ui.cpp',
    'src/settings_ui.cpp',
    'src/settings_routes.cpp',
    'src/nvd_db.cpp',
    'src/nvd_client.cpp',
    'src/nvd_sync.cpp',
    'src/update_registry.cpp',
    'src/response_store.cpp',
    'src/audit_store.cpp',
    'src/tag_store.cpp',
    'src/scope_engine.cpp',
    'src/analytics_event_store.cpp',
    'src/analytics_sinks.cpp',
    'src/data_export.cpp',
    'src/instruction_db_pool.cpp',
    'src/instruction_store.cpp',
    'src/execution_tracker.cpp',
    'src/approval_manager.cpp',
    'src/schedule_engine.cpp',
    'src/help_ui.cpp',
    'src/instruction_ui.cpp',
    'src/rbac_store.cpp',
    'src/oidc_provider.cpp',
    'src/error_codes.cpp',
    'src/result_envelope.cpp',
    'src/concurrency_manager.cpp',
    'src/legacy_shim.cpp',
    'src/management_group_store.cpp',
    'src/api_token_store.cpp',
    'src/quarantine_store.cpp',
    'src/policy_store.cpp',
    'src/runtime_config_store.cpp',
    'src/custom_properties_store.cpp',
    'src/mcp_server.cpp',
    'src/rest_api_v1.cpp',
    'src/compliance_routes.cpp',
    'src/dashboard_routes.cpp',
    'src/workflow_routes.cpp',
    'src/notification_routes.cpp',
    'src/webhook_routes.cpp',
    'src/discovery_routes.cpp',
    'src/compliance_ui.cpp',
    'src/cel_eval.cpp',
    'src/compliance_eval.cpp',
    'src/workflow_engine.cpp',
    'src/product_pack_store.cpp',
    'src/inventory_store.cpp',
    'src/notification_store.cpp',
    'src/webhook_store.cpp',
    'src/directory_sync.cpp',
    'src/patch_manager.cpp',
    'src/deployment_store.cpp',
    'src/discovery_store.cpp',
    'src/inventory_eval.cpp',
    'src/device_token_store.cpp',
    'src/software_deployment_store.cpp',
    'src/license_store.cpp',
    'src/topology_ui.cpp',
    'src/statistics_ui.cpp',
    'src/css_bundle.cpp',
    'src/static_js_bundle.cpp',
    'src/icons_svg.cpp',
    'src/migration_runner.cpp',
    'src/rate_limiter.cpp',
    'src/cert_reloader.cpp',
    'src/security_headers.cpp',
  ),
  include_directories: ['include'],
  cpp_args: https_cpp_args + ['-DCPPHTTPLIB_LISTEN_BACKLOG=128'] + (cxx.get_id() == 'msvc' ? ['/bigobj'] : []),
  dependencies: [yuzu_sdk_dep, yuzu_proto_dep, spdlog_dep, httplib_dep,
                 sqlite3_dep, nlohmann_json_dep, re2_dep] + auth_crypto_deps + https_deps,
)

yuzu_server_core_dep = declare_dependency(
  link_with: yuzu_server_core_lib,
  include_directories: include_directories('include'),
  dependencies: [yuzu_sdk_dep, yuzu_proto_dep, spdlog_dep, httplib_dep,
                 sqlite3_dep, nlohmann_json_dep, re2_dep] + auth_crypto_deps + https_deps,
)

executable(
  'yuzu-server',
  files('src/main.cpp'),
  dependencies: [yuzu_server_core_dep, cli11_dep] + auth_crypto_deps,
  install: true,
)
