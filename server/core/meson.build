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

# Build-time embed of vendored ECharts into a generated .cpp containing
# chunked raw string literals (sliced to fit MSVC's 16,380-byte limit on
# raw string literals — error C2026). Symbol: kEChartsJs.
echarts_embed = custom_target(
  'echarts_js_bundle',
  input: 'vendor/echarts.min.js',
  output: 'echarts_js_bundle.cpp',
  command: [
    find_program('python3', 'python'),
    files('scripts/embed_js.py'),
    '@INPUT@',
    '@OUTPUT@',
    'EChartsJs',
  ],
)

# Build-time embed of the Yuzu Design System CSS bundle. The source
# kYuzuCss exceeded MSVC's 16,380-byte raw-string-literal limit (C2026)
# after the design-token expansion. Chunking into ~14 KB
# fragments concatenated at static-init time keeps every chunk under
# the limit. Symbol: kYuzuCss (std::string).
yuzu_css_embed = custom_target(
  'yuzu_css_bundle',
  input: 'static/yuzu.css',
  output: 'yuzu_css_bundle.cpp',
  command: [
    find_program('python3', 'python'),
    files('scripts/embed_js.py'),
    '@INPUT@',
    '@OUTPUT@',
    'YuzuCss',
  ],
)

# Build-time embed of vendored Inter variable webfont as a constexpr
# byte array (woff2 binary; cannot use raw string literals). Symbol:
# kInterVariableWoff2 — std::string_view of the bytes.
inter_embed = custom_target(
  'inter_woff2_bundle',
  input: 'vendor/inter/InterVariable.woff2',
  output: 'inter_woff2_bundle.cpp',
  command: [
    find_program('python3', 'python'),
    files('scripts/embed_binary.py'),
    '@INPUT@',
    '@OUTPUT@',
    'InterVariableWoff2',
  ],
)

# Build-time YAML→JSON conversion for shipped Yuzu content. The
# server iterates kBundledDefinitions / kBundledSets on startup and
# upserts them into the instruction store, so charts are populated
# without operator intervention. Sidesteps yaml-cpp on Windows MSVC
# (#625) by doing the parse at build time with PyYAML.
#
# PyYAML is a hard build dependency: the embedded vector is the only
# path by which shipped InstructionDefinitions reach the server (no
# filesystem fallback at runtime), so a missing PyYAML used to silently
# produce a binary with an empty Instructions tab. Probe at configure
# time so the failure surfaces here rather than mid-compile.
embed_python = find_program('python3', 'python')
_yaml_probe = run_command(embed_python, '-c', 'import yaml', check: false)
if _yaml_probe.returncode() != 0
  error(
    'PyYAML is required to embed shipped InstructionDefinitions but is '
    + 'not importable from ' + embed_python.full_path() + '. '
    + 'Install with `pip install pyyaml` (Linux/macOS) or '
    + '`pacman -S python-yaml` (MSYS2). See CLAUDE.md "Instruction Engine".'
  )
endif

content_embed = custom_target(
  'bundled_content',
  output: 'bundled_content.cpp',
  command: [
    embed_python,
    files('scripts/embed_content.py'),
    meson.project_source_root() / 'content',
    '@OUTPUT@',
  ],
  build_always_stale: true,  # always re-scan content/ for edits
)

yuzu_server_core_lib = static_library(
  'yuzu_server_core',
  [echarts_embed, yuzu_css_embed, inter_embed, content_embed,
  files(
    'src/server.cpp',
    'src/agent_registry.cpp',
    'src/agent_service_impl.cpp',
    'src/gateway_service_impl.cpp',
    'src/auth.cpp',
    'src/auth_db.cpp',
    'src/auth_routes.cpp',
    'src/auto_approve.cpp',
    'src/dashboard_ui.cpp',
    'src/chargen_ui.cpp',
    'src/procfetch_ui.cpp',
    'src/login_ui.cpp',
    'src/settings_ui.cpp',
    'src/settings_routes.cpp',
    'src/plugin_signing_helpers.cpp',
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
    'src/execution_event_bus.cpp',
    'src/approval_manager.cpp',
    'src/schedule_engine.cpp',
    'src/help_ui.cpp',
    'src/instruction_ui.cpp',
    'src/tar_page_ui.cpp',
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
    'src/guaranteed_state_store.cpp',
    'src/runtime_config_store.cpp',
    'src/custom_properties_store.cpp',
    'src/mcp_server.cpp',
    'src/rest_api_v1.cpp',
    'src/compliance_routes.cpp',
    'src/dashboard_routes.cpp',
    'src/workflow_routes.cpp',
    'src/notification_routes.cpp',
    'src/webhook_routes.cpp',
    'src/offload_routes.cpp',
    'src/discovery_routes.cpp',
    'src/compliance_ui.cpp',
    'src/cel_eval.cpp',
    'src/compliance_eval.cpp',
    'src/workflow_engine.cpp',
    'src/product_pack_store.cpp',
    'src/inventory_store.cpp',
    'src/notification_store.cpp',
    'src/webhook_store.cpp',
    'src/offload_target_store.cpp',
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
    # css_bundle.cpp removed in favour of build-time chunked embed (Gate 4
    # cpp-B1: kYuzuCss exceeds MSVC's 16,380-byte raw-string-literal limit).
    # Source CSS lives at server/core/static/yuzu.css; embed_js.py emits
    # yuzu_css_bundle.cpp with the chunked literal pattern.
    'src/static_js_bundle.cpp',
    'src/charts_js_bundle.cpp',
    'src/visualization_engine.cpp',
    'src/response_templates_engine.cpp',
    'src/icons_svg.cpp',
    'src/migration_runner.cpp',
    'src/rate_limiter.cpp',
    'src/cert_reloader.cpp',
    'src/security_headers.cpp',
  )],
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
