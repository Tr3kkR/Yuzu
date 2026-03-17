# Platform-specific crypto for auth module
if host_machine.system() == 'windows'
  bcrypt_dep = cxx.find_library('bcrypt')
  auth_crypto_deps = [bcrypt_dep]
else
  openssl_dep = dependency('openssl', required: true)
  auth_crypto_deps = [openssl_dep]
endif

# OpenSSL for HTTPS (cpp-httplib SSLServer support)
# On Linux/macOS, openssl_dep is already declared above.
# On Windows, OpenSSL is available transitively via gRPC/vcpkg.
if host_machine.system() == 'windows'
  openssl_dep = dependency('openssl', method: 'cmake', modules: ['OpenSSL::SSL', 'OpenSSL::Crypto'], required: false)
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

sqlite3_dep = dependency('sqlite3', required: false)
if not sqlite3_dep.found()
  sqlite3_dep = dependency('unofficial-sqlite3', method: 'cmake', modules: ['unofficial::sqlite3::sqlite3'], required: false)
endif
if not sqlite3_dep.found()
  sqlite3_dep = cxx.find_library('sqlite3')
endif
nlohmann_json_dep = dependency('nlohmann_json', required: true)

yuzu_server_core_lib = static_library(
  'yuzu_server_core',
  files(
    'src/server.cpp',
    'src/auth.cpp',
    'src/auto_approve.cpp',
    'src/dashboard_ui.cpp',
    'src/chargen_ui.cpp',
    'src/procfetch_ui.cpp',
    'src/login_ui.cpp',
    'src/settings_ui.cpp',
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
    'src/instruction_store.cpp',
    'src/execution_tracker.cpp',
    'src/approval_manager.cpp',
    'src/schedule_engine.cpp',
    'src/help_ui.cpp',
    'src/instruction_ui.cpp',
  ),
  include_directories: ['include'],
  cpp_args: https_cpp_args + (cxx.get_id() == 'msvc' ? ['/bigobj'] : []),
  dependencies: [yuzu_sdk_dep, yuzu_proto_dep, spdlog_dep, httplib_dep,
                 sqlite3_dep, nlohmann_json_dep] + auth_crypto_deps + https_deps,
)

yuzu_server_core_dep = declare_dependency(
  link_with: yuzu_server_core_lib,
  include_directories: include_directories('include'),
  dependencies: [yuzu_sdk_dep, yuzu_proto_dep, spdlog_dep, httplib_dep,
                 sqlite3_dep, nlohmann_json_dep] + auth_crypto_deps + https_deps,
)

executable(
  'yuzu-server',
  files('src/main.cpp'),
  dependencies: [yuzu_server_core_dep, cli11_dep] + auth_crypto_deps,
  install: true,
)
