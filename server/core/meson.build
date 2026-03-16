# Platform-specific crypto for auth module
if host_machine.system() == 'windows'
  bcrypt_dep = cxx.find_library('bcrypt')
  auth_crypto_deps = [bcrypt_dep]
else
  openssl_dep = dependency('openssl', required: true)
  auth_crypto_deps = [openssl_dep]
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
  ),
  include_directories: ['include'],
  dependencies: [yuzu_sdk_dep, yuzu_proto_dep, spdlog_dep, httplib_dep,
                 sqlite3_dep, nlohmann_json_dep] + auth_crypto_deps,
)

yuzu_server_core_dep = declare_dependency(
  link_with: yuzu_server_core_lib,
  include_directories: include_directories('include'),
  dependencies: [yuzu_sdk_dep, yuzu_proto_dep, spdlog_dep, httplib_dep,
                 sqlite3_dep, nlohmann_json_dep] + auth_crypto_deps,
)

executable(
  'yuzu-server',
  files('src/main.cpp'),
  dependencies: [yuzu_server_core_dep, cli11_dep] + auth_crypto_deps,
  install: true,
)
