# Platform-specific crypto for auth module
if host_machine.system() == 'windows'
  bcrypt_dep = cxx.find_library('bcrypt')
  auth_crypto_deps = [bcrypt_dep]
else
  openssl_dep = dependency('openssl', required: true)
  auth_crypto_deps = [openssl_dep]
endif

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
  ),
  include_directories: ['include'],
  dependencies: [yuzu_sdk_dep, yuzu_proto_dep, spdlog_dep, httplib_dep] + auth_crypto_deps,
)

yuzu_server_core_dep = declare_dependency(
  link_with: yuzu_server_core_lib,
  include_directories: include_directories('include'),
  dependencies: [yuzu_sdk_dep, yuzu_proto_dep, spdlog_dep, httplib_dep],
)

executable(
  'yuzu-server',
  files('src/main.cpp'),
  dependencies: [yuzu_server_core_dep, cli11_dep] + auth_crypto_deps,
  install: true,
)
