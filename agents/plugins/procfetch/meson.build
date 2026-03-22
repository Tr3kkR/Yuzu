procfetch_deps = [yuzu_sdk_dep, yuzu_agent_core_dep]

# Windows: bcrypt.lib linked via #pragma comment(lib) in source
if host_machine.system() != 'windows'
  openssl_dep = dependency('openssl', required: true)
  procfetch_deps += openssl_dep
endif

shared_library(
  'procfetch',
  files('src/procfetch_plugin.cpp'),
  name_prefix: '',
  dependencies: procfetch_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
