users_deps = [yuzu_sdk_dep, yuzu_agent_core_dep]
# Windows: wtsapi32.lib, netapi32.lib linked via #pragma comment(lib) in source

shared_library(
  'users',
  files('src/users_plugin.cpp'),
  name_prefix: '',
  dependencies: users_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
