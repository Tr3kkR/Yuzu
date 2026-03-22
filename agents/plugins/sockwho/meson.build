sockwho_deps = [yuzu_sdk_dep, yuzu_agent_core_dep]
# Windows: ws2_32.lib, iphlpapi.lib linked via #pragma comment(lib) in source

shared_library(
  'sockwho',
  files('src/sockwho_plugin.cpp'),
  name_prefix: '',
  dependencies: sockwho_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
