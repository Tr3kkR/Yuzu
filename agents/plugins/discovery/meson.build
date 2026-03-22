discovery_deps = [yuzu_sdk_dep, yuzu_agent_core_dep]
# Windows: ws2_32.lib, iphlpapi.lib linked via #pragma comment(lib) in source

shared_library(
  'discovery',
  files('src/discovery_plugin.cpp'),
  name_prefix: '',
  dependencies: discovery_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
