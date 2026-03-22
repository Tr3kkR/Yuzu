wifi_deps = [yuzu_sdk_dep, yuzu_agent_core_dep]
# Windows: wlanapi.lib linked via #pragma comment(lib) in source

shared_library(
  'wifi',
  files('src/wifi_plugin.cpp'),
  name_prefix: '',
  dependencies: wifi_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
