wol_deps = [yuzu_sdk_dep, yuzu_agent_core_dep]
# Windows: ws2_32.lib linked via #pragma comment(lib) in source

shared_library(
  'wol',
  files('src/wol_plugin.cpp'),
  name_prefix: '',
  dependencies: wol_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
