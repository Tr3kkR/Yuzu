device_identity_deps = [yuzu_sdk_dep, yuzu_agent_core_dep]
# Windows: netapi32.lib, secur32.lib linked via #pragma comment(lib) in source

shared_library(
  'device_identity',
  files('src/device_identity_plugin.cpp'),
  name_prefix: '',
  dependencies: device_identity_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
