hardware_deps = [yuzu_sdk_dep, yuzu_agent_core_dep]
# Windows: wbemuuid.lib, ole32.lib, oleaut32.lib linked via #pragma comment(lib) in source

shared_library(
  'hardware',
  files('src/hardware_plugin.cpp'),
  name_prefix: '',
  dependencies: hardware_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
