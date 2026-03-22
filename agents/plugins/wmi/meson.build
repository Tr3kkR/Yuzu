wmi_deps = [yuzu_sdk_dep, yuzu_agent_core_dep]
# Windows: wbemuuid.lib, ole32.lib, oleaut32.lib linked via #pragma comment(lib) in source

shared_library(
  'wmi',
  files('src/wmi_plugin.cpp'),
  name_prefix: '',
  dependencies: wmi_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
