shared_library(
  'registry',
  files('src/registry_plugin.cpp'),
  name_prefix: '',
  dependencies: [yuzu_sdk_dep, yuzu_agent_core_dep, spdlog_dep],
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
