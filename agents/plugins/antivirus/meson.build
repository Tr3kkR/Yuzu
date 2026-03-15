shared_library(
  'antivirus',
  files('src/antivirus_plugin.cpp'),
  name_prefix: '',
  dependencies: [yuzu_sdk_dep, yuzu_agent_core_dep],
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
