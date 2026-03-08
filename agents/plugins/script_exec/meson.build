shared_library(
  'script_exec',
  files('src/script_exec_plugin.cpp'),
  name_prefix: '',
  dependencies: [yuzu_sdk_dep, yuzu_agent_core_dep],
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
