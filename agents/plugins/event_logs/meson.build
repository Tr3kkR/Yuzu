shared_library(
  'event_logs',
  files('src/event_logs_plugin.cpp'),
  name_prefix: '',
  dependencies: [yuzu_sdk_dep, yuzu_agent_core_dep],
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
