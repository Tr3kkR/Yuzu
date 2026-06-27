network_config_deps = [yuzu_sdk_dep, yuzu_agent_core_dep]

shared_library(
  'network_config',
  files('src/network_config_plugin.cpp'),
  name_prefix: '',
  include_directories: include_directories('../shared'),  # win_str.hpp (#1681)
  dependencies: network_config_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
