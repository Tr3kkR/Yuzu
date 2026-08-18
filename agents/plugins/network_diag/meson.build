shared_library(
  'network_diag',
  files('src/network_diag_plugin.cpp'),
  name_prefix: '',
  include_directories: include_directories('../../shared'),  # macos_socket_walk.hpp (Wave 3 PR3.1)
  dependencies: [yuzu_sdk_dep, yuzu_agent_core_dep],
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
