wifi_deps = [yuzu_sdk_dep, yuzu_agent_core_dep]

if host_machine.system() == 'windows'
  wifi_deps += cxx.find_library('wlanapi')
endif

shared_library(
  'wifi',
  files('src/wifi_plugin.cpp'),
  name_prefix: '',
  include_directories: include_directories('../../shared'),  # win_str.hpp (#1681)
  dependencies: wifi_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
