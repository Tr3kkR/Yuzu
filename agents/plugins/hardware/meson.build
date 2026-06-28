hardware_deps = [yuzu_sdk_dep, yuzu_agent_core_dep]

if host_machine.system() == 'windows'
  hardware_deps += cxx.find_library('wbemuuid')
  hardware_deps += cxx.find_library('ole32')
  hardware_deps += cxx.find_library('oleaut32')
endif

shared_library(
  'hardware',
  files('src/hardware_plugin.cpp'),
  name_prefix: '',
  include_directories: include_directories('../../shared'),  # win_str.hpp (#1681, _WIN32-gated)
  dependencies: hardware_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
