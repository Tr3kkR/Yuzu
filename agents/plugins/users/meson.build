users_deps = [yuzu_sdk_dep, yuzu_agent_core_dep]

if host_machine.system() == 'windows'
  users_deps += cxx.find_library('wtsapi32')
  users_deps += cxx.find_library('netapi32')
endif

shared_library(
  'users',
  files('src/users_plugin.cpp'),
  name_prefix: '',
  include_directories: include_directories('../../shared'),  # win_str.hpp (#1681)
  dependencies: users_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
