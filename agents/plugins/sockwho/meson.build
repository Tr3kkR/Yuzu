sockwho_deps = [yuzu_sdk_dep, yuzu_agent_core_dep]

if host_machine.system() == 'windows'
  sockwho_deps += cxx.find_library('iphlpapi')
  sockwho_deps += cxx.find_library('ws2_32')
endif

shared_library(
  'sockwho',
  files('src/sockwho_plugin.cpp'),
  name_prefix: '',
  dependencies: sockwho_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
