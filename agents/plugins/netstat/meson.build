netstat_deps = [yuzu_sdk_dep, yuzu_agent_core_dep]

if host_machine.system() == 'windows'
  netstat_deps += cxx.find_library('iphlpapi')
  netstat_deps += cxx.find_library('ws2_32')
endif

shared_library(
  'netstat',
  files('src/netstat_plugin.cpp'),
  name_prefix: '',
  dependencies: netstat_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
