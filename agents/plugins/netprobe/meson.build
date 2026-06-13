netprobe_deps = [yuzu_sdk_dep, yuzu_agent_core_dep]

if host_machine.system() == 'windows'
  netprobe_deps += cxx.find_library('iphlpapi')
  netprobe_deps += cxx.find_library('ws2_32')
endif

shared_library(
  'netprobe',
  files('src/netprobe_plugin.cpp'),
  name_prefix: '',
  dependencies: netprobe_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
