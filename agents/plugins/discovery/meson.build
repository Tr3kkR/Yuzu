discovery_deps = [yuzu_sdk_dep, yuzu_agent_core_dep]

# Windows needs iphlpapi for ARP table and ws2_32 for socket functions
if host_machine.system() == 'windows'
  discovery_deps += [
    meson.get_compiler('cpp').find_library('iphlpapi'),
    meson.get_compiler('cpp').find_library('ws2_32'),
  ]
endif

shared_library(
  'discovery',
  files('src/discovery_plugin.cpp'),
  name_prefix: '',
  dependencies: discovery_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
