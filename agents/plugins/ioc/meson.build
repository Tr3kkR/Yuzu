ioc_deps = [yuzu_sdk_dep, yuzu_agent_core_dep]

if host_machine.system() == 'windows'
  ioc_deps += cxx.find_library('iphlpapi')
  ioc_deps += cxx.find_library('ws2_32')
endif

shared_library(
  'ioc',
  files('src/ioc_plugin.cpp'),
  name_prefix: '',
  dependencies: ioc_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
