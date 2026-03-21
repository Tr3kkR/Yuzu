wol_deps = [yuzu_sdk_dep, yuzu_agent_core_dep]

if host_machine.system() == 'windows'
  wol_deps += cxx.find_library('ws2_32')
endif

shared_library(
  'wol',
  files('src/wol_plugin.cpp'),
  name_prefix: '',
  dependencies: wol_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
