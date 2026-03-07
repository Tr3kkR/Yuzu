device_identity_deps = [yuzu_sdk_dep, yuzu_agent_core_dep]

if host_machine.system() == 'windows'
  device_identity_deps += cxx.find_library('netapi32')
  device_identity_deps += cxx.find_library('secur32')
endif

shared_library(
  'device_identity',
  files('src/device_identity_plugin.cpp'),
  name_prefix: '',
  dependencies: device_identity_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
