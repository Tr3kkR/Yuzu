msi_packages_deps = [yuzu_sdk_dep, yuzu_agent_core_dep]

if host_machine.system() == 'windows'
  msi_packages_deps += cxx.find_library('msi')
endif

shared_library(
  'msi_packages',
  files('src/msi_packages_plugin.cpp'),
  name_prefix: '',
  dependencies: msi_packages_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
