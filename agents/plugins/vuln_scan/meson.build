vuln_scan_deps = [yuzu_sdk_dep, yuzu_agent_core_dep, nlohmann_dep, openssl_dep]

if host_machine.system() == 'windows'
  vuln_scan_deps += meson.get_compiler('cpp').find_library('version')
elif host_machine.system() == 'darwin'
  vuln_scan_deps += dependency('appleframeworks', modules: ['CoreFoundation'])
endif

shared_library(
  'vuln_scan',
  files('src/vuln_scan_plugin.cpp'),
  name_prefix: '',
  dependencies: vuln_scan_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
