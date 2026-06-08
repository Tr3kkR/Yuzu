vuln_scan_deps = [
  yuzu_sdk_dep,
  yuzu_agent_core_dep,
  nlohmann_dep,
  # OpenSSL EVP — real SHA-256 verification of staged CVE rule files
  # (rules_integrity.hpp). Explicit dep so the include path + link are
  # guaranteed for the plugin rather than relying on transitive carry.
  dependency('openssl', required: true, include_type: 'system'),
]

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
