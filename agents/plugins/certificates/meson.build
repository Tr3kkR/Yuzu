# Platform-specific crypto dependencies for certificate store access
cert_deps = [yuzu_sdk_dep, yuzu_agent_core_dep]
if host_machine.system() == 'windows'
  cert_deps += cxx.find_library('crypt32')
endif

shared_library(
  'certificates',
  files('src/certificates_plugin.cpp'),
  name_prefix: '',
  dependencies: cert_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
