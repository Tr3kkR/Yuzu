# Platform-specific crypto dependencies for certificate store access
# Windows: crypt32.lib linked via #pragma comment(lib) in source
cert_deps = [yuzu_sdk_dep, yuzu_agent_core_dep]

shared_library(
  'certificates',
  files('src/certificates_plugin.cpp'),
  name_prefix: '',
  dependencies: cert_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
