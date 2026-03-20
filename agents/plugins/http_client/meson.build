if host_machine.system() == 'windows'
  http_extra_deps = [cxx.find_library('bcrypt')]
else
  http_extra_deps = [dependency('openssl', required: true)]
endif

shared_library(
  'http_client',
  files('src/http_client_plugin.cpp'),
  name_prefix: '',
  dependencies: [yuzu_sdk_dep, yuzu_agent_core_dep] + http_extra_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
