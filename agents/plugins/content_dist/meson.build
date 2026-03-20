if host_machine.system() == 'windows'
  cd_extra_deps = [cxx.find_library('bcrypt')]
else
  cd_extra_deps = [dependency('openssl', required: true)]
endif

shared_library(
  'content_dist',
  files('src/content_dist_plugin.cpp'),
  name_prefix: '',
  dependencies: [yuzu_sdk_dep, yuzu_agent_core_dep] + cd_extra_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
