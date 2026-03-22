interaction_deps = [yuzu_sdk_dep, yuzu_agent_core_dep]
# Windows: shell32.lib, user32.lib linked via #pragma comment(lib) in source

shared_library(
  'interaction',
  files('src/interaction_plugin.cpp'),
  name_prefix: '',
  dependencies: interaction_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
