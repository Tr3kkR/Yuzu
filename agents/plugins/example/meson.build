shared_library(
  'example',
  files('src/example_plugin.cpp'),
  name_prefix: '',          # Strip 'lib' prefix → example.so / example.dll
  dependencies: [yuzu_sdk_dep, yuzu_agent_core_dep],
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
