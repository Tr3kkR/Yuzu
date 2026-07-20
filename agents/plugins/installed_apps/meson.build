shared_library(
  'installed_apps',
  files('src/installed_apps_plugin.cpp'),
  name_prefix: '',
  include_directories: include_directories('../filesystem/src'),  # filesystem_macos_sig.hpp (shared macOS sig/version classifiers, #2273/1.10)
  dependencies: [yuzu_sdk_dep, yuzu_agent_core_dep, nlohmann_dep],  # nlohmann for system_profiler -json parse (#2273/1.10)
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
