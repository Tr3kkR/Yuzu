tar_deps = [yuzu_sdk_dep, yuzu_agent_core_dep, spdlog_dep, sqlite3_dep, nlohmann_dep]
# Windows: advapi32, iphlpapi, ws2_32, wtsapi32 linked via #pragma comment(lib) in source

shared_library(
  'tar',
  files(
    'src/tar_plugin.cpp',
    'src/tar_db.cpp',
    'src/tar_diff.cpp',
    'src/tar_network_collector.cpp',
    'src/tar_service_collector.cpp',
    'src/tar_user_collector.cpp',
  ),
  name_prefix: '',
  dependencies: tar_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
