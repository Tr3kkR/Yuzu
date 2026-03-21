tar_deps = [yuzu_sdk_dep, yuzu_agent_core_dep, spdlog_dep, sqlite3_dep, nlohmann_dep]

if host_machine.system() == 'windows'
  tar_deps += cxx.find_library('advapi32')
  tar_deps += cxx.find_library('iphlpapi')
  tar_deps += cxx.find_library('ws2_32')
  tar_deps += cxx.find_library('wtsapi32')
endif

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
