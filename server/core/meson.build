yuzu_server_core_lib = static_library(
  'yuzu_server_core',
  files('src/server.cpp', 'src/chargen_ui.cpp'),
  include_directories: ['include'],
  dependencies: [yuzu_sdk_dep, yuzu_proto_dep, grpcpp_dep, spdlog_dep, httplib_dep],
)

yuzu_server_core_dep = declare_dependency(
  link_with: yuzu_server_core_lib,
  include_directories: include_directories('include'),
  dependencies: [yuzu_sdk_dep, yuzu_proto_dep, grpcpp_dep, spdlog_dep, httplib_dep],
)

executable(
  'yuzu-server',
  files('src/main.cpp'),
  dependencies: [yuzu_server_core_dep, cli11_dep],
  install: true,
)
