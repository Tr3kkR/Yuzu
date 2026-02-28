yuzu_agent_core_lib = static_library(
  'yuzu_agent_core',
  files('src/agent.cpp', 'src/plugin_loader.cpp'),
  include_directories: ['include'],
  dependencies: [yuzu_sdk_dep, yuzu_proto_dep, grpc_dep, spdlog_dep],
)

yuzu_agent_core_dep = declare_dependency(
  link_with: yuzu_agent_core_lib,
  include_directories: include_directories('include'),
)

executable(
  'yuzu-agent',
  files('src/main.cpp'),
  dependencies: [yuzu_agent_core_dep, cli11_dep],
  install: true,
)
