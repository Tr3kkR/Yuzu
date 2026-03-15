yuzu_agent_core_lib = shared_library(
  'yuzu_agent_core',
  files('src/agent.cpp', 'src/cert_discovery.cpp', 'src/cert_store.cpp', 'src/cloud_identity.cpp', 'src/identity_store.cpp', 'src/plugin_loader.cpp'),
  include_directories: [
    include_directories('include'),
    include_directories('../../sdk/include'),
  ],
  dependencies: [yuzu_sdk_dep, yuzu_proto_dep, spdlog_dep, sqlite3_dep],
  cpp_args: ['-DYUZU_AGENT_CORE_BUILDING'],
  install: true,
)

yuzu_agent_core_dep = declare_dependency(
  link_with: yuzu_agent_core_lib,
  include_directories: [
    include_directories('include'),
    include_directories('../../sdk/include'),
  ],
)

executable(
  'yuzu-agent',
  files('src/main.cpp'),
  include_directories: [
    include_directories('include'),
    include_directories('../../sdk/include'),
  ],
  dependencies: [yuzu_agent_core_dep, spdlog_dep, cli11_dep],
  install: true,
)