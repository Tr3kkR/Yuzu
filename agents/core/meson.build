# Platform-specific crypto for updater SHA-256 verification
# Windows: bcrypt.lib linked via #pragma comment(lib) in source files
if host_machine.system() == 'windows'
  agent_crypto_deps = []
else
  agent_openssl_dep = dependency('openssl', required: true)
  agent_crypto_deps = [agent_openssl_dep]
endif

yuzu_agent_core_lib = shared_library(
  'yuzu_agent_core',
  files('src/agent.cpp', 'src/cert_discovery.cpp', 'src/cert_store.cpp', 'src/cloud_identity.cpp', 'src/identity_store.cpp', 'src/kv_store.cpp', 'src/plugin_loader.cpp', 'src/process_enum.cpp', 'src/sdk_utilities.cpp', 'src/temp_file.cpp', 'src/trigger_engine.cpp', 'src/updater.cpp'),
  include_directories: [
    include_directories('include'),
    include_directories('../../sdk/include'),
  ],
  dependencies: [yuzu_sdk_dep, yuzu_proto_dep, spdlog_dep, sqlite3_dep, nlohmann_dep] + agent_crypto_deps,
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