# OpenSSL is required on every platform — used by:
#   * updater.cpp + plugin_loader.cpp SHA-256 (Linux/macOS path; Windows
#     SHA-256 still goes through bcrypt for the digest, but
#   * plugin_loader.cpp CMS signature verification needs OpenSSL
#     unconditionally (CMS_verify, X509_STORE) so the verifier behaves
#     identically on all hosts. On Windows libssl/libcrypto are already
#     linked transitively via gRPC; this declaration just brings in the
#     include path so #include <openssl/cms.h> resolves.
agent_openssl_dep = dependency('openssl', required: true, include_type: 'system')
agent_crypto_deps = [agent_openssl_dep]

# Linux: the systemd service guard (guard_systemd.cpp) watches unit run-state over
# sd-bus, which libsystemd provides. libsystemd exists only on Linux, so this
# dependency is gated by host system — the source file is wrapped in
# `#if defined(__linux__)` and compiles to an empty TU elsewhere (the dex_macos_*.cpp
# pattern), so off-Linux nothing references sd-bus.h and no link dep is needed.
# required: true on Linux because a Linux agent that cannot offer the service guard is
# a regression (install libsystemd-dev / systemd-devel). The non-systemd runtime
# fallback is a start()-time concern, handled inside the guard, not a build-time one.
agent_platform_deps = []
if host_machine.system() == 'linux'
  agent_platform_deps += dependency('libsystemd', required: true, include_type: 'system')
endif

yuzu_agent_core_lib = shared_library(
  'yuzu_agent_core',
  files('src/agent.cpp', 'src/agent_csr.cpp', 'src/cert_discovery.cpp', 'src/cert_store.cpp', 'src/cloud_identity.cpp', 'src/dex_event.cpp', 'src/dex_linux_collector.cpp', 'src/dex_linux_proc.cpp', 'src/dex_linux_storage.cpp', 'src/dex_macos_collector.cpp', 'src/dex_macos_iokit.cpp', 'src/dex_macos_oslog.cpp', 'src/dex_macos_signals.cpp', 'src/dex_observer.cpp', 'src/dex_perf_breach.cpp', 'src/dex_signal_catalog.cpp', 'src/dex_win_poll.cpp', 'src/guard_file.cpp', 'src/guard_registry.cpp', 'src/guard_service.cpp', 'src/guard_systemd.cpp', 'src/guardian_engine.cpp', 'src/identity_store.cpp', 'src/kv_store.cpp', 'src/local_dispatcher.cpp', 'src/network_interfaces.cpp', 'src/plugin_loader.cpp', 'src/process_enum.cpp', 'src/resilience_strategy.cpp', 'src/sdk_utilities.cpp', 'src/temp_file.cpp', 'src/trigger_engine.cpp', 'src/updater.cpp'),
  include_directories: [
    include_directories('include'),
    include_directories('../../sdk/include'),
  ],
  dependencies: [yuzu_sdk_dep, yuzu_proto_dep, spdlog_dep, sqlite3_dep, nlohmann_dep] + agent_crypto_deps + agent_platform_deps,
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
  dependencies: [yuzu_agent_core_dep, spdlog_dep, cli11_dep, sqlite3_dep],
  install: true,
)
