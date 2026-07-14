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

# Linux: the systemd service guard (guard_systemd.cpp) AND the Service spark
# mechanism (spark_service.cpp, ADR-0021 Stage 1 PR 1c) watch unit run-state over
# sd-bus, which libsystemd provides. Both are wrapped in
# `#if defined(__linux__) && defined(YUZU_HAVE_LIBSYSTEMD)` and compile to a no-op
# stub (start() returns false / make_service_mechanism() returns nullptr, like the
# off-Linux build) when libsystemd is not used. The `systemd_guard` feature option
# (default `enabled`) controls the dependency for BOTH:
#   enabled  — require libsystemd, so the shipped agent always offers the guard and a
#              build that has lost libsystemd-dev FAILS loudly instead of silently
#              shipping a guard-less agent. Default ⇒ CI / Docker / release stay
#              unchanged and keep the guarantee with no extra flags.
#   auto     — use libsystemd if found, else build the no-op stub (no configure error).
#   disabled — always build the no-op stub.
# Pass `-Dsystemd_guard=auto` (or `disabled`) for musl/Alpine/non-systemd/minimal
# images where libsystemd is absent.
agent_platform_deps = []
agent_platform_args = []
if host_machine.system() == 'darwin'
  # macOS FileGuard: the FSEvents watch core (guard_fsevents.cpp) needs
  # CoreServices (FSEventStream*) + CoreFoundation (CFString/CFArray). Both
  # frameworks ship in the Command Line Tools SDK — unlike EndpointSecurity —
  # so required: true is safe on every mac host (docs/darwin-compat.md).
  agent_platform_deps += dependency('appleframeworks',
                                    modules: ['CoreFoundation', 'CoreServices'],
                                    required: true)
endif
if host_machine.system() == 'linux'
  libsystemd_dep = dependency('libsystemd', required: get_option('systemd_guard'),
                              include_type: 'system')
  if libsystemd_dep.found()
    agent_platform_deps += libsystemd_dep
    agent_platform_args += '-DYUZU_HAVE_LIBSYSTEMD'
  else
    message('libsystemd not used (systemd_guard != enabled, and not found) — Linux '
          + 'systemd service guard built as a no-op stub')
  endif
endif

yuzu_agent_core_lib = shared_library(
  'yuzu_agent_core',
  files('src/agent.cpp', 'src/agent_csr.cpp', 'src/cert_discovery.cpp', 'src/cert_store.cpp', 'src/cloud_identity.cpp', 'src/dex_event.cpp', 'src/dex_linux_collector.cpp', 'src/dex_linux_journal.cpp', 'src/dex_linux_kmsg.cpp', 'src/dex_linux_proc.cpp', 'src/dex_linux_storage.cpp', 'src/dex_linux_sysfs.cpp', 'src/dex_macos_collector.cpp', 'src/dex_macos_iokit.cpp', 'src/dex_macos_oslog.cpp', 'src/dex_macos_signals.cpp', 'src/dex_observer.cpp', 'src/dex_perf_breach.cpp', 'src/dex_rate_limiter.cpp', 'src/dex_signal_catalog.cpp', 'src/dex_win_poll.cpp', 'src/guard_file.cpp', 'src/guard_fsevents.cpp', 'src/guard_registry.cpp', 'src/guard_service.cpp', 'src/guard_systemd.cpp', 'src/guardian_engine.cpp', 'src/identity_store.cpp', 'src/kv_store.cpp', 'src/local_dispatcher.cpp', 'src/network_interfaces.cpp', 'src/net_quality_sampler.cpp', 'src/plugin_loader.cpp', 'src/process_enum.cpp', 'src/resilience_strategy.cpp', 'src/sdk_utilities.cpp', 'src/spark_disk.cpp', 'src/spark_engine.cpp', 'src/spark_file.cpp', 'src/spark_interval.cpp', 'src/spark_registry.cpp', 'src/spark_service.cpp', 'src/spark_spec.cpp', 'src/spark_startup.cpp', 'src/sync_canonical.cpp', 'src/sync_scheduler.cpp', 'src/sync_source_app_perf.cpp', 'src/sync_source_device_ci.cpp', 'src/sync_source_installed_software.cpp', 'src/sync_source_software_licensing.cpp', 'src/temp_file.cpp', 'src/trigger_engine.cpp', 'src/updater.cpp'),
  include_directories: [
    include_directories('include'),
    include_directories('../../sdk/include'),
    include_directories('../shared'),  # win_str.hpp shared wide<->UTF-8 helpers (#1681, _WIN32-gated)
  ],
  dependencies: [yuzu_sdk_dep, yuzu_proto_dep, spdlog_dep, sqlite3_dep, nlohmann_dep] + agent_crypto_deps + agent_platform_deps,
  cpp_args: ['-DYUZU_AGENT_CORE_BUILDING'] + agent_platform_args,
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
  files('src/main.cpp', 'src/service_win.cpp'),
  include_directories: [
    include_directories('include'),
    include_directories('../../sdk/include'),
    include_directories('../shared'),  # win_sc_handle.hpp SC_HANDLE RAII owner (#1822, _WIN32-gated)
  ],
  dependencies: [yuzu_agent_core_dep, spdlog_dep, cli11_dep, sqlite3_dep],
  install: true,
)
