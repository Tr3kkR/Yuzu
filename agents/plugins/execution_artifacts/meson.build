# execution_artifacts — Windows-only ShimCache / Amcache / Prefetch plugin.
# Multi-TU shape follows disk_actions/meson.build: one portable plugin TU
# (execute()/descriptors, this package/P31) plus a Windows-only leg TU
# (execution_artifacts_win.cpp, P32) that is listed only when building for
# Windows — a single-OS non-Windows build simply omits the leg source, since
# every action on those platforms is the fixed unsupported|windows_only_
# artefact outcome the portable TU already handles with no OS call at all.
execution_artifacts_deps = [yuzu_sdk_dep, yuzu_agent_core_dep, spdlog_dep]
execution_artifacts_sources = files('src/execution_artifacts_plugin.cpp')

if host_machine.system() == 'windows'
  # advapi32: RegQueryValueExW (ShimCache) + RegLoadAppKeyW/AdjustTokenPrivileges
  # (Amcache). ntdll: RtlGetCompressionWorkSpaceSize/RtlDecompressBufferEx
  # (Prefetch MAM decompression) — not a normal import-library dependency,
  # hence cxx.find_library rather than a plain link_with.
  execution_artifacts_deps += [
    cxx.find_library('advapi32'),
    cxx.find_library('ntdll'),
  ]
  execution_artifacts_sources += files('src/execution_artifacts_win.cpp')
endif

# Assigned to a variable (mirrors disk_actions_plugin_lib /
# app_usage_plugin_lib) so tests/meson.build's link_depends can order this
# build ahead of test_execution_artifacts_local_dispatcher.cpp, which loads
# the real execution_artifacts.dll/.so/.dylib by path via
# yuzu::agent::PluginHandle::load.
execution_artifacts_plugin_lib = shared_library(
  'execution_artifacts',
  execution_artifacts_sources,
  name_prefix: '',
  include_directories: include_directories('../../shared'),  # win_profiles.hpp / win_reg_handle.hpp (the-rig 2026-09-07: C1083 without it)
  dependencies: execution_artifacts_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
