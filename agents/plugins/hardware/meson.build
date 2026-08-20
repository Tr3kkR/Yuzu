hardware_deps = [yuzu_sdk_dep, yuzu_agent_core_dep, nlohmann_dep, spdlog_dep]

if host_machine.system() == 'windows'
  hardware_deps += cxx.find_library('wbemuuid')
  hardware_deps += cxx.find_library('ole32')
  hardware_deps += cxx.find_library('oleaut32')
elif host_machine.system() == 'darwin'
  # Wave 3 (#2380/ADR-3002 promotion): the "system" action reads the IOKit
  # IOPlatformExpertDevice registry entry natively (kIOPlatformSerialNumberKey
  # / kIOPlatformUUIDKey) instead of shelling out to `ioreg`. Same dependency
  # shape as tests/meson.build's agent_test_native_deps (PLAN-08) — agent-core
  # itself links no IOKit/CoreFoundation on darwin, so this plugin pulls its
  # own copy.
  hardware_deps += dependency('appleframeworks', modules: ['IOKit', 'CoreFoundation'],
                               include_type: 'system')
endif

# Assigned to a variable (mirrors users_plugin_lib in
# agents/plugins/users/meson.build) so tests/meson.build's link_depends can
# order this build ahead of test_hardware_device_identity_posix_actions.cpp,
# which loads the real hardware.dylib/.so by path via
# yuzu::agent::PluginHandle::load.
hardware_plugin_lib = shared_library(
  'hardware',
  files('src/hardware_plugin.cpp'),
  name_prefix: '',
  include_directories: include_directories('../../shared'),  # win_str.hpp (#1681, _WIN32-gated)
  dependencies: hardware_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
