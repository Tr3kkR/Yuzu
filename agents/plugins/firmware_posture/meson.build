# firmware_posture -- BIOS/UEFI firmware vendor, version and update-pending posture (read-only).
# Shape follows peripherals/meson.build: a portable plugin TU plus three per-OS leg TUs, each
# #ifdef-gated internally for its own target, so all four are listed unconditionally.
firmware_posture_deps = [yuzu_sdk_dep, yuzu_agent_core_dep, spdlog_dep]

if host_machine.system() == 'darwin'
  # IOKit for IORegistryEntryFromPath/IORegistryEntryCreateCFProperty on the IODeviceTree
  # plane; CoreFoundation for the CFData those return. agent-core's IOKit link does
  # NOT propagate to a shared_library consumer, so it is named here exactly as
  # hardware/meson.build:18-19 does.
  firmware_posture_deps += dependency('appleframeworks', modules: ['IOKit', 'CoreFoundation'],
                                      include_type: 'system')
endif

# The Windows link libraries (WMI: wbemuuid/ole32/oleaut32) and the Linux libsystemd
# dependency plus its -DYUZU_HAVE_LIBSYSTEMD argument belong to the win/linux leg TUs and are
# added alongside them; nothing here adds a vcpkg.json entry (sd-bus is a system dependency).

# Assigned (not anonymous) so tests/meson.build's link_depends can name this build output.
firmware_posture_plugin_lib = shared_library(
  'firmware_posture',
  files(
    'src/firmware_posture_plugin.cpp',
    'src/firmware_posture_linux.cpp',
    'src/firmware_posture_macos.cpp',
    'src/firmware_posture_win.cpp',
  ),
  name_prefix: '',
  include_directories: include_directories('../../shared'),  # constraint_accumulator.hpp
  dependencies: firmware_posture_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
