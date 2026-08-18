bitlocker_deps = [yuzu_sdk_dep, yuzu_agent_core_dep, spdlog_dep]
bitlocker_sources = files('src/bitlocker_plugin.cpp')
bitlocker_include_dirs = []

if host_machine.system() == 'windows'
  # Win32_EncryptableVolume WMI query + a per-volume GetConversionStatus()
  # method call (root\CIMV2\Security\MicrosoftVolumeEncryption) replace the
  # raw `manage-bde -status` popen this plugin used to run. wmi_bounded.hpp
  # (+.cpp) and win_com.hpp live in agents/shared/ and are being authored in
  # parallel on PR3.3a -- not yet on this branch. This plugin is coded
  # against their agreed API surface (bitlocker_windows_wmi.hpp) and will
  # link once that PR lands; wmi_bounded.cpp compiles directly into this
  # plugin's DLL, same as every other agents/shared consumer that isn't
  # header-only (each plugin is its own shared_library target).
  bitlocker_sources += files('../../shared/wmi_bounded.cpp')
  bitlocker_include_dirs += include_directories('../../shared')  # wmi_bounded.hpp, win_com.hpp, win_str.hpp
  bitlocker_deps += cxx.find_library('wbemuuid')
  bitlocker_deps += cxx.find_library('ole32')
  bitlocker_deps += cxx.find_library('oleaut32')
elif host_machine.system() == 'linux'
  # crypto_LUKS TYPE enumeration promoted from an `lsblk` shell-out to
  # genuine rung-1 in-process libblkid (util-linux) -- a system pkg-config
  # library, not vcpkg. Open/mapped state comes from a plain
  # /sys/class/block/dm-*/dm/uuid read (no library needed for that half).
  bitlocker_deps += dependency('blkid', required: true)
endif

shared_library(
  'bitlocker',
  bitlocker_sources,
  name_prefix: '',
  include_directories: bitlocker_include_dirs,
  dependencies: bitlocker_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
