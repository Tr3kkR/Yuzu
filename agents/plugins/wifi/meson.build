wifi_deps = [yuzu_sdk_dep, yuzu_agent_core_dep]
wifi_sources = files('src/wifi_plugin.cpp')
wifi_objcpp_args = []

if host_machine.system() == 'windows'
  wifi_deps += cxx.find_library('wlanapi')
elif host_machine.system() == 'darwin'
  # First Objective-C++ TU in the tree (still true — this is the worked example
  # for the reusable per-target appleframeworks/objcpp template, not a second
  # implementation of it). CoreWLAN is an Objective-C framework, so the
  # current-connection query lives in wifi_corewlan.mm. `add_languages('objcpp')`
  # and the shared `-std=c++23`/`-fvisibility=hidden`/`-fobjc-arc` args now live
  # ONCE at the top-level meson.build's `corefoundation_dep` site (`apple_objcpp_args`)
  # instead of here — this block only supplies what is genuinely wifi-specific:
  # its own .mm source and its own framework module list. CoreWLAN is a PUBLIC
  # framework in the base macOS SDK (present with the Command Line Tools SDK,
  # unlike EndpointSecurity), so this dependency() call is required: true — a
  # failure here is a real problem, not a missing-full-Xcode fallback. See
  # docs/darwin-compat.md and docs/native-objcpp-conventions.md.
  wifi_sources += files('src/wifi_corewlan.mm')
  wifi_deps += dependency('appleframeworks', modules: ['CoreWLAN', 'Foundation'],
                          include_type: 'system')
  wifi_objcpp_args += apple_objcpp_args
endif

shared_library(
  'wifi',
  wifi_sources,
  name_prefix: '',
  include_directories: include_directories('../../shared'),  # win_str.hpp (#1681)
  dependencies: wifi_deps,
  objcpp_args: wifi_objcpp_args,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
