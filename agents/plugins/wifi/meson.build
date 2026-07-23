wifi_deps = [yuzu_sdk_dep, yuzu_agent_core_dep]
wifi_sources = files('src/wifi_plugin.cpp')
wifi_objcpp_args = []

if host_machine.system() == 'windows'
  wifi_deps += cxx.find_library('wlanapi')
elif host_machine.system() == 'darwin'
  # First Objective-C++ TU in the tree. CoreWLAN is an Objective-C framework, so
  # the current-connection query lives in wifi_corewlan.mm. The top-level
  # project() declares C++ only, so enable objcpp here (macOS-only) — no other
  # plugin needs it. CoreWLAN is a PUBLIC framework in the base macOS SDK
  # (present with the Command Line Tools SDK, unlike EndpointSecurity), so this
  # is required: true — a failure here is a real problem, not a missing-full-Xcode
  # fallback. See docs/darwin-compat.md.
  add_languages('objcpp', native: false, required: true)
  wifi_sources += files('src/wifi_corewlan.mm')
  wifi_deps += dependency('appleframeworks', modules: ['CoreWLAN', 'Foundation'],
                          include_type: 'system')
  # objcpp is a separate language from cpp, so the project-level -std / visibility
  # args do not reach the .mm — set them here. Probe for the C++23 flag rather
  # than hardcoding it: Apple Clang 15 rejects the raw `-std=c++23` spelling and
  # needs `-std=c++2b` (docs/ci-cpp23-troubleshooting.md), so pick whichever the
  # objcpp compiler accepts. ARC keeps the CoreWLAN object lifetimes correct
  # without manual retain/release.
  objcpp = meson.get_compiler('objcpp')
  wifi_objcpp_std = objcpp.has_argument('-std=c++23') ? '-std=c++23' : '-std=c++2b'
  wifi_objcpp_args += [wifi_objcpp_std, '-fvisibility=hidden', '-fobjc-arc']
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
