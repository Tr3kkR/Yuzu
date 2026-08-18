# WP-A (wave 3) is landing agents/shared/wmi_bounded.hpp + .cpp and
# win_com.hpp in parallel -- an in-process bounded-WMI/COM helper, needing
# the same wbemuuid/ole32/oleaut32 libs the `wmi` plugin's own meson.build
# links for its own (independent) COM/WMI use. Referenced here ahead of that
# package landing (see antivirus_plugin.cpp's Windows leg); integration wires
# the two together.
av_deps = [yuzu_sdk_dep, yuzu_agent_core_dep]
av_sources = files('src/antivirus_plugin.cpp')
if host_machine.system() == 'windows'
  av_deps += [cxx.find_library('wbemuuid'), cxx.find_library('ole32'), cxx.find_library('oleaut32')]
  av_sources += files('../../shared/wmi_bounded.cpp')
endif

shared_library(
  'antivirus',
  av_sources,
  name_prefix: '',
  include_directories: include_directories('../../shared'),  # win_reg_handle.hpp/win_profiles.hpp/wmi_bounded.hpp (PR1.7, WP-A)
  dependencies: av_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
