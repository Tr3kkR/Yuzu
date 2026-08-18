installed_apps_deps = [yuzu_sdk_dep, yuzu_agent_core_dep]
if host_machine.system() == 'windows'
  # win_profiles.hpp / win_reg_handle.hpp: Reg*W + RegLoadKeyW/RegUnLoadKeyW,
  # AdjustTokenPrivileges (#2771). The plugin already called RegLoadKeyW via
  # MSVC's default libs; naming the dependency makes it explicit.
  installed_apps_deps += [cxx.find_library('advapi32')]
endif

shared_library(
  'installed_apps',
  files('src/installed_apps_plugin.cpp'),
  name_prefix: '',
  # win_profiles.hpp / win_reg_handle.hpp / user_profile_model.hpp (#2771).
  # NOT win_str.hpp: this plugin deliberately keeps its own
  # installed_apps_registry_utf8.hpp, whose reg_sz_to_utf8 differs from the
  # shared one on interior NULs — both headers carry a do-not-merge note.
  include_directories: include_directories('../../shared'),
  dependencies: installed_apps_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
