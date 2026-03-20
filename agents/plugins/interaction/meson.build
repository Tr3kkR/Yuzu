interaction_deps = [yuzu_sdk_dep, yuzu_agent_core_dep]

# Windows needs shell32 for Shell_NotifyIconW
if host_machine.system() == 'windows'
  interaction_deps += [
    meson.get_compiler('cpp').find_library('shell32'),
    meson.get_compiler('cpp').find_library('user32'),
  ]
endif

shared_library(
  'interaction',
  files('src/interaction_plugin.cpp'),
  name_prefix: '',
  dependencies: interaction_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
