include(${CMAKE_SOURCE_DIR}/cmake/modules/CompilerFlags.cmake)

add_library(plugin_installed_apps SHARED
  src/installed_apps_plugin.cpp
)
add_library(yuzu::plugin_installed_apps ALIAS plugin_installed_apps)

target_link_libraries(plugin_installed_apps PRIVATE yuzu::sdk)

set_target_properties(plugin_installed_apps PROPERTIES
  PREFIX ""
  OUTPUT_NAME "installed_apps"
)

yuzu_set_compiler_flags(plugin_installed_apps)

install(TARGETS plugin_installed_apps LIBRARY DESTINATION lib/yuzu/plugins)
