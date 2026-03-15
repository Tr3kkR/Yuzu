include(${CMAKE_SOURCE_DIR}/cmake/modules/CompilerFlags.cmake)

add_library(plugin_windows_updates SHARED
  src/windows_updates_plugin.cpp
)
add_library(yuzu::plugin_windows_updates ALIAS plugin_windows_updates)

target_link_libraries(plugin_windows_updates PRIVATE yuzu::sdk)

set_target_properties(plugin_windows_updates PROPERTIES
  PREFIX ""
  OUTPUT_NAME "windows_updates"
)

yuzu_set_compiler_flags(plugin_windows_updates)

install(TARGETS plugin_windows_updates LIBRARY DESTINATION lib/yuzu/plugins)
