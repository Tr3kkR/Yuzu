include(${CMAKE_SOURCE_DIR}/cmake/modules/CompilerFlags.cmake)

add_library(plugin_filesystem SHARED
  src/filesystem_plugin.cpp
)
add_library(yuzu::plugin_filesystem ALIAS plugin_filesystem)

target_link_libraries(plugin_filesystem PRIVATE yuzu::sdk)

set_target_properties(plugin_filesystem PROPERTIES
  PREFIX ""
  OUTPUT_NAME "filesystem"
)

yuzu_set_compiler_flags(plugin_filesystem)

install(TARGETS plugin_filesystem LIBRARY DESTINATION lib/yuzu/plugins)
