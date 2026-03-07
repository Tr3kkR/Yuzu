include(${CMAKE_SOURCE_DIR}/cmake/modules/CompilerFlags.cmake)

add_library(plugin_status SHARED
  src/status_plugin.cpp
)
add_library(yuzu::plugin_status ALIAS plugin_status)

target_link_libraries(plugin_status PRIVATE yuzu::sdk)

set_target_properties(plugin_status PROPERTIES
  PREFIX ""
  OUTPUT_NAME "status"
)

yuzu_set_compiler_flags(plugin_status)

install(TARGETS plugin_status LIBRARY DESTINATION lib/yuzu/plugins)
