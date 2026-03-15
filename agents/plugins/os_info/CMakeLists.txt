include(${CMAKE_SOURCE_DIR}/cmake/modules/CompilerFlags.cmake)

add_library(plugin_os_info SHARED
  src/os_info_plugin.cpp
)
add_library(yuzu::plugin_os_info ALIAS plugin_os_info)

target_link_libraries(plugin_os_info PRIVATE yuzu::sdk)

set_target_properties(plugin_os_info PROPERTIES
  PREFIX ""
  OUTPUT_NAME "os_info"
)

yuzu_set_compiler_flags(plugin_os_info)

install(TARGETS plugin_os_info LIBRARY DESTINATION lib/yuzu/plugins)
