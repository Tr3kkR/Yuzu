include(${CMAKE_SOURCE_DIR}/cmake/modules/CompilerFlags.cmake)

add_library(plugin_antivirus SHARED
  src/antivirus_plugin.cpp
)
add_library(yuzu::plugin_antivirus ALIAS plugin_antivirus)

target_link_libraries(plugin_antivirus PRIVATE yuzu::sdk)

set_target_properties(plugin_antivirus PROPERTIES
  PREFIX ""
  OUTPUT_NAME "antivirus"
)

yuzu_set_compiler_flags(plugin_antivirus)

install(TARGETS plugin_antivirus LIBRARY DESTINATION lib/yuzu/plugins)
