include(${CMAKE_SOURCE_DIR}/cmake/modules/CompilerFlags.cmake)

add_library(plugin_firewall SHARED
  src/firewall_plugin.cpp
)
add_library(yuzu::plugin_firewall ALIAS plugin_firewall)

target_link_libraries(plugin_firewall PRIVATE yuzu::sdk)

set_target_properties(plugin_firewall PROPERTIES
  PREFIX ""
  OUTPUT_NAME "firewall"
)

yuzu_set_compiler_flags(plugin_firewall)

install(TARGETS plugin_firewall LIBRARY DESTINATION lib/yuzu/plugins)
