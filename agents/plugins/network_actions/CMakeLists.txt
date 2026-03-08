include(${CMAKE_SOURCE_DIR}/cmake/modules/CompilerFlags.cmake)

add_library(plugin_network_actions SHARED
  src/network_actions_plugin.cpp
)
add_library(yuzu::plugin_network_actions ALIAS plugin_network_actions)

target_link_libraries(plugin_network_actions PRIVATE yuzu::sdk)

set_target_properties(plugin_network_actions PROPERTIES
  PREFIX ""
  OUTPUT_NAME "network_actions"
)

yuzu_set_compiler_flags(plugin_network_actions)

install(TARGETS plugin_network_actions LIBRARY DESTINATION lib/yuzu/plugins)
