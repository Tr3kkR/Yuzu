include(${CMAKE_SOURCE_DIR}/cmake/modules/CompilerFlags.cmake)

add_library(plugin_network_diag SHARED
  src/network_diag_plugin.cpp
)
add_library(yuzu::plugin_network_diag ALIAS plugin_network_diag)

target_link_libraries(plugin_network_diag PRIVATE yuzu::sdk)

set_target_properties(plugin_network_diag PROPERTIES
  PREFIX ""
  OUTPUT_NAME "network_diag"
)

yuzu_set_compiler_flags(plugin_network_diag)

install(TARGETS plugin_network_diag LIBRARY DESTINATION lib/yuzu/plugins)
