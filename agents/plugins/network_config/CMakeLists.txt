include(${CMAKE_SOURCE_DIR}/cmake/modules/CompilerFlags.cmake)

add_library(plugin_network_config SHARED
  src/network_config_plugin.cpp
)
add_library(yuzu::plugin_network_config ALIAS plugin_network_config)

target_link_libraries(plugin_network_config PRIVATE yuzu::sdk)

if(WIN32)
  target_link_libraries(plugin_network_config PRIVATE iphlpapi ws2_32 winhttp)
endif()

set_target_properties(plugin_network_config PROPERTIES
  PREFIX ""
  OUTPUT_NAME "network_config"
)

yuzu_set_compiler_flags(plugin_network_config)

install(TARGETS plugin_network_config LIBRARY DESTINATION lib/yuzu/plugins)
