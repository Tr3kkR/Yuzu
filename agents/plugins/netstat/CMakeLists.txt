include(${CMAKE_SOURCE_DIR}/cmake/modules/CompilerFlags.cmake)

add_library(plugin_netstat SHARED
  src/netstat_plugin.cpp
)
add_library(yuzu::plugin_netstat ALIAS plugin_netstat)

target_link_libraries(plugin_netstat PRIVATE yuzu::sdk)

if(WIN32)
  target_link_libraries(plugin_netstat PRIVATE iphlpapi ws2_32)
endif()

set_target_properties(plugin_netstat PROPERTIES
  PREFIX ""
  OUTPUT_NAME "netstat"
)

yuzu_set_compiler_flags(plugin_netstat)

install(TARGETS plugin_netstat LIBRARY DESTINATION lib/yuzu/plugins)
