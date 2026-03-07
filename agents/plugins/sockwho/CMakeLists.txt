include(${CMAKE_SOURCE_DIR}/cmake/modules/CompilerFlags.cmake)

add_library(plugin_sockwho SHARED
  src/sockwho_plugin.cpp
)
add_library(yuzu::plugin_sockwho ALIAS plugin_sockwho)

target_link_libraries(plugin_sockwho PRIVATE yuzu::sdk)

if(WIN32)
  target_link_libraries(plugin_sockwho PRIVATE iphlpapi ws2_32)
endif()

set_target_properties(plugin_sockwho PROPERTIES
  PREFIX ""
  OUTPUT_NAME "sockwho"
)

yuzu_set_compiler_flags(plugin_sockwho)

install(TARGETS plugin_sockwho LIBRARY DESTINATION lib/yuzu/plugins)
