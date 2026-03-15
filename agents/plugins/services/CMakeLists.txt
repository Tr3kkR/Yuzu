include(${CMAKE_SOURCE_DIR}/cmake/modules/CompilerFlags.cmake)

add_library(plugin_services SHARED
  src/services_plugin.cpp
)
add_library(yuzu::plugin_services ALIAS plugin_services)

target_link_libraries(plugin_services PRIVATE yuzu::sdk)

set_target_properties(plugin_services PROPERTIES
  PREFIX ""
  OUTPUT_NAME "services"
)

yuzu_set_compiler_flags(plugin_services)

install(TARGETS plugin_services LIBRARY DESTINATION lib/yuzu/plugins)
