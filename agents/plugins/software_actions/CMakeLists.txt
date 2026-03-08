include(${CMAKE_SOURCE_DIR}/cmake/modules/CompilerFlags.cmake)

add_library(plugin_software_actions SHARED
  src/software_actions_plugin.cpp
)
add_library(yuzu::plugin_software_actions ALIAS plugin_software_actions)

target_link_libraries(plugin_software_actions PRIVATE yuzu::sdk)

set_target_properties(plugin_software_actions PROPERTIES
  PREFIX ""
  OUTPUT_NAME "software_actions"
)

yuzu_set_compiler_flags(plugin_software_actions)

install(TARGETS plugin_software_actions LIBRARY DESTINATION lib/yuzu/plugins)
