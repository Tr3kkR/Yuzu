include(${CMAKE_SOURCE_DIR}/cmake/modules/CompilerFlags.cmake)

add_library(plugin_processes SHARED
  src/processes_plugin.cpp
)
add_library(yuzu::plugin_processes ALIAS plugin_processes)

target_link_libraries(plugin_processes PRIVATE yuzu::sdk)

set_target_properties(plugin_processes PROPERTIES
  PREFIX ""
  OUTPUT_NAME "processes"
)

yuzu_set_compiler_flags(plugin_processes)

install(TARGETS plugin_processes LIBRARY DESTINATION lib/yuzu/plugins)
