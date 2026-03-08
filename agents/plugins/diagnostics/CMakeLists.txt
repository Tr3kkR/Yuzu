include(${CMAKE_SOURCE_DIR}/cmake/modules/CompilerFlags.cmake)

add_library(plugin_diagnostics SHARED
  src/diagnostics_plugin.cpp
)
add_library(yuzu::plugin_diagnostics ALIAS plugin_diagnostics)

target_link_libraries(plugin_diagnostics PRIVATE yuzu::sdk)

set_target_properties(plugin_diagnostics PROPERTIES
  PREFIX ""
  OUTPUT_NAME "diagnostics"
)

yuzu_set_compiler_flags(plugin_diagnostics)

install(TARGETS plugin_diagnostics LIBRARY DESTINATION lib/yuzu/plugins)
