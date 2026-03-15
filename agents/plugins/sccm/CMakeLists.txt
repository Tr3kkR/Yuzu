include(${CMAKE_SOURCE_DIR}/cmake/modules/CompilerFlags.cmake)

add_library(plugin_sccm SHARED
  src/sccm_plugin.cpp
)
add_library(yuzu::plugin_sccm ALIAS plugin_sccm)

target_link_libraries(plugin_sccm PRIVATE yuzu::sdk)

set_target_properties(plugin_sccm PROPERTIES
  PREFIX ""
  OUTPUT_NAME "sccm"
)

yuzu_set_compiler_flags(plugin_sccm)

install(TARGETS plugin_sccm LIBRARY DESTINATION lib/yuzu/plugins)
