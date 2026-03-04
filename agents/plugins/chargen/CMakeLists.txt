include(${CMAKE_SOURCE_DIR}/cmake/modules/CompilerFlags.cmake)

add_library(plugin_chargen SHARED
  src/chargen_plugin.cpp
)
add_library(yuzu::plugin_chargen ALIAS plugin_chargen)

target_link_libraries(plugin_chargen PRIVATE yuzu::sdk)

set_target_properties(plugin_chargen PROPERTIES
  PREFIX ""
  OUTPUT_NAME "chargen"
)

yuzu_set_compiler_flags(plugin_chargen)

install(TARGETS plugin_chargen LIBRARY DESTINATION lib/yuzu/plugins)
