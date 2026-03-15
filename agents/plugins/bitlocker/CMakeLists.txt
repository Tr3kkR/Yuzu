include(${CMAKE_SOURCE_DIR}/cmake/modules/CompilerFlags.cmake)

add_library(plugin_bitlocker SHARED
  src/bitlocker_plugin.cpp
)
add_library(yuzu::plugin_bitlocker ALIAS plugin_bitlocker)

target_link_libraries(plugin_bitlocker PRIVATE yuzu::sdk)

set_target_properties(plugin_bitlocker PROPERTIES
  PREFIX ""
  OUTPUT_NAME "bitlocker"
)

yuzu_set_compiler_flags(plugin_bitlocker)

install(TARGETS plugin_bitlocker LIBRARY DESTINATION lib/yuzu/plugins)
