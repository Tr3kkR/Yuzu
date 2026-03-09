include(${CMAKE_SOURCE_DIR}/cmake/modules/CompilerFlags.cmake)

add_library(plugin_vuln_scan SHARED
  src/vuln_scan_plugin.cpp
)
add_library(yuzu::plugin_vuln_scan ALIAS plugin_vuln_scan)

target_link_libraries(plugin_vuln_scan PRIVATE yuzu::sdk)

set_target_properties(plugin_vuln_scan PROPERTIES
  PREFIX ""
  OUTPUT_NAME "vuln_scan"
)

yuzu_set_compiler_flags(plugin_vuln_scan)

install(TARGETS plugin_vuln_scan LIBRARY DESTINATION lib/yuzu/plugins)
