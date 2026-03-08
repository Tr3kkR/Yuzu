include(${CMAKE_SOURCE_DIR}/cmake/modules/CompilerFlags.cmake)

add_library(plugin_script_exec SHARED
  src/script_exec_plugin.cpp
)
add_library(yuzu::plugin_script_exec ALIAS plugin_script_exec)

target_link_libraries(plugin_script_exec PRIVATE yuzu::sdk)

set_target_properties(plugin_script_exec PROPERTIES
  PREFIX ""
  OUTPUT_NAME "script_exec"
)

yuzu_set_compiler_flags(plugin_script_exec)

install(TARGETS plugin_script_exec LIBRARY DESTINATION lib/yuzu/plugins)
