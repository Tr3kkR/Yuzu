include(${CMAKE_SOURCE_DIR}/cmake/modules/CompilerFlags.cmake)

add_library(plugin_event_logs SHARED
  src/event_logs_plugin.cpp
)
add_library(yuzu::plugin_event_logs ALIAS plugin_event_logs)

target_link_libraries(plugin_event_logs PRIVATE yuzu::sdk)

set_target_properties(plugin_event_logs PROPERTIES
  PREFIX ""
  OUTPUT_NAME "event_logs"
)

yuzu_set_compiler_flags(plugin_event_logs)

install(TARGETS plugin_event_logs LIBRARY DESTINATION lib/yuzu/plugins)
