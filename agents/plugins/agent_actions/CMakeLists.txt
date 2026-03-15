include(${CMAKE_SOURCE_DIR}/cmake/modules/CompilerFlags.cmake)

add_library(plugin_agent_actions SHARED
  src/agent_actions_plugin.cpp
)
add_library(yuzu::plugin_agent_actions ALIAS plugin_agent_actions)

target_link_libraries(plugin_agent_actions PRIVATE yuzu::sdk spdlog::spdlog)

set_target_properties(plugin_agent_actions PROPERTIES
  PREFIX ""
  OUTPUT_NAME "agent_actions"
)

yuzu_set_compiler_flags(plugin_agent_actions)

install(TARGETS plugin_agent_actions LIBRARY DESTINATION lib/yuzu/plugins)
