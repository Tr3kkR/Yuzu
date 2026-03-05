include(${CMAKE_SOURCE_DIR}/cmake/modules/CompilerFlags.cmake)

# ── Agent static library (re-used by tests) ───────────────────────────────────
add_library(yuzu_agent_core STATIC
  src/agent.cpp
  src/plugin_loader.cpp
)
add_library(yuzu::agent_core ALIAS yuzu_agent_core)

target_include_directories(yuzu_agent_core
  PUBLIC  include
  PRIVATE src
)

target_link_libraries(yuzu_agent_core
  PUBLIC
    yuzu::sdk
    yuzu_proto
    spdlog::spdlog
)

yuzu_set_compiler_flags(yuzu_agent_core)

# ── Agent executable ──────────────────────────────────────────────────────────
add_executable(yuzu-agent src/main.cpp)

target_link_libraries(yuzu-agent
  PRIVATE
    yuzu::agent_core
    CLI11::CLI11
)

yuzu_set_compiler_flags(yuzu-agent)

install(TARGETS yuzu-agent RUNTIME DESTINATION bin)
