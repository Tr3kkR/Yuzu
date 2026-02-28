# Tests — uses Catch2 (pulled via vcpkg)
find_package(Catch2 3 CONFIG REQUIRED)
include(Catch)

add_executable(yuzu_tests
  unit/test_plugin_loader.cpp
)

target_link_libraries(yuzu_tests
  PRIVATE
    yuzu::agent_core
    yuzu::sdk
    Catch2::Catch2WithMain
)

catch_discover_tests(yuzu_tests)
