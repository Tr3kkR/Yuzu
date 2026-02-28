include(${CMAKE_SOURCE_DIR}/cmake/modules/CompilerFlags.cmake)

add_library(plugin_example SHARED
  src/example_plugin.cpp
)
add_library(yuzu::plugin_example ALIAS plugin_example)

# Plugins link the SDK (headers only) and nothing else — no agent internals.
target_link_libraries(plugin_example PRIVATE yuzu::sdk)

# Strip the lib prefix on all platforms so the filename is "example.so" / "example.dll"
set_target_properties(plugin_example PROPERTIES
  PREFIX ""
  OUTPUT_NAME "example"
)

yuzu_set_compiler_flags(plugin_example)

install(TARGETS plugin_example LIBRARY DESTINATION lib/yuzu/plugins)
