include(${CMAKE_SOURCE_DIR}/cmake/modules/CompilerFlags.cmake)

add_library(plugin_users SHARED
  src/users_plugin.cpp
)
add_library(yuzu::plugin_users ALIAS plugin_users)

target_link_libraries(plugin_users PRIVATE yuzu::sdk)

if(WIN32)
  target_link_libraries(plugin_users PRIVATE wtsapi32 netapi32)
endif()

set_target_properties(plugin_users PROPERTIES
  PREFIX ""
  OUTPUT_NAME "users"
)

yuzu_set_compiler_flags(plugin_users)

install(TARGETS plugin_users LIBRARY DESTINATION lib/yuzu/plugins)
