include(${CMAKE_SOURCE_DIR}/cmake/modules/CompilerFlags.cmake)

add_library(plugin_procfetch SHARED
  src/procfetch_plugin.cpp
)
add_library(yuzu::plugin_procfetch ALIAS plugin_procfetch)

target_link_libraries(plugin_procfetch PRIVATE yuzu::sdk)

if(WIN32)
  target_link_libraries(plugin_procfetch PRIVATE bcrypt)
else()
  find_package(OpenSSL REQUIRED)
  target_link_libraries(plugin_procfetch PRIVATE OpenSSL::Crypto)
endif()

set_target_properties(plugin_procfetch PROPERTIES
  PREFIX ""
  OUTPUT_NAME "procfetch"
)

yuzu_set_compiler_flags(plugin_procfetch)

install(TARGETS plugin_procfetch LIBRARY DESTINATION lib/yuzu/plugins)
