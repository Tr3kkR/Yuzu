include(${CMAKE_SOURCE_DIR}/cmake/modules/CompilerFlags.cmake)

add_library(plugin_device_identity SHARED
  src/device_identity_plugin.cpp
)
add_library(yuzu::plugin_device_identity ALIAS plugin_device_identity)

target_link_libraries(plugin_device_identity PRIVATE yuzu::sdk)

if(WIN32)
  target_link_libraries(plugin_device_identity PRIVATE netapi32 secur32)
endif()

set_target_properties(plugin_device_identity PROPERTIES
  PREFIX ""
  OUTPUT_NAME "device_identity"
)

yuzu_set_compiler_flags(plugin_device_identity)

install(TARGETS plugin_device_identity LIBRARY DESTINATION lib/yuzu/plugins)
