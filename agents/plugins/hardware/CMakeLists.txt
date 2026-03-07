include(${CMAKE_SOURCE_DIR}/cmake/modules/CompilerFlags.cmake)

add_library(plugin_hardware SHARED
  src/hardware_plugin.cpp
)
add_library(yuzu::plugin_hardware ALIAS plugin_hardware)

target_link_libraries(plugin_hardware PRIVATE yuzu::sdk)

if(WIN32)
  target_link_libraries(plugin_hardware PRIVATE wbemuuid ole32 oleaut32)
endif()

set_target_properties(plugin_hardware PROPERTIES
  PREFIX ""
  OUTPUT_NAME "hardware"
)

yuzu_set_compiler_flags(plugin_hardware)

install(TARGETS plugin_hardware LIBRARY DESTINATION lib/yuzu/plugins)
