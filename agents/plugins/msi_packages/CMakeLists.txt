include(${CMAKE_SOURCE_DIR}/cmake/modules/CompilerFlags.cmake)

add_library(plugin_msi_packages SHARED
  src/msi_packages_plugin.cpp
)
add_library(yuzu::plugin_msi_packages ALIAS plugin_msi_packages)

target_link_libraries(plugin_msi_packages PRIVATE yuzu::sdk)

if(WIN32)
  target_link_libraries(plugin_msi_packages PRIVATE msi)
endif()

set_target_properties(plugin_msi_packages PROPERTIES
  PREFIX ""
  OUTPUT_NAME "msi_packages"
)

yuzu_set_compiler_flags(plugin_msi_packages)

install(TARGETS plugin_msi_packages LIBRARY DESTINATION lib/yuzu/plugins)
