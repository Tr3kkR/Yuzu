# SDK: header-only interface library — plugins and agents link against this.
add_library(yuzu_sdk INTERFACE)
add_library(yuzu::sdk ALIAS yuzu_sdk)

target_include_directories(yuzu_sdk
  INTERFACE
    $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/generated/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_compile_features(yuzu_sdk INTERFACE cxx_std_23)

install(
  TARGETS yuzu_sdk
  EXPORT  yuzuTargets
)
