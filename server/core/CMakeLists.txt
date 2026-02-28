include(${CMAKE_SOURCE_DIR}/cmake/modules/CompilerFlags.cmake)

add_library(yuzu_server_core STATIC
  src/server.cpp
)
add_library(yuzu::server_core ALIAS yuzu_server_core)

target_include_directories(yuzu_server_core PUBLIC include)

target_link_libraries(yuzu_server_core
  PUBLIC
    yuzu::sdk
    yuzu_proto
    gRPC::grpc++
    spdlog::spdlog
)

yuzu_set_compiler_flags(yuzu_server_core)

add_executable(yuzu-server src/main.cpp)

target_link_libraries(yuzu-server
  PRIVATE
    yuzu::server_core
    CLI11::CLI11
)

yuzu_set_compiler_flags(yuzu-server)

install(TARGETS yuzu-server RUNTIME DESTINATION bin)
