include(${CMAKE_SOURCE_DIR}/cmake/modules/CompilerFlags.cmake)

add_library(yuzu_server_core STATIC
  src/server.cpp
  src/auth.cpp
  src/auto_approve.cpp
  src/dashboard_ui.cpp
  src/chargen_ui.cpp
  src/procfetch_ui.cpp
  src/login_ui.cpp
  src/settings_ui.cpp
  src/nvd_db.cpp
  src/nvd_client.cpp
  src/nvd_sync.cpp
)
add_library(yuzu::server_core ALIAS yuzu_server_core)

target_include_directories(yuzu_server_core PUBLIC include)

find_package(nlohmann_json CONFIG REQUIRED)
find_package(unofficial-sqlite3 CONFIG REQUIRED)

target_link_libraries(yuzu_server_core
  PUBLIC
    yuzu::sdk
    yuzu_proto
    spdlog::spdlog
    httplib::httplib
    nlohmann_json::nlohmann_json
    unofficial::sqlite3::sqlite3
)

# Platform-specific crypto for auth module
if(WIN32)
  target_link_libraries(yuzu_server_core PUBLIC bcrypt)
else()
  find_package(OpenSSL REQUIRED)
  target_link_libraries(yuzu_server_core PUBLIC OpenSSL::Crypto)
endif()

yuzu_set_compiler_flags(yuzu_server_core)

add_executable(yuzu-server src/main.cpp)

target_link_libraries(yuzu-server
  PRIVATE
    yuzu::server_core
    CLI11::CLI11
)

yuzu_set_compiler_flags(yuzu-server)

install(TARGETS yuzu-server RUNTIME DESTINATION bin)
