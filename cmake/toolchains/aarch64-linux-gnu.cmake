# Cross-compilation toolchain: Linux ARM64 (aarch64-linux-gnu)
# Install toolchain: apt install gcc-aarch64-linux-gnu g++-aarch64-linux-gnu

set(CMAKE_SYSTEM_NAME      Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

set(TOOLCHAIN_PREFIX aarch64-linux-gnu)

find_program(CMAKE_C_COMPILER   ${TOOLCHAIN_PREFIX}-gcc   REQUIRED)
find_program(CMAKE_CXX_COMPILER ${TOOLCHAIN_PREFIX}-g++   REQUIRED)
find_program(CMAKE_AR           ${TOOLCHAIN_PREFIX}-ar     REQUIRED)
find_program(CMAKE_RANLIB       ${TOOLCHAIN_PREFIX}-ranlib REQUIRED)
find_program(CMAKE_STRIP        ${TOOLCHAIN_PREFIX}-strip  REQUIRED)

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
