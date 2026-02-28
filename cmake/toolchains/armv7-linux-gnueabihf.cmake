# Cross-compilation toolchain: Linux ARMv7 hard-float (embedded / IoT)
# Install toolchain: apt install gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf

set(CMAKE_SYSTEM_NAME      Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)

set(TOOLCHAIN_PREFIX arm-linux-gnueabihf)

find_program(CMAKE_C_COMPILER   ${TOOLCHAIN_PREFIX}-gcc   REQUIRED)
find_program(CMAKE_CXX_COMPILER ${TOOLCHAIN_PREFIX}-g++   REQUIRED)
find_program(CMAKE_AR           ${TOOLCHAIN_PREFIX}-ar     REQUIRED)
find_program(CMAKE_RANLIB       ${TOOLCHAIN_PREFIX}-ranlib REQUIRED)
find_program(CMAKE_STRIP        ${TOOLCHAIN_PREFIX}-strip  REQUIRED)

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
