#!/bin/bash
# setup_msvc_env.sh - Source this before running Claude Code or building Yuzu
# Usage: source ./setup_msvc_env.sh
#
# Sets up the full MSVC + vcpkg + protobuf/gRPC toolchain for MSYS2 bash.
# After sourcing, you can run cmake, meson, ninja, cl.exe etc. directly.

# ── Version pins (update when toolchain upgrades) ────────────────────────────
_MSVC_VER="14.44.35207"
_SDK_VER="10.0.22621.0"

# ── Base directories (Unix-style paths for MSYS2) ────────────────────────────
_VS_ROOT="/c/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools"
_VS_INSTALLER="/c/Program Files (x86)/Microsoft Visual Studio/Installer"
_VC_TOOLS="${_VS_ROOT}/VC/Tools/MSVC/${_MSVC_VER}"
_WIN_SDK="/c/Program Files (x86)/Windows Kits/10"
_VCPKG="/c/Users/natha/vcpkg"
_CMAKE_DIR="/c/Program Files/CMake/bin"
_MESON_DIR="/c/Users/natha/AppData/Local/Packages/PythonSoftwareFoundation.Python.3.13_qbz5n2kfra8p0/LocalCache/local-packages/Python313/Scripts"

# ── Compiler selection (force MSVC, never Clang) ─────────────────────────────
export CC="cl.exe"
export CXX="cl.exe"

# ── CMake / build config ─────────────────────────────────────────────────────
export CMAKE_GENERATOR="Ninja"
export CMAKE_BUILD_TYPE="Debug"

# ── vcpkg ─────────────────────────────────────────────────────────────────────
export VCPKG_ROOT="C:\\Users\\natha\\vcpkg"
export CMAKE_TOOLCHAIN_FILE="C:\\Users\\natha\\vcpkg\\scripts\\buildsystems\\vcpkg.cmake"
export VCPKG_DEFAULT_TRIPLET="x64-windows"

# ── INCLUDE paths for cl.exe (Windows backslash format — cl.exe is native) ───
_VC_TOOLS_WIN="C:\\Program Files (x86)\\Microsoft Visual Studio\\2022\\BuildTools\\VC\\Tools\\MSVC\\${_MSVC_VER}"
_WIN_SDK_WIN="C:\\Program Files (x86)\\Windows Kits\\10"
export INCLUDE="${_VC_TOOLS_WIN}\\include;${_WIN_SDK_WIN}\\Include\\${_SDK_VER}\\ucrt;${_WIN_SDK_WIN}\\Include\\${_SDK_VER}\\um;${_WIN_SDK_WIN}\\Include\\${_SDK_VER}\\shared"

# ── LIB paths for link.exe (Windows backslash format) ────────────────────────
export LIB="${_VC_TOOLS_WIN}\\lib\\x64;${_WIN_SDK_WIN}\\Lib\\${_SDK_VER}\\ucrt\\x64;${_WIN_SDK_WIN}\\Lib\\${_SDK_VER}\\um\\x64"

# ── PATH (Unix forward-slash format for MSYS2) ──────────────────────────────
#
# Order matters — we prepend so our tools win over any MSYS2/mingw defaults.
# Specifically: cl.exe before gcc, CMake before MSYS cmake, etc.
#
# Components:
#   1. MSVC compiler + linker (cl.exe, link.exe, lib.exe)
#   2. vswhere.exe (needed if vcvars64.bat is ever called)
#   3. CMake (standalone install — more recent than VS bundled)
#   4. Ninja (VS bundled)
#   5. Meson + pip-installed ninja (Python Scripts dir)
#   6. vcpkg root (vcpkg.exe)
#   7. protoc + grpc_cpp_plugin (vcpkg tools)
#   8. Windows SDK bin (rc.exe, mt.exe, midl.exe)
_NEW_PATH=""
_NEW_PATH+="${_VC_TOOLS}/bin/Hostx64/x64:"
_NEW_PATH+="${_VS_INSTALLER}:"
_NEW_PATH+="${_CMAKE_DIR}:"
_NEW_PATH+="${_VS_ROOT}/Common7/IDE/CommonExtensions/Microsoft/CMake/Ninja:"
_NEW_PATH+="${_MESON_DIR}:"
_NEW_PATH+="${_VCPKG}:"
_NEW_PATH+="${_VCPKG}/installed/x64-windows/tools/protobuf:"
_NEW_PATH+="${_VCPKG}/installed/x64-windows/tools/grpc:"
_NEW_PATH+="${_WIN_SDK}/bin/${_SDK_VER}/x64:"

export PATH="${_NEW_PATH}${PATH}"

# ── Verify ───────────────────────────────────────────────────────────────────
echo "MSVC environment loaded for MSYS2 bash."
echo ""
_check() {
    local name="$1"
    local path
    path=$(which "$name" 2>/dev/null)
    if [ -n "$path" ]; then
        printf "  %-20s %s\n" "$name" "$path"
    else
        printf "  %-20s \e[31mNOT FOUND\e[0m\n" "$name"
    fi
}
_check cl.exe
_check link.exe
_check cmake
_check ninja
_check meson
_check vcpkg
_check protoc
_check grpc_cpp_plugin
_check rc.exe
echo ""
echo "  VCPKG_ROOT=$VCPKG_ROOT"
echo "  CMAKE_GENERATOR=$CMAKE_GENERATOR"
echo "  CC=$CC  CXX=$CXX"

# Clean up temp vars
unset _MSVC_VER _SDK_VER _VS_ROOT _VS_INSTALLER _VC_TOOLS _WIN_SDK _VCPKG
unset _CMAKE_DIR _MESON_DIR _VC_TOOLS_WIN _WIN_SDK_WIN _NEW_PATH
unset -f _check
