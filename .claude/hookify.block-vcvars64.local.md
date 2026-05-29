---
name: block-vcvars64
enabled: true
event: bash
pattern: vcvars64\.bat
action: block
---

**[BLOCK] `vcvars64.bat` is banned on this project -- it corrupts the build shell.**

`vcvars64.bat` returns exit code 1 because of optional VS extension failures
(Clang, bundled CMake, ConnectionManager) even when `cl.exe` itself initialises
fine. That non-zero exit aborts any `.bat`/shell wrapper that sources it, leaving
a half-initialised MSVC environment.

Use instead:

    source ./setup_msvc_env.sh

This sets every MSVC path directly in MSYS2 bash without the failing extension
scripts. See `docs/windows-build.md` and project memory "Build Environment (Windows)".
