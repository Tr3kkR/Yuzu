---
name: warn-clang-windows-compiler
enabled: true
event: bash
action: warn
pattern: 'Program Files[\\/]+LLVM[\\/]+bin[\\/]+clang(\+\+)?(\.exe)?(?![-\w])'
---

**[WARN] Don't build with the Windows LLVM Clang -- the Windows build must use `cl.exe` / MSVC.**

This command invokes `clang`/`clang++` from `C:\Program Files\LLVM\bin`. On
Windows, Yuzu compiles with MSVC `cl.exe`, not LLVM Clang.

On Windows, use:

    source ./setup_msvc_env.sh      # puts cl.exe + MSVC paths on PATH
    meson compile -C build-windows

Notes:
- Clang IS a supported compiler on Linux and macOS (`linux-clang18/19.ini`, Apple
  Clang) -- this rule only matches the Windows `Program Files\LLVM\bin` path, so it
  never fires on Unix clang builds.
- `clangd`, `clang-format`, `clang-tidy`, `clang-cl` are fine and are deliberately
  not matched.
