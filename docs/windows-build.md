# Windows Build Reference

Reference for the Windows build toolchain paths and prerequisites. CLAUDE.md keeps only the load-bearing rule ("MSYS2 bash + `setup_msvc_env.sh`, NOT `vcvars64.bat`"); this document is the path inventory that `setup_msvc_env.sh` manages for you.

## Build from MSYS2 bash

```bash
source ./setup_msvc_env.sh           # MSVC paths
source scripts/ensure-erlang.sh      # Erlang/OTP on PATH (gateway target)
meson compile -C build-windows       # canonical Windows dir; coexists with build-linux from WSL2
```

**Do NOT use `vcvars64.bat`.** It returns exit code 1 due to optional extension failures (Clang, bundled CMake, ConnectionManager) even though cl.exe is set up correctly. This causes `.bat` wrapper scripts to abort or misbehave. `setup_msvc_env.sh` sets all MSVC paths directly in MSYS2 bash and is the only supported build method.

`scripts/ensure-erlang.sh` is the sibling helper for the Erlang/OTP toolchain (see "Toolchain activation (Erlang on PATH)" in CLAUDE.md's Erlang gateway section). Source both before invoking meson if your build touches the gateway custom_target.

## Toolchain paths

All paths are configured by `setup_msvc_env.sh`. Do **not** use Clang (`C:\Program Files\LLVM\bin`) — must use cl.exe / MSVC.

| Tool | Path |
|---|---|
| cl.exe | `C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\cl.exe` |
| cmake.exe | `C:\Program Files\CMake\bin\cmake.exe` (needed by Meson's cmake dep method) |
| ninja.exe | Installed with CMake or VS BuildTools |
| python | `C:\Python314\python.exe` (system-wide, installed via Chocolatey) |
| meson | `C:\Python314\Scripts\meson.exe` (`pip install meson==1.9.2`) |
| vcpkg | `C:\vcpkg` (`VCPKG_ROOT`) |
| protoc | `C:\vcpkg\installed\x64-windows\tools\protobuf\protoc.exe` |
| grpc_cpp_plugin | `C:\vcpkg\installed\x64-windows\tools\grpc\grpc_cpp_plugin.exe` |
