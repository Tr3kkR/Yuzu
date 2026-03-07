@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
set PATH=C:\Users\natha\vcpkg\installed\x64-windows\tools\protobuf;C:\Users\natha\vcpkg\installed\x64-windows\tools\grpc;%PATH%
cd /d C:\Users\natha\Yuzu
meson compile -C builddir
