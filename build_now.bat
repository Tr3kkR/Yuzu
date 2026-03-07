@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >/dev/null 2>&1
set PATH=C:\Users\natha\vcpkg\installed\x64-windows\tools\protobuf;C:\Users\natha\vcpkg\installed\x64-windows\tools\grpc;%PATH%
cd /d C:\Users\natha\Yuzu
meson compile -C builddir > C:\Users\natha\Yuzu\build_log.txt 2>&1
echo EXITCODE=%ERRORLEVEL% >> C:\Users\natha\Yuzu\build_log.txt
