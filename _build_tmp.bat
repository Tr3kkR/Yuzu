@echo off
set "PATH=C:\Program Files (x86)\Microsoft Visual Studio\Installer;%PATH%"
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >/dev/null 2>&1
if errorlevel 1 (
    echo vcvars64 failed
    exit /b 1
)
where cl
set PATH=C:\Users\natha\vcpkg\installed\x64-windows\tools\protobuf;C:\Users\natha\vcpkg\installed\x64-windows\tools\grpc;%PATH%
cd /d C:\Users\natha\Yuzu
meson compile -C builddir
