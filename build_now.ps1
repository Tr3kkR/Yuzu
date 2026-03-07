$batContent = @"
@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >/dev/null 2>&1
set PATH=C:\Users\natha\vcpkg\installed\x64-windows\tools\protobuf;C:\Users\natha\vcpkg\installed\x64-windows\tools\grpc;%PATH%
cd /d C:\Users\natha\Yuzu
meson compile -C builddir
"@
$batContent | Out-File -Encoding ascii "C:\Users\natha\Yuzu\_build_tmp.bat"
& cmd /c "C:\Users\natha\Yuzu\_build_tmp.bat"
