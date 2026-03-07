## Summary

New **os_info** plugin that reports detailed operating system information beyond what the existing status plugin's `info` action provides (which only returns OS name, arch, and hostname).

## Actions

- **os_name** — Returns the full OS product name (e.g., "Windows 11 Pro", "Ubuntu 24.04 LTS"). Output: `os_name|Windows 11 Pro`.
- **os_version** — Returns the OS version number (e.g., "10.0.22631", "6.8.0-41-generic"). Output: `os_version|10.0.22631`.
- **os_build** — Returns the OS build number or kernel build string. Output: `os_build|22631.4460`.
- **os_arch** — Returns the OS architecture (x86, x86_64, arm64). Output: `os_arch|x86_64`.
- **uptime** — Returns the system uptime as total seconds and a human-readable string. Output: `uptime_seconds|86400`, `uptime_display|1d 0h 0m`.

## Notes

- **Windows**: `RtlGetVersion` for version/build (avoids manifest issues with `GetVersionEx`), registry `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` for product name and UBR.
- **Linux**: Parse `/etc/os-release` for name, `/proc/version` for kernel, `/proc/uptime` for uptime.
- **macOS**: `sw_vers` for product name/version/build, `sysctl kern.boottime` for uptime.
- The existing `status` plugin `info` action returns `os|Linux` and `arch|x86_64`. This plugin provides richer detail.

## Files

- `agents/plugins/os_info/src/os_info_plugin.cpp` (new)
- `agents/plugins/os_info/CMakeLists.txt` (new)
- `agents/plugins/os_info/meson.build` (new)
