## Summary

New **installed_apps** plugin that inventories all software installed on the system, with the ability to query specific applications by name.

## Actions

- **list** — Lists all installed applications with name, version, publisher, and install date. Output: `app|name|version|publisher|install_date` per app.
- **query** — Params: `name` (required). Checks if a specific application is installed and returns its version(s). Supports partial name matching. Output: `found|true/false`, `app|name|version|publisher` per match.

## Notes

- **Windows**: Read from registry `HKLM/HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*` (both 32-bit and 64-bit views).
- **Linux**: Query package manager (`dpkg -l`, `rpm -qa`, or `pacman -Q`). Detect which package manager is available.
- **macOS**: Parse `/Applications/*.app/Contents/Info.plist` for GUI apps, `pkgutil --pkgs` for packages.
- Large output — consider streaming results line-by-line (the plugin framework already supports this via repeated `write_output` calls).

## Files

- `agents/plugins/installed_apps/src/installed_apps_plugin.cpp` (new)
- `agents/plugins/installed_apps/CMakeLists.txt` (new)
- `agents/plugins/installed_apps/meson.build` (new)
