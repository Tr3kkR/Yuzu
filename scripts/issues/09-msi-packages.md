## Summary

New **msi_packages** plugin (Windows-only) that enumerates installed MSI packages and their product codes for patch management and software asset tracking.

## Actions

- **list** — Lists all installed MSI packages with product name, version, product code, and install location. Output: `msi|product_code|name|version|install_location` per package.
- **product_codes** — Returns a compact list of all MSI product code GUIDs. Useful for scripted uninstalls or compliance checks. Output: `product_code|{GUID}|name` per package.

## Notes

- **Windows only**: Use `MsiEnumProducts` + `MsiGetProductInfo` from the Windows Installer API (`msi.h`). Link against `msi.lib`.
- On Linux/macOS, these actions return `error|platform not supported` with exit code 1.
- Product codes are GUIDs in `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}` format.

## Files

- `agents/plugins/msi_packages/src/msi_packages_plugin.cpp` (new)
- `agents/plugins/msi_packages/CMakeLists.txt` (new)
- `agents/plugins/msi_packages/meson.build` (new)
