## Summary

New **software_actions** plugin that performs software management operations: uninstalling applications, installing MSI packages, and repairing MSI installations.

## Actions

- **uninstall** — Params: `name` or `product_code` (required). Uninstalls an application by name (registry lookup) or MSI product code. Runs the uninstall string silently.
- **install_msi** — Params: `path` or `url` (required), `args` (optional). Installs an MSI package from a local path or network share. Runs `msiexec /i` with `/qn` (quiet) by default.
- **repair_msi** — Params: `product_code` (required). Repairs an MSI installation by product code using `msiexec /f`.

## Notes

- **Security**: These are privileged operations. The agent should verify the command came from an authorized server session before executing. Consider a confirmation/approval mechanism.
- **Windows**: Use `msiexec.exe` subprocess for MSI operations. For general uninstall, invoke the `UninstallString` from the registry.
- **Linux**: Use the system package manager (`apt remove`, `yum remove`, `dpkg -i`).
- Returns `status|ok` or `status|error` with `exit_code|N` and `output|...` lines.

## Files

- `agents/plugins/software_actions/src/software_actions_plugin.cpp` (new)
- `agents/plugins/software_actions/CMakeLists.txt` (new)
- `agents/plugins/software_actions/meson.build` (new)
