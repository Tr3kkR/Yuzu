## Summary

New **windows_updates** plugin (Windows-only) that queries Windows Update status and provides actions to trigger scans, install updates, and clear the update cache.

## Actions

- **installed** — Params: `count` (optional, default 50). Lists recently installed Windows updates with KB number, title, and install date. Output: `update|kb|title|install_date|type` per update.
- **missing** — Lists available but not-yet-installed updates. Requires a prior scan. Output: `update|kb|title|severity|size_mb` per update.
- **failures** — Lists recent update installation failures with error codes. Output: `failure|kb|title|error_code|date` per failure.
- **scan** — Triggers a Windows Update scan for available updates. Returns when scan completes. Output: `status|ok/error`, `updates_found|N`.
- **install** — Params: `kb` (optional, installs all if omitted). Installs pending Windows updates (all or a specific KB). Output: `status|ok/error`, `installed_count|N`, `reboot_required|true/false`.
- **clear_cache** — Stops the Windows Update service, clears the `SoftwareDistribution` folder, and restarts the service. Output: `status|ok/error`, `freed_mb|N`.

## Notes

- **Windows only**: Use the Windows Update Agent (WUA) COM API (`IUpdateSearcher`, `IUpdateInstaller`) or fall back to `wuauclt` / `UsoClient` subprocesses.
- On Linux, returns `error|platform not supported`. Consider `apt`/`yum` update equivalents as a separate plugin.
- Scan and install operations can take minutes — use `report_progress()` to stream progress.
- Reboot requirements should be clearly reported but never automatically executed.

## Files

- `agents/plugins/windows_updates/src/windows_updates_plugin.cpp` (new)
- `agents/plugins/windows_updates/CMakeLists.txt` (new)
- `agents/plugins/windows_updates/meson.build` (new)
