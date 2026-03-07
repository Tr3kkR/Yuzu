## Summary

New **sccm** plugin (Windows-only) that queries Microsoft SCCM/ConfigMgr client status and provides actions to trigger policy and inventory cycles.

## Actions

- **client_version** — Returns the installed SCCM client (ccmexec) version. Returns `installed|false` if SCCM is not present. Output: `installed|true/false`, `version|X.Y.Z`, `client_path|...`.
- **site** — Returns the assigned SCCM site code and management point. Output: `site_code|ABC`, `management_point|mp.corp.com`, `assignment_type|auto/manual`.
- **trigger_machine_policy** — Triggers an SCCM Machine Policy Retrieval and Evaluation Cycle. Equivalent to triggering schedule `{00000000-0000-0000-0000-000000000021}`. Output: `status|ok/error`, `message|...`.
- **trigger_hw_inventory** — Triggers an SCCM Hardware Inventory Cycle. Equivalent to triggering schedule `{00000000-0000-0000-0000-000000000001}`. Output: `status|ok/error`, `message|...`.

## Notes

- **Windows only**: Use WMI namespace `ROOT\ccm` (classes `SMS_Client`, `CCM_ClientUtilities`). Trigger cycles via `CPApplet.CPAppletMgr` COM or WMI method `TriggerSchedule`.
- Check for SCCM client presence by looking for `ccmexec.exe` service or the WMI namespace.
- On non-Windows platforms, return `error|platform not supported`.

## Files

- `agents/plugins/sccm/src/sccm_plugin.cpp` (new)
- `agents/plugins/sccm/CMakeLists.txt` (new)
- `agents/plugins/sccm/meson.build` (new)
