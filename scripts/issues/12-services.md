## Summary

New **services** plugin that inventories system services and provides lifecycle management actions (start, stop, restart, change startup type).

## Actions

- **list** — Lists all installed services with name, display name, status, and startup type. Output: `svc|name|display_name|status|startup_type` per service.
- **running** — Lists only currently running services. Same format as `list` but filtered.
- **startup_types** — Lists all services grouped by startup type (Auto, Manual, Disabled). Output: `startup|type|service_name` per service.
- **start** — Params: `name` (required). Starts a stopped service. Output: `status|ok/error`, `message|...`.
- **stop** — Params: `name` (required). Stops a running service. Output: `status|ok/error`, `message|...`.
- **restart** — Params: `name` (required). Stops then starts a service. Output: `status|ok/error`, `message|...`.
- **set_startup** — Params: `name` (required), `type` (required: auto/manual/disabled). Changes a service's startup type. Output: `status|ok/error`, `message|...`.

## Notes

- **Windows**: Use Service Control Manager API (`OpenSCManager`, `EnumServicesStatusEx`, `StartService`, `ControlService`, `ChangeServiceConfig`).
- **Linux**: Use `systemctl` for systemd systems. Detect init system (systemd vs SysV) and adapt.
- **macOS**: Use `launchctl` for launchd services.

## Files

- `agents/plugins/services/src/services_plugin.cpp` (new)
- `agents/plugins/services/CMakeLists.txt` (new)
- `agents/plugins/services/meson.build` (new)
