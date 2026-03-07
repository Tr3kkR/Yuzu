## Summary

Extend process management beyond the existing **procfetch** plugin (which only enumerates processes with SHA-1 hashes). New **processes** plugin for targeted queries and process lifecycle actions.

## Actions

- **list** — Lists running processes with PID, name, user, CPU%, and memory. Output: `proc|pid|name|user|cpu_pct|mem_kb` per process.
- **query** — Params: `name` (required). Checks if a specific process is running. Returns all matching instances. Output: `found|true/false`, `proc|pid|name|user|cmd` per match.
- **kill** — Params: `pid` or `name` (required), `force` (optional, default false). Terminates a process by PID or name. Uses SIGTERM by default, SIGKILL if `force=true`. Output: `status|ok/error`, `killed_pid|N`.
- **start** — Params: `command` (required), `args` (optional). Starts a new process. Runs detached from the agent. Output: `status|ok/error`, `pid|N`.

## Notes

- **procfetch** already does process enumeration with SHA-1 hashing. This plugin is lighter-weight (no hashing) but adds query/kill/start actions.
- **Windows**: `CreateToolhelp32Snapshot` for listing, `TerminateProcess` for kill, `CreateProcess` for start.
- **Linux**: `/proc` filesystem for listing, `kill()` syscall, `fork+exec` for start.
- **Security**: Kill and start are privileged operations — audit log all invocations.

## Files

- `agents/plugins/processes/src/processes_plugin.cpp` (new)
- `agents/plugins/processes/CMakeLists.txt` (new)
- `agents/plugins/processes/meson.build` (new)
