## Summary

New **agent_actions** plugin providing management actions that modify the agent's runtime state. These are mutating operations (unlike the read-only status/diagnostics plugins).

## Actions

- **restart** — Triggers a graceful restart of the Yuzu Agent process. Shuts down plugins, closes gRPC stream, then re-execs the process.
- **refresh_config** — Reloads agent configuration from disk/server without a full restart. Updates heartbeat interval, log level, TLS settings.
- **reconnect** — Params: `server` (optional). Disconnects from the current server and reconnects, optionally to a different server address.
- **set_log_level** — Params: `level` (required: trace/debug/info/warn/error). Changes the agent's spdlog log level at runtime. Updates the config map so the status plugin reflects the change.

## Notes

- **restart**: Use `execv()`/`CreateProcess()` to replace the current process. Must flush logs and close DB handles first.
- **refresh_config**: Requires a config-reload mechanism in the agent core (currently config is immutable after startup).
- **reconnect**: Cancel the current Subscribe stream and re-register with the server.
- **set_log_level**: Call `spdlog::set_level()` and update the `agent.log_level` config key.
- All actions return `status|ok` or `status|error` with a `message|...` line.

## Files

- `agents/plugins/agent_actions/src/agent_actions_plugin.cpp` (new)
- `agents/plugins/agent_actions/CMakeLists.txt` (new)
- `agents/plugins/agent_actions/meson.build` (new)
- `agents/core/src/agent.cpp` (expose restart/reconnect/config-reload hooks)
