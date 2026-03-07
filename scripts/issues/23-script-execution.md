## Summary

New **script_exec** plugin that executes arbitrary commands and scripts on the agent host. This is the most powerful and most security-sensitive plugin — it provides general-purpose remote execution capability.

## Actions

- **exec** — Params: `command` (required), `args` (optional), `timeout` (optional, default 300s). Executes a command-line process and returns stdout, stderr, and exit code.
- **powershell** — Params: `script` (required), `timeout` (optional, default 300s). Executes a PowerShell script block via `powershell.exe -Command`. Windows-only.
- **batch** — Params: `script` (required), `timeout` (optional, default 300s). Executes a batch script via `cmd.exe /c`. Windows-only.
- **bash** — Params: `script` (required), `timeout` (optional, default 300s). Executes a bash script via `/bin/bash -c`. Linux/macOS only.

## Output Format

All actions stream output line-by-line via `write_output()`:
- `stdout|<line>` per line of stdout
- `stderr|<line>` per line of stderr
- `exit_code|N` on completion
- `status|ok/error/timeout`

## Notes

- **Security**: This plugin is effectively "remote code execution as a feature." It MUST:
  - Only execute commands from authorized, authenticated server sessions.
  - Log all executions with full command text, user identity, and timestamps.
  - Support a configurable allowlist/blocklist of permitted commands.
  - Enforce the timeout to prevent runaway processes.
- **Implementation**: Use `popen` / `CreateProcess` with stdout/stderr pipe redirection. Stream output in real-time rather than buffering.
- Consider running scripts in a sandboxed context (low-privilege user, restricted filesystem access) by default.

## Files

- `agents/plugins/script_exec/src/script_exec_plugin.cpp` (new)
- `agents/plugins/script_exec/CMakeLists.txt` (new)
- `agents/plugins/script_exec/meson.build` (new)
