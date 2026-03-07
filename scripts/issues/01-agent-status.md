## Summary

Extend the existing **status** plugin (`agents/plugins/status/`) to cover remaining agent introspection queries. The plugin already reports version, build number, git commit, platform info, health metrics, installed plugins, connection details, and full config. This issue tracks the remaining gaps.

## Actions to Add

- **modules** — List installed agent modules/plugins with version, description, and loaded status. Highlights any agent that has a different plugin set compared to peers (anomaly detection). Output: `module|name|version|status` per module.
- **switch** — Report which Yuzu server ("switch") the agent is connected to, including session ID, connection duration, and reconnect count. Output: `switch_address|host:port`, `session_id|...`, `connected_since|epoch_ms`, `reconnect_count|N`.

## Notes

- `modules` overlaps with the existing `plugins` action but adds loaded/unloaded status and peer-comparison metadata.
- `switch` extends the existing `connection` action with session-level detail.
- Output follows the existing `key|value` pipe-delimited convention.
- Cross-platform: fully portable (data comes from agent internals, no OS calls).

## Files

- `agents/plugins/status/src/status_plugin.cpp`
- `agents/core/src/agent.cpp` (may need to expose session metadata via config keys)
