## Summary

New **event_logs** plugin that queries Windows Event Logs (or journald on Linux) for error entries and matching criteria, with actions to clear or export logs.

## Actions

- **errors** — Params: `log` (optional, default System), `hours` (optional, default 24). Returns error-level entries from the specified log within the time window. Output: `event|log|event_id|source|time|message` per entry.
- **query** — Params: `log` (required), `filter` (required: XPath or keyword), `count` (optional, default 100). Searches event log entries matching the filter criteria. Output: `event|log|event_id|level|source|time|message` per entry.
- **clear** — Params: `log` (required). Clears all entries from the specified event log. Output: `status|ok/error`, `message|...`.
- **export** — Params: `log` (required), `format` (optional: evtx/csv, default evtx). Exports the specified event log to a file. Returns the file path. Output: `status|ok/error`, `path|...`, `size|N`.

## Notes

- **Windows**: Use Windows Event Log API (`EvtQuery`, `EvtNext`, `EvtClear`, `EvtExportLog`) or `wevtutil` subprocess.
- **Linux**: Use `journalctl` for systemd journal queries. Map `log` param to journal units.
- **macOS**: Use `log show` / `log stream` command.
- Query results can be very large — use `count` param to limit and stream results line-by-line.

## Files

- `agents/plugins/event_logs/src/event_logs_plugin.cpp` (new)
- `agents/plugins/event_logs/CMakeLists.txt` (new)
- `agents/plugins/event_logs/meson.build` (new)
