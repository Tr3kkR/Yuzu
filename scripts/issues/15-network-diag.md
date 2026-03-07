## Summary

New **network_diag** plugin for network diagnostic queries: listening ports and established connections. Complements the existing **netstat** and **sockwho** plugins with a simpler, more focused interface.

## Actions

- **listening** — Params: `protocol` (optional: tcp/udp/all, default all). Lists all listening ports with protocol, address, port, and owning process. Output: `listen|proto|address|port|pid|process_name` per port.
- **connections** — Params: `state` (optional: established/all, default established). Lists active network connections with remote address, state, and owning process. Output: `conn|proto|local_addr|local_port|remote_addr|remote_port|state|pid|process_name` per connection.

## Notes

- The existing **netstat** plugin provides raw socket enumeration. The existing **sockwho** plugin maps sockets to processes. This plugin combines both into a cleaner interface.
- **Windows**: `GetExtendedTcpTable` / `GetExtendedUdpTable` (same as netstat plugin).
- **Linux**: Parse `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, `/proc/net/udp6` and `/proc/[pid]/fd` for process mapping.
- May consolidate with or replace netstat/sockwho plugins in the future.

## Files

- `agents/plugins/network_diag/src/network_diag_plugin.cpp` (new)
- `agents/plugins/network_diag/CMakeLists.txt` (new)
- `agents/plugins/network_diag/meson.build` (new)
