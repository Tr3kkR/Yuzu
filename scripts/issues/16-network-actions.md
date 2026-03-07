## Summary

New **network_actions** plugin providing network remediation actions commonly used in troubleshooting.

## Actions

- **flush_dns** — Flushes the local DNS resolver cache. Equivalent to `ipconfig /flushdns` (Windows) or `resolvectl flush-caches` (Linux).
- **reset_stack** — Resets the TCP/IP network stack. Equivalent to `netsh int ip reset` (Windows) or restarting `NetworkManager`/`systemd-networkd` (Linux). Requires reboot on Windows.

## Notes

- Both actions require elevated privileges.
- **Windows**: Execute `ipconfig /flushdns` and `netsh int ip reset` via subprocess.
- **Linux**: Execute `resolvectl flush-caches` or `systemd-resolve --flush-caches` for DNS, `systemctl restart NetworkManager` for stack reset.
- **macOS**: `dscacheutil -flushcache && sudo killall -HUP mDNSResponder` for DNS.
- Returns `status|ok/error` with `output|...` containing command output.

## Files

- `agents/plugins/network_actions/src/network_actions_plugin.cpp` (new)
- `agents/plugins/network_actions/CMakeLists.txt` (new)
- `agents/plugins/network_actions/meson.build` (new)
