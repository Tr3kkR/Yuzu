## Summary

New **firewall** plugin that queries the host firewall state and provides actions to enable or disable it.

## Actions

- **state** — Returns the firewall enabled/disabled state for each profile (Domain, Private, Public on Windows; default zones on Linux). Output: `profile|name|enabled|inbound_default|outbound_default` per profile.
- **enable** — Params: `profile` (optional, default all). Enables the firewall for the specified profile or all profiles. Output: `status|ok/error`, `message|...`.
- **disable** — Params: `profile` (optional, default all). Disables the firewall for the specified profile or all profiles. Output: `status|ok/error`, `message|...`.

## Notes

- **Windows**: Use `INetFwPolicy2` COM interface or `netsh advfirewall` subprocess.
- **Linux**: Check `ufw status`, `firewalld` (via `firewall-cmd --state`), or `iptables -L`.
- **macOS**: `pfctl -s info` for packet filter state.
- **Security**: Disabling the firewall is a high-risk operation. Should require explicit authorization.

## Files

- `agents/plugins/firewall/src/firewall_plugin.cpp` (new)
- `agents/plugins/firewall/CMakeLists.txt` (new)
- `agents/plugins/firewall/meson.build` (new)
