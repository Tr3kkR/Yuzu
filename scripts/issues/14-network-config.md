## Summary

New **network_config** plugin that reports network adapter configuration, IP addressing, DNS settings, and proxy configuration.

## Actions

- **adapters** — Lists all network adapters with name, MAC address, speed, and status (up/down). Output: `adapter|name|mac|speed_mbps|status` per adapter.
- **ip_addresses** — Lists all assigned IP addresses (IPv4 and IPv6) with adapter, subnet mask, and gateway. Output: `ip|adapter|address|prefix_len|gateway` per address.
- **dns_servers** — Lists configured DNS servers per adapter. Output: `dns|adapter|server_address|type` per server.
- **proxy** — Returns the system proxy configuration (HTTP, HTTPS, SOCKS, PAC URL, bypass list). Output: `proxy_type|http/socks/pac`, `proxy_address|host:port`, `bypass|list`.

## Notes

- **Windows**: `GetAdaptersAddresses` for adapters/IPs/DNS, `WinHttpGetIEProxyConfigForCurrentUser` for proxy.
- **Linux**: Parse `/sys/class/net/`, `ip addr show`, `/etc/resolv.conf`, and environment variables (`http_proxy`, `https_proxy`).
- **macOS**: `ifconfig`, `scutil --dns`, `networksetup -getwebproxy`.
- The existing **netstat** plugin covers listening ports and connections. This plugin covers configuration.

## Files

- `agents/plugins/network_config/src/network_config_plugin.cpp` (new)
- `agents/plugins/network_config/CMakeLists.txt` (new)
- `agents/plugins/network_config/meson.build` (new)
