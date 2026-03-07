## Summary

New **diagnostics** plugin that exposes agent runtime diagnostic information: current log level, installed TLS certificates, and connection history to the server.

## Actions

- **log_level** — Returns the agent's current spdlog log level (trace/debug/info/warn/error). Output: `log_level|info`.
- **certificates** — Lists TLS certificates configured for the agent (CA cert, client cert, client key paths and expiry dates). Parses PEM files to extract subject, issuer, and expiry. Output: `cert|type|subject|issuer|expires` per cert.
- **connection_history** — Returns a log of recent connection/reconnection events to the server, including timestamps, duration, and disconnect reasons. Output: `event|timestamp|type|detail` per event.

## Notes

- **Log level**: Read from `agent.log_level` config key (already populated).
- **Certificates**: Requires PEM parsing. Use OpenSSL on Linux/macOS, Windows CryptoAPI on Windows. If certs aren't configured (no-TLS mode), return empty results.
- **Connection history**: Agent core needs to record connect/disconnect events in a ring buffer or SQLite table, then expose via config keys.
- Cross-platform: certificate parsing is platform-specific; log level and connection history are portable.

## Files

- `agents/plugins/diagnostics/src/diagnostics_plugin.cpp` (new)
- `agents/plugins/diagnostics/CMakeLists.txt` (new)
- `agents/plugins/diagnostics/meson.build` (new)
- `agents/core/src/agent.cpp` (connection history tracking)
