---
title: "[P2/MEDIUM] Strengthen --allow-one-way-tls safety guards"
labels: security, enhancement, P2
assignees: ""
---

## Summary

The `--allow-one-way-tls` flag silently downgrades from mTLS to one-way TLS with only a `spdlog::warn()`. In production, accidentally setting this flag would allow any client to connect without certificate verification. This should require stronger confirmation.

## Affected Files

- `server/core/src/server.cpp` (lines 740-745)
- `server/core/src/main.cpp` — CLI flag definition

## Recommended Fix

1. **Rename flag** to `--insecure-skip-client-verify` to make the security implication explicit
2. **Require confirmation** via environment variable:
```cpp
if (cfg.allow_one_way_tls) {
    if (std::getenv("YUZU_ALLOW_INSECURE_TLS") == nullptr) {
        spdlog::error("--insecure-skip-client-verify requires YUZU_ALLOW_INSECURE_TLS=1 env var");
        return 1;
    }
    spdlog::warn("*** CLIENT CERTIFICATE VERIFICATION DISABLED ***");
    spdlog::warn("*** Any client can connect without authentication ***");
}
```

3. **Log prominently** at startup and periodically (every 5 minutes) to ensure operators notice

## Acceptance Criteria

- [ ] Flag renamed to `--insecure-skip-client-verify`
- [ ] Requires `YUZU_ALLOW_INSECURE_TLS=1` environment variable as double confirmation
- [ ] Prominent startup warning logged at ERROR level
- [ ] Periodic reminder warning logged every 5 minutes
- [ ] Old `--allow-one-way-tls` flag deprecated with helpful error message
