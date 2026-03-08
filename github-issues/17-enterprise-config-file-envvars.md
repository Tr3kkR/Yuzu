---
title: "[P1/ENT] Add config file and environment variable support"
labels: enhancement, enterprise, P1
assignees: ""
---

## Summary

All configuration is via CLI flags only. Secrets (certificate paths, enrollment tokens, API keys) must be passed as command-line arguments, which are visible to all users via `ps aux` or `/proc/[pid]/cmdline`. Enterprise deployments need config files and environment variable support.

## Affected Files

- `agents/core/src/main.cpp` — CLI argument parsing
- `server/core/src/main.cpp` — CLI argument parsing
- `agents/core/include/yuzu/agent/agent.hpp` — Config struct
- `server/core/include/yuzu/server/server.hpp` — Config struct

## Recommended Implementation

### 1. Environment variables (priority)

Map all sensitive config to `YUZU_*` environment variables:

| CLI Flag | Environment Variable | Component |
|----------|---------------------|-----------|
| `--key` | `YUZU_SERVER_KEY` | Server |
| `--cert` | `YUZU_SERVER_CERT` | Server |
| `--ca-cert` | `YUZU_CA_CERT` | Both |
| `--client-key` | `YUZU_CLIENT_KEY` | Agent |
| `--client-cert` | `YUZU_CLIENT_CERT` | Agent |
| `--api-key` | `YUZU_HTTP_API_KEY` | Server |
| `--enrollment-token` | `YUZU_ENROLLMENT_TOKEN` | Both |

CLI11 supports environment variable fallbacks natively:
```cpp
app.add_option("--key", cfg.tls_server_key, "PEM server private key")
   ->envname("YUZU_SERVER_KEY");
```

### 2. Config file (TOML or YAML)

```toml
# /etc/yuzu/server.toml
[server]
listen_address = "0.0.0.0:50051"
web_address = "127.0.0.1"
web_port = 8080

[tls]
cert = "/etc/yuzu/certs/server.pem"
key = "/etc/yuzu/certs/server-key.pem"
ca_cert = "/etc/yuzu/certs/ca.pem"

[auth]
api_key_file = "/etc/yuzu/api-key"
enrollment_token_file = "/etc/yuzu/enrollment-token"
```

CLI11 can read from config files:
```cpp
app.set_config("--config", "/etc/yuzu/server.toml", "Configuration file");
```

### 3. Precedence order

`CLI flags > environment variables > config file > defaults`

## Acceptance Criteria

- [ ] All CLI flags have corresponding `YUZU_*` environment variables
- [ ] `--config` flag loads TOML config file
- [ ] Precedence: CLI > env > config > defaults
- [ ] Sensitive values never logged in plaintext
- [ ] Config file permissions validated (warn if world-readable)
- [ ] Documentation with example config files for agent and server
- [ ] `_FILE` suffix pattern supported for Docker secrets (e.g., `YUZU_SERVER_KEY_FILE=/run/secrets/key`)
