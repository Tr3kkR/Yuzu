# Troubleshooting Guide

## Agent Won't Connect

**Symptoms:** Agent logs `Failed to register` or `UNAVAILABLE` errors.

| Check | Fix |
|-------|-----|
| Wrong server address | Verify `--server host:port` matches server's `--listen` address |
| TLS mismatch | Ensure agent has `--ca-cert` pointing to the server's CA |
| Enrollment not approved | Check Settings > Pending Agents in the dashboard |
| Firewall | Verify port 50051 is open between agent and server |
| Gateway mode | If using gateway, agent connects to gateway port (50051), not server directly |

```bash
# Test connectivity
nc -zv yuzu-server 50051

# Check agent logs
yuzu-agent --server yuzu-server:50051 --no-tls --log-level debug
```

## Dashboard Returns 502/503

| Check | Fix |
|-------|-----|
| Server not running | `systemctl status yuzu-server` |
| Port conflict | `ss -tlnp | grep 8080` — kill conflicting process |
| HTTPS redirect loop | Use `--no-https-redirect` if HTTPS cert is not set up |
| Draining/shutdown | Check if `/readyz` returns 503 — server may be shutting down |

## Policy Non-Compliance

| Check | Fix |
|-------|-----|
| Stale compliance data | POST `/api/v1/policies/{id}/evaluate` to force re-evaluation |
| CEL expression error | Check policy store logs for parse errors |
| Trigger not firing | Verify trigger type and interval in policy YAML |
| Wrong scope | Test scope expression against target device |

## High Memory Usage

| Check | Fix |
|-------|-----|
| SQLite WAL growth | Run `PRAGMA wal_checkpoint(TRUNCATE)` on large .db files |
| Response retention too long | Reduce `--response-retention-days` (default: 90) |
| Too many connected agents | Check `--max-agents` limit, consider gateway for distribution |
| Agent thread pool | Agent thread pool is bounded (4-32 workers, 1000 max queue) |

## Gateway Disconnections

| Check | Fix |
|-------|-----|
| Heartbeat timeout | Increase agent `--heartbeat` interval or server `--session-timeout` |
| Erlang VM crash | Check `/var/log/yuzu/gateway-crash.dump` |
| Upstream unreachable | Verify server `--gateway-upstream` address matches gateway config |
| Process limit | Erlang default process limit is 262144 — sufficient for most fleets |

## Certificate Errors

| Check | Fix |
|-------|-----|
| Expired cert | `openssl x509 -enddate -noout -in server.crt` |
| Wrong CA | Agent's `--ca-cert` must match server's signing CA |
| SAN mismatch | Server cert SAN must include the hostname agents connect to |
| Windows cert store | Verify thumbprint: `certutil -store MY` |

## Log Diagnosis

Key log patterns to search for:

```bash
# Authentication failures
grep -i "unauthorized\|auth.*fail\|invalid.*token" /var/log/yuzu/server.log

# gRPC errors
grep -i "UNAVAILABLE\|DEADLINE_EXCEEDED\|PERMISSION_DENIED" /var/log/yuzu/server.log

# SQLite errors
grep -i "sqlite\|database.*locked\|busy" /var/log/yuzu/server.log

# Migration issues
grep -i "MigrationRunner\|migrat" /var/log/yuzu/server.log
```

**Recommended log levels:**
- Production: `info` (default)
- Investigating issues: `debug`
- Deep trace: `trace` (generates high volume)
