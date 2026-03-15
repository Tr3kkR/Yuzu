# Yuzu Codebase Security Review

**Date:** 2026-03-07
**Scope:** RAII & memory safety, mTLS implementation, authentication/authorization, HTTP API security, enterprise deployment readiness

---

## Executive Summary

Yuzu is a well-structured C++23 agent/server framework with a solid foundation. The mTLS implementation is above-average for a project at this stage — it includes proper certificate identity binding and peer verification. However, several issues would need to be addressed before enterprise deployment: unauthenticated HTTP endpoints, a thread-safety race in the agent command dispatch, manual JSON construction vulnerable to injection, and the absence of deployment infrastructure (containers, service units, config files).

**Overall assessment:** Good for development/lab use. Needs targeted hardening for production enterprise deployment.

---

## 1. RAII & Memory Safety

### Strengths

- **Smart pointer discipline is strong.** Factory methods return `std::unique_ptr<Agent>` / `std::unique_ptr<Server>` (`agent.cpp:412`, `server.cpp:984`). gRPC servers, HTTP servers, and loggers are all owned via `unique_ptr`/`shared_ptr`.
- **Plugin loader has correct RAII.** `PluginHandle` implements move semantics with proper cleanup in the destructor (`plugin_loader.cpp:28-51`). The move-assignment operator correctly closes the old handle before taking ownership. Error paths call `YUZU_DLCLOSE()` before returning `std::unexpected`.
- **`std::expected<T, E>` used idiomatically** for error handling in `PluginHandle::load()` and `resolve_agent_id()`, avoiding exceptions in the hot path.
- **Mutex-protected shared state.** `AgentRegistry` uses fine-grained locking: a registry-level mutex plus per-session `stream_mu` for write serialization (`server.cpp:107,251`).
- **Sanitizer integration.** CMake supports both ASan+UBSan and TSan (`CompilerFlags.cmake:28-35`).

### Issues

#### CRITICAL: Use-after-free risk in command dispatch thread (`agent.cpp:287-345`)

```cpp
auto* raw_stream = stream.get();  // line 287 — raw pointer extracted
std::thread exec_thread([this, target, cmd, raw_stream]() {
    // ... uses raw_stream at lines 328, 345 ...
});
```

The `stream` object (a `unique_ptr<ClientReaderWriter>`) is scoped to the block starting at line 241. Background threads capture `raw_stream` and may still be writing to it when the `stream->Read()` loop exits (line 356) and `stream` is destroyed. Although threads are joined at lines 372-377 (after `shutdown_plugins`), plugin `shutdown()` may return before the threads have finished their final `Write()` calls.

**Fix:** Join all exec threads *before* allowing the stream to go out of scope, or use a `shared_ptr` for the stream with threads holding a copy.

#### MEDIUM: Signal handler calls non-signal-safe functions (`agent/main.cpp:29-31`, `server/main.cpp:15-17`)

```cpp
static void on_signal(int sig) {
    spdlog::warn("...");   // Not async-signal-safe
    if (g_agent) g_agent->stop();
}
```

`spdlog::warn()` allocates memory and acquires mutexes — undefined behavior in a signal handler. `stop()` itself does atomic stores and `TryCancel()` which is likely safe, but the logging call is not.

**Fix:** Remove the `spdlog` call from the signal handler. Use `write(STDERR_FILENO, ...)` for diagnostics if needed, or set an atomic flag and log from the main thread.

#### MEDIUM: Global raw pointer for signal handler (`agent/main.cpp:27`, `server/main.cpp:13`)

```cpp
static yuzu::agent::Agent* g_agent = nullptr;
```

No synchronization between setting `g_agent` (line 92) and the signal handler reading it. In practice this is safe because `std::signal` is called after the assignment, providing a happens-before relationship. However, making this `std::atomic<Agent*>` would be more defensive.

#### LOW: SQLite without RAII wrapper (`identity_store.cpp:83-157`)

Every error path manually calls `sqlite3_finalize()` and `sqlite3_close()`. This works but is fragile — a future modification could miss a cleanup. A small RAII wrapper (or scope guard) would make this bulletproof.

#### LOW: `goto` used for control flow (`agent.cpp:178,186,229,252`)

The `run()` method uses `goto shutdown_plugins` for error handling. While functional, this is unusual in modern C++23 code and makes it harder to reason about object lifetimes. An early-return pattern with a destructor-based cleanup would be more idiomatic.

---

## 2. mTLS Implementation

### Strengths — This is well done

- **Full mTLS with identity binding.** The server enforces `GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY` when a CA cert is provided (`server.cpp:737-738`). It then extracts CN and SAN from the peer certificate and validates that the agent's claimed `agent_id` matches (`server.cpp:480-516`).
- **Session binding across RPCs.** The server records peer identity at `Register()` time and re-validates at `Subscribe()` time (`server.cpp:375-386`). This prevents a malicious agent from hijacking another agent's session by stealing the session ID — the TLS identity must also match.
- **Pending registration TTL.** Session tokens expire after 60 seconds (`server.cpp:560`), limiting the window for session fixation attacks.
- **Separate credentials for management listener.** The server supports independent TLS configuration for the management gRPC port (`server.cpp:644-659`), allowing different trust boundaries for agent-facing vs. operator-facing traffic.
- **Secure defaults.** TLS is enabled by default (`Config::tls_enabled{true}`). Disabling it requires explicit `--no-tls`. Omitting `--ca-cert` without `--allow-one-way-tls` causes a hard failure.
- **Certificate instructions are clear.** `scripts/Certificate Instructions.txt` provides a complete walk-through with correct OpenSSL commands and SAN configuration.

### Issues

#### HIGH: Predictable session IDs (`server.cpp:330-331`)

```cpp
auto session_id = "session-" + std::to_string(
    std::chrono::steady_clock::now().time_since_epoch().count());
```

Session tokens are derived from a monotonic clock timestamp — they are sequential and predictable. An attacker who can observe one session ID can predict future ones. Combined with the unauthenticated HTTP API, this could allow session hijacking.

**Fix:** Use a cryptographically secure random generator (e.g., `RAND_bytes()` from OpenSSL, which is already a transitive dependency via gRPC).

#### HIGH: No enrollment token / pre-authentication (`agent.proto:40-42`)

Any entity that possesses a valid client certificate signed by the CA can register as an agent with an arbitrary `agent_id`. The `RegisterRequest` has no `enrollment_token` field. In an enterprise environment, this means:

- A compromised CA key allows unlimited agent impersonation
- There's no way to restrict which certificates are authorized to register (no allowlist / revocation check)
- The CLAUDE.md already identifies this as a gap (Auth item #1)

**Recommendation:** Add an enrollment token validated server-side, and consider OCSP stapling or CRL checks for certificate revocation.

#### HIGH: Private keys read into memory with no protection (`agent.cpp:191`, `server.cpp:717`)

```cpp
ssl_opts.pem_private_key = read_file_contents(cfg_.tls_client_key);
```

Private keys are read into `std::string` objects and passed to gRPC. These strings are not zeroed on deallocation — key material persists in freed heap memory. In a core dump or memory forensics scenario, keys are recoverable.

**Recommendation:** Use `OPENSSL_cleanse()` or a secure allocator for key material. At minimum, zero the strings after passing them to gRPC.

#### MEDIUM: Agent UUID generation uses non-cryptographic PRNG (`identity_store.cpp:14-39`)

```cpp
std::random_device rd;
std::mt19937_64 gen(rd());
```

`std::mt19937_64` is a Mersenne Twister — deterministic and recoverable from observed output. If an attacker observes an agent's UUID (e.g., via the unauthenticated `/api/agents` endpoint), they could theoretically recover the PRNG state and predict UUIDs generated on the same machine. Use `RAND_bytes()` from OpenSSL (already a transitive dependency) instead.

#### MEDIUM: No certificate rotation / hot-reload

Certificates are loaded once at startup. Rotating certificates requires a full process restart. For enterprise deployments with short-lived certificates (e.g., Vault PKI, SPIFFE), this is a significant operational burden.

#### MEDIUM: `--allow-one-way-tls` weakens security silently

This flag disables client certificate verification with only a `spdlog::warn()`. In a production deployment, accidentally setting this flag would silently downgrade from mTLS to one-way TLS. Consider requiring an additional confirmation or environment variable.

---

## 3. HTTP API Security

#### CRITICAL: All HTTP endpoints are unauthenticated (`server.cpp:752-900`)

The web server exposes:
- `GET /` — Dashboard UI
- `GET /api/agents` — Lists all connected agents (information disclosure)
- `POST /api/command` — **Dispatches arbitrary commands to agents** (remote code execution surface)
- `GET /events` — SSE stream of all agent events
- `POST /api/chargen/start`, `/api/chargen/stop`, `/api/procfetch/fetch`

None of these endpoints check for authentication. Anyone who can reach the web port (default `0.0.0.0:8080`) can:
1. List all agents in the deployment
2. Send arbitrary plugin commands to any or all agents
3. Monitor all agent traffic via SSE

The CLAUDE.md identifies this as Auth item #2. This is the **single most critical security gap** in the codebase.

**Recommendation:** At minimum, add `Authorization: Bearer <key>` validation as middleware on all `/api/*` and `/events` routes before any production use.

#### HIGH: JSON injection in `to_json()` (`server.cpp:209-225`)

```cpp
json += "{\"agent_id\":\"" + s->agent_id + "\",\"hostname\":\"" + s->hostname + ...
```

Agent metadata (agent_id, hostname, OS, arch) is concatenated directly into JSON without escaping. If an agent registers with a hostname containing `"`, `\`, or control characters, this produces malformed or injectable JSON. While the agent itself controls this data (and mTLS limits who can register), a compromised agent could inject arbitrary JSON that the dashboard JavaScript would parse.

**Fix:** Use proper JSON escaping, or adopt nlohmann/json which is **already a declared dependency** in `vcpkg.json`.

#### HIGH: Hand-rolled JSON parser is fragile (`server.cpp:931-966`)

Note: `nlohmann-json` is already listed in `vcpkg.json` as a dependency, making the hand-rolled parser entirely unnecessary.

`extract_json_string()` and `extract_json_string_array()` use simple string searching. They don't handle:
- Escaped quotes in values (`\"`)
- Nested objects with the same key name
- Unicode escape sequences
- Whitespace variations

A crafted request body could bypass validation or extract incorrect values.

#### MEDIUM: Missing compiler hardening flags (`CompilerFlags.cmake`)

The build does not enable:
- `-D_FORTIFY_SOURCE=2` — compile-time/runtime buffer overflow detection
- `-fstack-protector-strong` — stack canary protection
- `-Wl,-z,relro,-z,now` (full RELRO) — GOT hardening against overwrite attacks
- PIE enforcement for position-independent executables
- MSVC `/DYNAMICBASE /HIGHENTROPYVA /NXCOMPAT` — ASLR + DEP on Windows

These are standard enterprise hardening flags and should be enabled for release builds.

#### MEDIUM: Web server binds to `0.0.0.0` by default

The HTTP dashboard defaults to listening on all interfaces. In enterprise deployments, this should default to `127.0.0.1` or require explicit opt-in for network binding.

#### MEDIUM: No CORS headers, CSP, or other security headers

The web UI responses don't set `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, or CORS headers. This leaves the dashboard vulnerable to clickjacking and MIME-type confusion attacks.

#### MEDIUM: No HTTPS on the web dashboard

The HTTP dashboard runs plain HTTP. Even though gRPC uses TLS, the management web interface transmits commands and agent data in cleartext.

---

## 4. Plugin Security

#### MEDIUM: No plugin sandboxing

Plugins run in-process via `dlopen`/`LoadLibrary` (`plugin_loader.cpp:57`). A malicious or buggy plugin has full access to the agent process — it can read private keys from memory, modify gRPC streams, or execute arbitrary system calls.

**Recommendation for enterprise:** Document the trust model (plugins must be trusted as the agent process itself). Consider code signing for plugin `.so`/`.dll` files and restricting `--plugin-dir` permissions.

#### LOW: No plugin allowlist

The agent loads **all** `.so`/`.dll` files found in `--plugin-dir`. There's no way to restrict which plugins are loaded by name or hash. An attacker who can write to the plugin directory gets code execution.

---

## 5. Enterprise Deployment Readiness

### What's in good shape

| Aspect | Status | Notes |
|---|---|---|
| Cross-platform | Excellent | Windows, Linux, macOS, ARM64 with CI for all |
| CI pipeline | Good | 4-platform matrix, vcpkg binary caching, Debug+Release |
| Build system | Good | CMake presets, vcpkg manifest with pinned baseline |
| Dependency pinning | Good | vcpkg baseline pinned to specific commit |
| CLI argument handling | Good | CLI11 with sensible defaults |
| Logging | Good | spdlog with configurable levels, file + console sinks |
| gRPC health checks | Good | `grpc::EnableDefaultHealthCheckService(true)` |

### What's missing for enterprise

| Gap | Impact | Effort |
|---|---|---|
| **No containerization** | No Docker images, no K8s manifests, no Helm charts | Medium |
| **No systemd/service units** | Manual process management | Low |
| **No config file support** | All config via CLI flags only — no YAML/TOML/JSON config file | Medium |
| **No environment variable config** | Secrets must be passed as CLI args (visible in `ps`) | Low |
| **No metrics/observability** | No Prometheus metrics, no OpenTelemetry, no structured logging (JSON) | Medium |
| **No rate limiting** | Unlimited agent registrations, no command throttling | Low |
| **No audit logging** | Commands sent to agents aren't logged in a durable audit trail | Medium |
| **No log rotation** | File logger uses `basic_file_sink` — no size limits | Low |
| **No graceful drain** | `stop()` joins threads but doesn't drain in-flight commands | Medium |
| **No session timeout enforcement** | `session_timeout` is in Config but not implemented | Low |
| **No reconnection logic** | Agent doesn't reconnect if server restarts | Medium |
| **ManagementService unimplemented** | `ManagementServiceImpl` is a placeholder (`server.cpp:575-578`) | Medium |
| **No RBAC** | No admin vs. read-only role distinction on any endpoint | Medium |

### Deployment friction assessment

To deploy this in an enterprise today, an operator would need to:

1. Build from source (no release binaries or packages)
2. Generate certificates manually following the text instructions
3. Write their own systemd units or init scripts
4. Configure everything via CLI flags (no config file)
5. Set up their own reverse proxy for HTTPS on the dashboard
6. Accept that the web API is completely unauthenticated
7. Accept no monitoring/metrics integration

**Verdict:** The architecture is sound and the mTLS foundation is solid. The codebase is ~2-3 months of focused work away from enterprise readiness, with the HTTP authentication gap and containerization being the highest priorities.

---

## 6. Priority Recommendations

### P0 — Must fix before any production use
1. **Add authentication to HTTP endpoints** — Bearer token at minimum, OIDC/SSO for enterprise
2. **Fix use-after-free risk in agent command dispatch** — Join threads before stream destruction
3. **Fix JSON injection in `to_json()`** — Escape agent metadata properly
4. **Use cryptographically secure session IDs** — Replace timestamp-based generation with `RAND_bytes()`

### P1 — Should fix for any serious deployment
4. **Remove spdlog calls from signal handlers** — Undefined behavior
5. **Add enrollment token to `RegisterRequest`** — Prevent unauthorized agent registration
6. **Zero private key material after use** — Prevent key recovery from memory/core dumps
7. **Add config file support** — Stop passing secrets via CLI args

### P2 — Enterprise hardening
8. Enable compiler hardening flags (`_FORTIFY_SOURCE`, stack protector, RELRO, PIE)
9. Add Docker/K8s deployment manifests
10. Add Prometheus metrics endpoint
11. Implement certificate hot-reload
12. Add agent reconnection with exponential backoff
13. Implement the ManagementService gRPC API
14. Add RBAC for web API and management API
15. Implement session timeout enforcement
16. Add structured JSON logging option
