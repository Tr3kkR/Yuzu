---
title: "[P2/MEDIUM] Add HTTPS/TLS support for web dashboard"
labels: security, enhancement, P2
assignees: ""
---

## Summary

The HTTP dashboard runs plain HTTP even when gRPC uses TLS. Commands, agent metadata, and event streams are transmitted in cleartext over the web interface, making them vulnerable to network sniffing and MITM attacks.

## Affected Files

- `server/core/src/server.cpp` (line 898) — `web_server_->listen()`
- `server/core/include/yuzu/server/server.hpp` — Config needs web TLS fields

## Recommended Fix

### Option A: Native TLS in httplib

httplib supports TLS natively via `SSLServer`:

```cpp
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
if (cfg_.tls_enabled && !cfg_.tls_server_cert.empty()) {
    web_server_ = std::make_unique<httplib::SSLServer>(
        cfg_.tls_server_cert.c_str(),
        cfg_.tls_server_key.c_str());
} else {
    web_server_ = std::make_unique<httplib::Server>();
}
#endif
```

### Option B: Reverse proxy (recommended for enterprise)

Document that production deployments should front the dashboard with nginx/Caddy/Envoy providing TLS termination. Add a `--web-tls-cert` / `--web-tls-key` option for direct TLS.

## Acceptance Criteria

- [ ] Web dashboard supports TLS when certificate/key are provided
- [ ] Reuse existing server TLS certificates by default (same `--cert`/`--key`)
- [ ] Separate `--web-tls-cert`/`--web-tls-key` options for independent certificates
- [ ] Plain HTTP still works for development when TLS is disabled
- [ ] Documentation covers reverse proxy setup for enterprise

## References

- SECURITY_REVIEW.md Section 3
