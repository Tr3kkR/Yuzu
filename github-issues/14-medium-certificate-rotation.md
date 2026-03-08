---
title: "[P2/MEDIUM] Support TLS certificate hot-reload without restart"
labels: enhancement, P2
assignees: ""
---

## Summary

Certificates are loaded once at startup. Rotating certificates requires a full process restart. For enterprise deployments with short-lived certificates (e.g., Vault PKI with 24h certs, SPIFFE/SPIRE), this creates operational burden and potential downtime.

## Affected Files

- `server/core/src/server.cpp` — TLS credential setup (lines 700-750)
- `agents/core/src/agent.cpp` — TLS credential setup (lines 170-200)

## Recommended Fix

### gRPC credential reload

gRPC supports `TlsServerCredentials` with `CertificateProviderInterface` for dynamic cert loading:

```cpp
// Create a file-watcher certificate provider
auto cert_provider = std::make_shared<grpc::experimental::FileWatcherCertificateProvider>(
    cfg_.tls_server_key.string(),   // private key path
    cfg_.tls_server_cert.string(),  // identity cert path
    cfg_.tls_ca_cert.string(),      // root cert path
    600                              // refresh interval (seconds)
);

auto tls_opts = grpc::experimental::TlsServerCredentialsOptions(cert_provider);
tls_opts.set_cert_request_type(GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY);
auto creds = grpc::experimental::TlsServerCredentials(tls_opts);
```

### SIGHUP reload

As a simpler alternative, support SIGHUP to trigger certificate reload:

```cpp
static std::atomic<bool> g_reload_certs{false};

static void on_sighup(int) {
    g_reload_certs.store(true, std::memory_order_relaxed);
}

// In server main loop, periodically check:
if (g_reload_certs.exchange(false)) {
    reload_certificates();
}
```

## Acceptance Criteria

- [ ] Certificates can be rotated without process restart
- [ ] Either file-watcher (automatic) or SIGHUP (manual) reload supported
- [ ] Active connections continue using old certificates until renegotiation
- [ ] New connections use updated certificates
- [ ] Reload failure logged without crashing the server
- [ ] Documented certificate rotation procedure

## References

- SECURITY_REVIEW.md Section 2
