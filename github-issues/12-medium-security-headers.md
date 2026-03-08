---
title: "[P2/MEDIUM] Add security headers (CSP, CORS, X-Frame-Options) to web UI"
labels: security, enhancement, P2
assignees: ""
---

## Summary

The web UI responses set no security headers, leaving the dashboard vulnerable to clickjacking, MIME-type confusion, and cross-origin attacks.

## Affected Files

- `server/core/src/server.cpp` — HTTP response handlers (lines 752-900)

## Missing Headers

| Header | Value | Purpose |
|--------|-------|---------|
| `Content-Security-Policy` | `default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'` | Prevent XSS via injected scripts |
| `X-Content-Type-Options` | `nosniff` | Prevent MIME-type sniffing |
| `X-Frame-Options` | `DENY` | Prevent clickjacking via iframe embedding |
| `X-XSS-Protection` | `0` | Disable browser XSS auditor (can cause issues) |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Limit referrer leakage |

## Recommended Fix

Use httplib's pre-routing handler to set headers on all responses:

```cpp
web_server_->set_pre_routing_handler(
    [](const httplib::Request&, httplib::Response& res) {
        res.set_header("X-Content-Type-Options", "nosniff");
        res.set_header("X-Frame-Options", "DENY");
        res.set_header("Referrer-Policy", "strict-origin-when-cross-origin");
        res.set_header("Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; connect-src 'self'");
        return httplib::Server::HandlerResponse::Unhandled;  // continue to route
    });
```

## Acceptance Criteria

- [ ] All HTTP responses include security headers
- [ ] Dashboard still functions correctly with CSP restrictions
- [ ] SSE `/events` endpoint works with `connect-src 'self'` CSP
- [ ] Headers verified with browser developer tools or `curl -I`
