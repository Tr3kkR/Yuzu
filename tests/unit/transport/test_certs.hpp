// SPDX-License-Identifier: Apache-2.0
// Self-signed TLS material for transport round-trip tests.
//
// QUIC mandates TLS 1.3 — unlike the gRPC backend's tests, there is no
// plaintext mode, so every msquic round-trip test needs a real cert/key
// pair. The material is embedded here as string literals (rather than
// committed .pem files loaded by path) so the tests have zero
// fixture-path plumbing and behave identically on every platform/CI.
//
// CN=localhost, SAN = DNS:localhost + IP:127.0.0.1, ECDSA P-256, valid
// 2026-05-14 .. 2126-04-20 (100-year expiry — a test fixture, never a
// production credential).
//
// Regenerate with:
//   openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
//     -keyout key.pem -out cert.pem -days 36500 -nodes \
//     -subj "/CN=localhost" \
//     -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

#pragma once

namespace yuzu::transport::test {

inline constexpr const char* kTestServerCertPem =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBnDCCAUGgAwIBAgIUAm+HSOe0kxtZIOKmpZyaszI+lwIwCgYIKoZIzj0EAwIw\n"
    "FDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI2MDUxNDE4MDIxM1oYDzIxMjYwNDIw\n"
    "MTgwMjEzWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjO\n"
    "PQMBBwNCAARWOay+C+qz7rN2uxL1dIV0nBtYxE8lmEVnt4+HxXex8FyF5fMeOX/1\n"
    "Ki2widWwUtjhk/emnB0q6JMoPngdmj/9o28wbTAdBgNVHQ4EFgQUWEiaqt8BZWnN\n"
    "VxS8FwBXwvn4mhcwHwYDVR0jBBgwFoAUWEiaqt8BZWnNVxS8FwBXwvn4mhcwDwYD\n"
    "VR0TAQH/BAUwAwEB/zAaBgNVHREEEzARgglsb2NhbGhvc3SHBH8AAAEwCgYIKoZI\n"
    "zj0EAwIDSQAwRgIhAOtKfkQvFgVLNc9G0WMXFeeSeu+2BdYBOcGhdiE8Ue25AiEA\n"
    "7HUZxsj9Y/qegVuqVIS6x7CtEvcE9jUbtF8QqgryJM8=\n"
    "-----END CERTIFICATE-----\n";

inline constexpr const char* kTestServerKeyPem =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgF532bYkKfmchzOWY\n"
    "EO3TDOPCUEeUFA9/aw0bHS3StKmhRANCAARWOay+C+qz7rN2uxL1dIV0nBtYxE8l\n"
    "mEVnt4+HxXex8FyF5fMeOX/1Ki2widWwUtjhk/emnB0q6JMoPngdmj/9\n"
    "-----END PRIVATE KEY-----\n";

} // namespace yuzu::transport::test
