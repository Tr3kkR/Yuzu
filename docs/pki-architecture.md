# Yuzu PKI architecture

Yuzu ships a self-managed internal Certificate Authority so a fresh install is
encrypted and mutually authenticated out of the box, with no external PKI
required — while still letting enterprises root Yuzu in their own CA later
(subordinate mode, Milestone 2). This is the routed reference for the PKI
subsystem; the auth-facing detail lives in `docs/auth-architecture.md`
("Default certificates", "Per-agent mTLS").

**Algorithm policy (locked):** ECDSA P-256 leaves, P-384 root. ECDSA is
roadmap-aligned for the gRPC→QUIC move (#376): QUIC mandates TLS 1.3, which
treats `ecdsa_secp256r1_sha256` / `ecdsa_secp384r1_sha384` as first-class, and
the smaller certs cost fewer bytes under QUIC's anti-amplification limit. The
signature digest follows the *issuer* key strength (P-384 → SHA-384, P-256 →
SHA-256). **100% OpenSSL 3.x** — no hand-rolled cryptographic primitives. RSA and
a configurable key algorithm are explicit non-goals for Milestone 1.

## Trust model — one CA, many consumers

A per-install internal CA is generated on first boot (ECDSA P-384 root, 10-year
life; see "Default certificates" below). **Every install generates its own root
— no bundled or shared private keys, ever.** It signs:

| Leaf | Consumer | Key | Validity | Identity |
|---|---|---|---|---|
| `default-https` | Dashboard HTTPS listener | EC P-256 | sized to CA notAfter | SAN: `localhost`, `127.0.0.1`, `::1`, `<hostname>` |
| `default-server` | Agent + management gRPC listeners | EC P-256 | sized to CA notAfter | same |
| `default-gateway` | Gateway listener + upstream client (PR5) | EC P-256 | sized to CA notAfter | same |
| per-agent leaf | Agent gRPC **client** cert (mTLS identity) | EC P-256 (agent-generated) | ~1y, auto-renew at 2/3 | `CN=<agent_id>`, URI SAN `yuzu://<ca-fingerprint>/agent/<agent_id>` |

Server-side leaves are long-lived because the threat model is "operator forgets to
rotate"; agent leaves are short-lived because they auto-renew over the existing
channel. The agent leaf's `CN` *is* the `agent_id`, so the existing #1118
client-identity binding becomes cryptographic with no new mechanism.

## Components

| Module | Responsibility |
|---|---|
| `server/core/src/x509_ca.{hpp,cpp}` (`yuzu::server::pki`) | Pure-OpenSSL engine: EC keygen, self-sign root, sign leaf from CSR (POP-verified, server-chosen subject/SAN/EKU), build CRL, SHA-256 fingerprint, parse, `verify_chain`. No SQLite / config / store deps — value types + PEM/DER strings only. |
| `server/core/src/key_provider.{hpp,cpp}` | `KeyProvider` interface + `FileKeyProvider` (0600 PEM in a 0700 dir). The HSM/PKCS#11 seam — `key_ref` is an opaque token (the absolute path today). |
| `server/core/src/ca_store.{hpp,cpp}` (`ca.db`) | SQLite inventory + lifecycle: `ca_root`, `ca_issued`, `ca_crl_versions`. **Metadata only — the root private key is never in the DB**, only its opaque `key_ref`. |
| `server/core/src/default_certs.{hpp,cpp}` | First-boot bootstrap: root + 3 server leaves + `default-marker.json`. Idempotent; regenerate-whole-set on corruption / clock-skew. |
| `agents/core/src/agent_csr.{hpp,cpp}` | Agent-side, self-contained OpenSSL (the agent cannot link `x509_ca`): EC P-256 keypair + CSR generation, 0600 leaf persistence, renew-at-2/3 inspection. |
| `server/core/src/ca_routes.{hpp,cpp}` | The `/api/v1/ca/*` REST surface (PR4). |

## `ca.db` (schema + invariants)

Created via `MigrationRunner` (namespace `ca_store`), opened `FULLMUTEX` + WAL +
`busy_timeout`, file mode 0600. Tables:

- `ca_root(id=1, cert_pem, key_ref, algo, not_before, not_after,
  fingerprint_sha256, mode, created_at)` — a single root row (REPLACEd on
  subordinate import, PR6).
- `ca_issued(serial_hex PRIMARY KEY, subject, san, purpose, not_after, status,
  revocation_reason, revoked_at, issued_at, issued_by, enrollment_request_id,
  cert_pem)`.
- `ca_crl_versions(version PRIMARY KEY, der, this_update, next_update,
  published_at)`.

Invariants: `key_ref` is opaque (pass to `load_key`, never parse). `revoke()`
uses `RETURNING` for change detection — never `sqlite3_changes()` on the shared
connection (#1033). `serial_hex` is canonical uppercase `BN_bn2hex` on both the
issuance and parse sides, so revocation lookups match exactly.

## Default certificates (PR2)

A fresh install no longer refuses to start without operator certs — on first boot
`ensure_default_certs()` generates the root + server leaves under the cert
directory (`auth::default_cert_dir()`, override `--ca-dir`) and the server is
encrypted + server-authenticated with zero operator action. It is impossible to
miss: ERROR startup banner, audit `server.default_certs_generated` +
`server.default_certs_in_use`, Prometheus `yuzu_server_default_certs_active`,
`/health` `tls.*`, `/readyz` `ca_store`/`ca_root`. Opt out with
`--no-default-certs`. Full detail: `docs/auth-architecture.md` "Default
certificates".

## Per-agent mTLS (PR3)

Agents auto-enroll for their own client cert: generate keypair + CSR → server
signs (POP-verified, identity server-set, CSR subject/SAN ignored) → agent
persists (key 0600) + reconnects with mutual TLS. Bootstrap is on one port
(request-but-don't-require client certs + app-layer enforcement). Enforcement is
**gradual** — a provisioned agent must present its leaf, a not-yet-provisioned /
legacy agent falls back to session + #826 peer-IP binding (non-breaking rollout).
Revocation is enforced at `Register` re-auth, `Subscribe`, `Heartbeat`, and
`DownloadUpdate`, issuer-scoped via `is_yuzu_issued` (`verify_chain` against our
CA, so a foreign cert in a multi-CA bundle is never trusted as an agent). Full
detail incl. custody + the deferred `--require-agent-identity`:
`docs/auth-architecture.md` "Per-agent mTLS".

## CA REST surface (PR4)

`server/core/src/ca_routes.{hpp,cpp}`, registered in `server.cpp` alongside the
other route modules. The crypto (CRL build, CA-key access) is injected as a
callback so `ca_routes` links no `x509_ca`/`key_provider`.

| Route | Auth | Purpose |
|---|---|---|
| `GET /api/v1/ca/root` | **public** | CA root certificate (PEM). Public by definition — clients/browsers need it to trust the install. |
| `GET /api/v1/ca/crl` | **public** | Current CRL (DER, `application/pkix-crl`). Served from the latest *published* CRL (cheap + DoS-safe — not rebuilt/signed per request); built on first access. |
| `GET /api/v1/ca/issued` | `Security:Read` | Issued-cert inventory (JSON: serial, subject, SAN, purpose, status, expiry, issued_by). `limit`/`offset` query params. |
| `POST /api/v1/ca/revoke` | `Security:Delete` | Revoke a serial (`{"serial_hex","reason"}`), then republish the CRL. |

Audit actions: `ca.cert.issued` (PR3, at enrollment), `ca.cert.revoked`,
`ca.crl.published`. Metrics: `yuzu_server_ca_cert_issued_total{purpose}`,
`yuzu_grpc_revoked_cert_total{rpc}`. Errors use the A4 envelope
(`docs/agentic-first-principle.md`). Revocation takes effect server-side
**immediately** (the mTLS accept gate reads `ca.db`, not the CRL); the CRL
republish propagates it to external consumers — a republish failure is surfaced
in the response (`crl_republished:false`) and does not undo the revocation.

`POST /api/v1/ca/issue` (general operator-chosen-CN signing for service / code-
signing certs) is **deferred**: an operator-issued client leaf whose CN collides
with an `agent_id` could impersonate that agent at the #1118 identity gate, so it
needs a dedicated non-agent namespace + EKU policy. Tracked follow-up.

## Key custody + threat model

The CA root key is a 0600 PEM in a 0700 directory via `FileKeyProvider`; it is
loaded transiently per signature (issuance, CRL build) and zeroed via RAII —
never resident for the process lifetime. The Milestone-1 threat model is
**local-host compromise**: an attacker who can read the 0600 key (or write
`ca.db`) is already past the boundary and holds the crown jewel regardless. For
stronger custody, replace the default certs with operator/HSM-backed material;
`KeyProvider` is the seam a future `Pkcs11KeyProvider` implements with
`key_ref` = a PKCS#11 URI and zero change to callers. On Windows the agent leaf
key currently relies on `std::filesystem::permissions` (an explicit owner-only
DACL via `SetNamedSecurityInfoW` is a tracked follow-up shared with
`FileKeyProvider`) — run the agent under a dedicated service account meanwhile.

## Operator runbook

- **Trust the dashboard cert in a browser:** download `GET /api/v1/ca/root` (or
  `<ca-dir>/default-ca.pem`) and add it to the OS/browser trust store. Verify
  with `openssl x509 -in default-ca.pem -noout -fingerprint -sha256` against the
  fingerprint in the startup banner / `/health`.
- **Distribute the CA to agents:** pass `--ca-cert <default-ca.pem>` (PR5 ships a
  shared cert volume so this is automatic in container deployments).
- **Inventory:** `GET /api/v1/ca/issued` (or the dashboard CA panel, PR4b).
- **Revoke a compromised agent:** `POST /api/v1/ca/revoke {"serial_hex":"…"}`, or
  use the **Settings → Internal CA** dashboard panel (find the agent's row in the
  inventory and click **Revoke** — the panel refreshes in place with the new
  status). Either way it is effective immediately server-side; the agent is
  refused on its next Subscribe/Heartbeat/OTA call (Register re-auth + the
  data-plane gates consult `ca.db` directly). NOTE: an agent holding an **already-open** Subscribe stream
  keeps it until that stream next reconnects — revocation does not actively tear
  down a live stream today (a follow-up). To force an immediate cutoff, restart
  the agent or wait for its reconnect; the revoked cert cannot re-establish.
- **CRL distribution:** point external consumers at `GET /api/v1/ca/crl`. A failed
  republish (after a revoke, or a failed startup pre-publish) increments
  `yuzu_server_ca_crl_publish_failures_total` and audits `ca.crl.published`
  `result=failure` — alert on it: the public CRL is stale while server-side
  enforcement is already live.
- **Back up** `<ca-dir>/default-ca.key` (0600) + `ca.db` to offline storage —
  losing the root key forces a full fleet re-enrollment.

## Roadmap

| PR | Scope | Status |
|---|---|---|
| PR1 | `x509_ca` + `key_provider` + `ca_store` | shipped |
| PR2 | Default-cert bootstrap + server TLS wiring | shipped |
| PR3 | Per-agent mTLS issuance at enrollment | shipped |
| PR4 | CA REST surface + this doc | shipped |
| PR4b | Dashboard CA panel (inventory, revoke, root/CRL download, rotation CTA) | shipped |
| PR5 | Gateway TLS + distribution flip (drop `--no-tls`/`--no-https`); gateway `_pb.erl` regen for per-agent mTLS through the gateway | planned |
| PR6 (M2) | Subordinate-CA (`--ca-mode subordinate`) + CSR export / offline signing | planned |

Deferred follow-ups tracked across the ladder: `POST /api/v1/ca/issue` with
namespace separation; centralized revocation/identity gRPC interceptor +
`--require-agent-identity`; **active teardown of a live Subscribe stream on
revocation** (today it ends on the next reconnect); `enrollment_request_id`→
enrollment-decision correlation; `crlNumber` in the `ca.crl.published` audit
detail; a `yuzu_server_ca_cert_revoked_total` counter + `/readyz`
`ca_crl_published` signal + a periodic CRL re-publish before `nextUpdate` (7-day)
lapses; a dedicated public-CA rate-limit bucket; dropping expired entries from the
CRL; `ca.db` expired-row pruning; `yuzu_server_ca_*_expiry_seconds` gauges +
alerting; a `docs/security-reviews/` PKI record + risk-register entries; ACME (P3).
