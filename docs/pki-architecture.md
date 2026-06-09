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

The three server-side leaves share one SAN set: the base `localhost` / `127.0.0.1` /
`::1` / `<hostname>` plus any operator `--cert-san` extras (`dns:<name>`, `ip:<addr>`,
or a bare value auto-classified by IP-literal shape; repeatable, and a single value
may be comma-separated). `--cert-san` is the supported way to make the built-in certs
valid for a deployment name a client actually dials — e.g. `--cert-san dns:gateway` so
an agent reaching the gateway by that service name passes SNI hostname verification.
Changing `--cert-san` does **not** rotate an existing set (the marker fast path returns
the prior certs); clear the cert dir or replace the certs for new SANs to take effect.

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

**MCP parity (A1).** The inventory + revoke operations are also exposed as MCP
tools — `list_issued_certs` (`Security:Read`) and `revoke_certificate`
(`Security:Delete`) — so an agentic worker reaches the same surface as the
dashboard/REST (agentic-first principle A1). They are governed by the standard
MCP tier ladder: `list_issued_certs` (a `Read`) runs on every tier including
`readonly`; `revoke_certificate` (a destructive `Delete`) is allowed only on `supervised`,
where it is approval-gated exactly like every other destructive MCP op (so an
autonomous worker cannot revoke without the approval workflow — the same
platform-wide approval-gated-execution boundary, not a CA-specific carve-out).

Audit actions: `ca.cert.issued` (PR3, at enrollment), `ca.cert.revoked`,
`ca.crl.published`, plus `ca.cert.reissue_blocked` (PR3 H-2 revoked-identity
re-provision guard). A revoke of a nonexistent/already-revoked serial audits
`ca.cert.revoked` `result=denied` (reject-without-state-change, idempotent
retry-safe — matches the destructive-sibling convention); `result=failure` is
reserved for an authorized-but-errored op (e.g. a `ca.crl.published` build/record
failure). Metrics: `yuzu_server_ca_cert_issued_total{purpose}`,
`yuzu_grpc_revoked_cert_total{rpc}`, `yuzu_server_ca_crl_publish_failures_total`,
`yuzu_server_ca_reissue_blocked_total`. Errors use the A4 envelope
(`docs/agentic-first-principle.md`). Revocation takes effect server-side
**immediately** (the mTLS accept gate reads `ca.db`, not the CRL); the CRL
republish propagates it to external consumers. A republish failure is honest:
`publish_crl()` returns failure (not the previously-built DER) when the CRL
cannot be persisted, so the response reports `crl_republished:false`, the
`ca.crl.published` `result=failure` audit fires, and the failure counter
increments — the revocation itself is NOT undone (already enforced server-side).

**curl examples:**

```bash
# Issued-cert inventory (admin token):
curl -s -H "X-Yuzu-Token: $TOKEN" https://localhost:8443/api/v1/ca/issued | jq

# Revoke a compromised agent's cert (republishes the CRL):
curl -s -X POST -H "X-Yuzu-Token: $TOKEN" -H 'Content-Type: application/json' \
     -d '{"serial_hex":"AB12CD…","reason":"key compromise"}' \
     https://localhost:8443/api/v1/ca/revoke | jq
```

`POST /api/v1/ca/issue` (general operator-chosen-CN signing for service / code-
signing certs) is **deferred**: an operator-issued client leaf whose CN collides
with an `agent_id` could impersonate that agent at the #1118 identity gate, so it
needs a dedicated non-agent namespace + EKU policy. Tracked follow-up.

## Gateway TLS (PR5)

The Erlang gateway (`gateway/`) is an optional scale-out fan-out plane that sits
between agents and the server. Its TLS posture is shaped by a hard property of
the underlying transport library, **grpcbox v0.17.1**, verified against its
source:

- A grpcbox listener does TLS **only** when its `transport_opts` map carries
  `ssl => true` **and** `keyfile`/`certfile`/`cacertfile` (all four). Omit
  `ssl => true` and it silently runs plaintext (`grpcbox_pool.erl:18`). When TLS
  is on, grpcbox **hardcodes** `fail_if_no_peer_cert=true` + `verify=verify_peer`
  + TLS 1.2 + ALPN `h2` — i.e. every TLS listener is **mutual** TLS; there is no
  request-but-don't-require mode.
- A grpcbox client channel does TLS via `{https, Host, Port, SslOpts}`; grpcbox
  prepends ALPN `h2` and passes `SslOpts` to `ssl:connect`, so the channel
  honours `cacertfile`/`certfile`/`keyfile`/`verify`. **`{verify, verify_peer}`
  is mandatory** — an ssl client does not verify the server otherwise — and OTP
  enforces SNI hostname matching, so the server cert SAN must cover the dialled
  host.

### M1 posture — upstream mutual TLS

| Hop | M1 TLS | Why |
|---|---|---|
| gateway → server upstream (`GatewayUpstream`, :50055) | **mutual TLS** | Both peers hold CA-issued certs (the gateway uses the `default-gateway` leaf, which has `serverAuth`+`clientAuth`). No bootstrap problem. |
| agent → gateway (:50051) | **one-way TLS (PR5c; live-wired in PR5b)** | The vendored+patched grpcbox (`_checkouts/grpcbox`) lets the agent listener run **server-authenticated** TLS (`verify_none` + `fail_if_no_peer_cert=false`) — encrypted + gateway-authenticated, **no client cert required**, so an unenrolled agent still bootstraps. Enabled in `sys.config.prod`; distributing the CA to agents + the deployed-compose wiring land in PR5b (the shipped composes are still plaintext until then). Agent identity stays app-layer (`gateway_observed_peer`, #1064), not transport. |
| operator → gateway mgmt (:50063) | **plaintext / strict mTLS** | The privileged operator/command plane. Do NOT one-way-TLS it (would be encrypted-but-unauthenticated). Keep on a trusted network, or require client certs via strict mTLS (the patched grpcbox's defaults — omit `verify`/`fail_if_no_peer_cert`); the server's command client presents a cert, so mTLS works here with no bootstrap problem. |

> **⚠ SECURITY — do not expose the plaintext gateway agent edge to an untrusted
> network.** The gateway is the command fan-out plane: it pushes
> `CommandRequest`s that agents execute. A plaintext, internet-or-LAN-reachable
> agent listener (:50051) has **no confidentiality, no integrity, and no gateway
> authentication** — an on-path attacker can read all inventory and, worse,
> **inject commands → remote code execution across the fleet**, or impersonate the
> gateway. This is potentially CRITICAL for an internet-facing gateway. It is a
> *pre-existing* property (the gateway was fully plaintext before PR5; PR5 only
> encrypts the gateway→server upstream hop), but it is NOT acceptable on an
> exposed deployment. **Direct agent→server connections are already full mTLS
> (PR2/PR3) over any network — the gap is specific to the gateway edge.**
>
> **One-way TLS now closes this (PR5c)** — the vendored+patched grpcbox
> (`_checkouts/grpcbox`) makes `fail_if_no_peer_cert`/`verify` configurable, so the
> agent listener can run server-authenticated TLS (`verify_none` +
> `fail_if_no_peer_cert=false`): encrypted + gateway-authenticated, no client cert
> required (bootstrap-safe). It is enabled in `sys.config.prod`. **But the deployed
> composes are still plaintext until PR5b wires it in + distributes the CA to
> agents.** So **until your deployment is on PR5b (or you enable one-way TLS + ship
> the CA yourself), a gateway exposed to an untrusted network MUST still do one
> of:** (a) terminate TLS in front of the gateway (reverse proxy on :50051,
> forwarding plaintext only over loopback/a trusted segment); or (b) keep the agent
> port on a trusted network (VPN / private subnet / service mesh). The QUIC
> transport (#376) is the longer-term native path.

The canonical correct gateway TLS config is `gateway/config/sys.config.prod`
(upstream `{https,...}` mutual TLS + **one-way TLS on the agent listener** (PR5c) +
a documented optional strict-mTLS block for the privileged mgmt listener). It is
unit-tested in `gateway/apps/yuzu_gw/test/yuzu_gw_mtls_tests.erl` — real EC
handshakes (P-384 CA / P-256 leaf) prove both the mutual-TLS option shape (certless
client rejected) **and** the one-way shape (certless client accepted, bootstrap-safe). `yuzu_gw_app:log_tls_state/0` reports the *actual* grpcbox posture at
startup (the older `tls_enabled`/`tls` env is advisory only — grpcbox reads its
own config at boot).

**Operational notes:**
- **Fail-closed on misconfig** — the gateway refuses to boot if the upstream channel
  is `https` *without* `{verify, verify_peer}` (encrypted but MITM-able);
  `evaluate_upstream_posture/2`, override `YUZU_GW_ALLOW_UNVERIFIED_UPSTREAM=1` for
  dev/CI. Plaintext upstream is still permitted (the UAT/dev posture).
- **Cert SAN ↔ dial-name (checklist)** — OTP enforces SNI hostname verification under
  `verify_peer`, so the server cert SAN must include the name the gateway dials. The
  default certs carry `localhost` + `IP:127.0.0.1` + `IP:::1` + `gethostname()`; for
  cross-container/host dialing, either dial the server's hostname and set that service's
  `hostname:` so its SAN matches, or add the dialled name with `--cert-san dns:<name>`
  (shipped — extends every default leaf's SAN).
- **Leaf rotation** — grpcbox reads the cert/key/CA files at channel *connect* time
  (lazy), so replacing `default-gateway.{pem,key}` on disk is picked up on the next
  upstream reconnect; an *established* channel keeps the old cert until it drops, so a
  `systemctl restart yuzu-gateway` is the deterministic way to force a rotation.
- **Observability** — an upstream TLS-handshake failure currently surfaces only as the
  generic circuit-breaker open state; a dedicated handshake-failure metric is a tracked
  follow-up. See the consolidated residual-risk register + follow-ups in
  `docs/security-reviews/pki-pr5-gateway-tls.md`.

### Per-agent enrollment through the gateway (proto regen)

The gateway vendors its own copies of the agent proto, and gpb emits
**self-contained** `_pb` modules — so the `yuzu.agent.v1` Register messages are
embedded in **three** generated modules: `agent_pb` (the agent-facing listener),
`gateway_pb` (the **`ProxyRegister` marshaller** used by `yuzu_gw_upstream:do_rpc/3`
— the load-bearing one for the gateway→server hop), and `management_pb`. Before
PR5 all three lacked `csr_pem`/`issued_certificate`/`issued_ca_chain`, so gpb
**dropped** them in transit and the gateway silently stripped the agent's CSR
while proxying `Register` — per-agent mTLS auto-provisioning only worked
direct-connect. PR5 regenerates **all three** modules (fields mirrored from the
canonical proto, same field numbers 7/7/8), so the gateway now forwards the CSR
and returns the issued cert verbatim. A field added to only one module is
silently stripped on the hop that marshals via another (`agent.proto:96`
documents this trap); per-module roundtrip tests now assert `agent_pb`,
`gateway_pb`, and `management_pb` — and a CI codegen-consistency guard is a
tracked follow-up.

**PR5d — the server actually issues on the proxied path.** PR5 made the *wire*
carry the fields, but `GatewayUpstreamServiceImpl::ProxyRegister` still never
called the signer, so a gateway-enrolled agent got no per-agent cert (it retried
then degraded to one-way TLS — surfaced by the PR5b boot-test). PR5d signs the
CSR in `ProxyRegister`, mirroring the direct `AgentServiceImpl::Register`: both
paths share **one** signer (`sign_agent_csr`) wired in `server.cpp`, so CA,
per-agent rate-limit, `ca_issued` recording, and the 16 KiB CSR-size cap are
identical and cannot drift. The Erlang gateway relays the `RegisterResponse`
verbatim (`yuzu_gw_agent_service:register/2`), so the issued cert reaches the
agent with no gateway change. **Revocation semantics:** issuance is *not* gated on
cert revocation on either path — revoke is serial-scoped (it invalidates a
presented leaf); **denying** the agent is what stops re-enrollment/re-issuance
(both paths reject a denied agent before signing). **M1 caveat:** the
agent↔gateway hop is one-way TLS (PR5c), so the issued leaf is presented to a
non-verifying listener for now — issuing it completes per-agent-mTLS day-one
(records the cert for inventory/revocation, future-proofs gateway mTLS), but
*cryptographic* through-gateway identity binding remains the QUIC-era follow-up
(agent identity across the gateway is still the app-layer `gateway_observed_peer`).

### Distribution flip — staged as PR5b

Making a fresh **containerised** install encrypted-by-default (dropping
`--no-tls`/`--no-https` across the compose/Dockerfile surface + a shared cert
volume) is staged separately because it carries container-integration steps that
must be validated against a booted stack, and **no CI workflow currently boots
the `deploy/docker/*.yml` composes** (the pre-release smoke writes its own inline
plaintext compose; the UAT rigs are manual). The known requirements PR5b must
satisfy:

- **Cert-dir ownership** — the runtime image runs as `yuzu`, but `/etc/yuzu` is
  root-owned; the cert dir must be writable by `yuzu` (chown, or a pre-created
  `0700` volume) or first-boot cert generation fails.
- **HTTPS healthcheck** — the compose healthchecks use a bash `/dev/tcp`
  plaintext HTTP GET against `/readyz`, which cannot complete a TLS handshake;
  switch to a TCP-connect liveness check or add `openssl s_client`.
- **Cert SAN ↔ dial name** — every name a client dials (e.g. the gateway dialing
  `server`, or an agent dialing `gateway`) must be in the dialled server's cert SAN.
  The default SAN is `localhost`/loopback/`gethostname()`; set the service `hostname:`
  to match, or add the dialled name(s) with `--cert-san dns:<name>` (e.g.
  `--cert-san dns:gateway --cert-san dns:server` so the cross-container service names
  validate). This is the per-agent-through-gateway enabler — the `default-gateway`
  leaf does not otherwise carry `DNS:gateway`.
- **Cert-volume timing** — the gateway must read certs from the shared volume
  *after* the server's first-boot generation; the gateway's plaintext listeners
  + lazy upstream channel make this benign, but it must be confirmed.

Until PR5b, the server is encrypted-and-mutually-authenticated by default when
run **without** `--no-tls`/`--no-https` (PR2 generates the certs); the shipped
compose rigs still pass those flags explicitly.

## Subordinate-CA — root Yuzu's CA in an enterprise PKI (PR6, M2)

By default the install CA is a self-signed root (`CaMode::Builtin`). An enterprise
that already runs PKI can make Yuzu's issuing CA a **subordinate** of its own
root, so every Yuzu-issued certificate chains to the corporate trust anchor.

**Key invariant — the issuing key never changes.** The enterprise signs Yuzu's
*existing* public key into an intermediate. Because a leaf's
`authorityKeyIdentifier` is derived from the issuer **key** (unchanged) and the
issuer DN is kept identical, every certificate issued *before* the switch keeps
validating *after* it. Only the issuer's cert (and the chain above it) changes.

**Flow:**
1. **Export** — `GET /api/v1/ca/root-csr` runs `ServerImpl::export_ca_csr`:
   `make_csr` over the existing CA key, subject = the CA's current DN. The CA key
   is loaded transiently and `secure_zero`'d on every exit path (same custody as
   `sign_agent_csr`). The CSR carries only the public key (already public via
   `/ca/root`) — no secret.
2. **Enterprise signs** the CSR as a subordinate CA (must be
   `basicConstraints: CA:TRUE`, `keyUsage: keyCertSign,cRLSign`) — offline, with
   the enterprise's own tooling. Yuzu never signs CA intermediates itself.
3. **Import** — `POST /api/v1/ca/import-chain` runs
   `ServerImpl::import_subordinate_chain`, which is the security crux and validates
   **in order**:
   - `parse_certificate(intermediate)` — parseable;
   - `pki::cert_is_ca` — `X509_check_ca()==1` (explicit `CA:TRUE`), else it cannot
     issue;
   - `pki::cert_matches_key(intermediate, our CA key)` — `EVP_PKEY_eq` of the
     cert's public key against our private key. **This is the load-bearing check**:
     it proves the enterprise signed the exact CSR we exported and that we still
     hold the matching private key. Without it, an operator (or a compromised one)
     could re-root the install at an attacker-chosen hierarchy or at an issuing
     cert whose key we don't hold (silently breaking all future issuance);
   - `pki::verify_chain_to_bundle(intermediate, chain_pem)` — the intermediate
     verifies up to a trust anchor inside the uploaded parent chain (any depth).
   Only then `set_root(cert=intermediate, chain=parent_chain, mode=Subordinate)`
   — `key_ref` and `algo` unchanged; `not_before`/`not_after` + `fingerprint`
   adopted from the intermediate. The CRL is then re-published so it is served
   under the new issuer's fingerprint.

**Schema:** `ca_root.chain_pem` (migration v4) holds the parent chain above the
issuing cert (empty in Builtin). `CaRoot.mode` records `builtin`/`subordinate`.
Issued-cert `issuer_fingerprint` (v2) links each leaf to the root that signed it,
so a re-key does not orphan the inventory.

**Issued chain:** `sign_agent_csr` returns `cert_pem + chain_pem` as the
`issued_ca_chain`, so a gateway/agent leaf receives a full path to the corporate
root (empty in Builtin → M1 single-cert behaviour unchanged).

**Surfaces:** REST `GET /api/v1/ca/root-csr` (`Security:Read`) + `POST
/api/v1/ca/import-chain` (`Security:Write`); the **Settings → Internal CA** panel
shows a Trust-mode badge + the CSR download + an import form (the dashboard
wrapper `/api/settings/ca/import-chain` is CSRF-gated like revoke). Audit:
`ca.root_csr.exported`, `ca.subordinate.imported`.

**Bring-your-own-leaf** stays orthogonal: any surface with an explicit
`--cert`/`--key`/`--ca-cert` (or `--https-cert`/`--https-key`) flag bypasses the
internal CA entirely for that surface — supported, unchanged, independent of CA
mode. ACME and a configurable RSA key algorithm remain explicitly out of scope.

## Secure-by-default deployment (PKI #1289)

The PR2 engine generates the CA + leaves on first boot, but the **shipped Docker
images** historically baked `--no-tls`/`--no-https` into their default CMD, so a
container off the published image was plaintext. #1289 flips that: the
`yuzu-server(-chisel)` and `yuzu-agent(-chisel)` images drop those flags, so a
container is encrypted + mutually authenticated with zero configuration —
dashboard over **HTTPS:8443** (8080 → HTTP→HTTPS redirect), agent/management/
gateway listeners over (m)TLS. Demo/UAT/test composes keep `--no-tls`
deliberately; native installs (deb/systemd, the Windows installer's opt-in
disable checkbox) were already secure-by-default.

**Agent CA auto-discovery.** The agent connects over TLS by default. With no
`--ca-cert` it checks the standard install-CA path
(`/etc/yuzu/certs/default-ca.pem`, or the Windows ProgramData path) **before**
grpc falls back to the system trust store — a Yuzu self-signed CA is not in the
system roots, so without this an agent pointed at a default-cert server silently
fails the handshake. If neither an explicit `--ca-cert` nor a discovered CA is
present it logs a clear warning rather than failing opaquely.

**Cross-container cert sharing — `--cert-group`.** A multi-container deploy
(server + Erlang gateway + agents) runs the three as DIFFERENT non-root uids but
shares ONE `/etc/yuzu/certs` volume. The server creates that dir `0700` and each
leaf key `0600` owned by itself, so a different-uid sibling can neither traverse
the dir nor read its key (the gateway's grpcbox crashes `eacces`). The
**`--cert-group <name|gid>`** flag (`YUZU_CERT_GROUP`) fixes this at cert-gen
time: it chgrp's the cert dir (`0750`) and **only** `default-gateway.key`
(`0640`) to a shared group — the FIXED gid 2000 `yuzu-pki` group baked into all
three images, of which each image's user is a member. The CA key, server key,
and HTTPS key stay `0600` owner-only — never group-shared; the CA + leaf certs
are public `0644`. Empty (the default, single-host) keeps the tight 0700/0600
posture. POSIX-only (Windows uses ACLs). This is `apply_cert_group_share()` in
`default_certs.cpp`, applied on both the generate and idempotent-restart paths.

**Gateway TLS config** still comes from the grpcbox block (`{grpcbox,
client|servers}`), which grpcbox reads itself — the `YUZU_GW_*` env vars do NOT
drive it (#1291). The secure reference mounts a TLS `sys.config`
(`reference-gateway-sys.config`: upstream mutual TLS to the `server` service,
one-way TLS agent listener). `--cert-san dns:gateway dns:server` puts the service
names on the default leaves so SNI verification succeeds across the hops.

**Reference composes:** `deploy/docker/docker-compose.reference.yml` (single
server, HTTPS + persistent CA volume) and
`deploy/docker/docker-compose.reference-gateway.yml` (server + gateway + agent,
the full mTLS topology with `--cert-group` + the mounted gateway sys.config).

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
  inventory, optionally type a reason, and click **Revoke** — the panel refreshes
  in place with the new status; the dashboard POST is CSRF-gated). Either way it
  is effective immediately server-side; the agent is refused on its next
  Subscribe/Heartbeat/CheckForUpdate/OTA call (Register re-auth + the data-plane
  gates consult `ca.db` directly). An agent holding an **already-open** Subscribe
  stream is torn down by the server's periodic revocation sweep (~15s; PR3 H-1,
  `yuzu_grpc_revoked_cert_total{rpc=stream_sweep}`, audited `session.cert_revoked`
  `source=stream_sweep`) — it does not survive on the data plane until a voluntary
  reconnect. A revoked agent also cannot re-provision its way back: deleting its
  key and re-enrolling is refused (`ca.cert.reissue_blocked`) while the
  revocation stands. **Gateway-proxied agents are the exception** — the server
  sees the gateway's cert, not the agent's leaf, so revocation is not enforced on
  the gateway hop (disconnect at the gateway too; see `auth-architecture.md`
  "Gateway-proxied agents: revocation scope").
- **CRL distribution:** point external consumers at `GET /api/v1/ca/crl`. The
  server keeps the CRL fresh on its own — a background freshness check
  re-publishes when the latest CRL is missing or within 24h of `nextUpdate`, so a
  fleet with no revocations never serves an expired CRL and a failed startup
  pre-publish self-heals on the next tick (no permanent 503). A failed republish
  increments `yuzu_server_ca_crl_publish_failures_total` and audits
  `ca.crl.published` `result=failure` — alert on it: the public CRL is stale while
  server-side enforcement is already live.
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
| PR5 | Gateway TLS: upstream mutual TLS **reference config** (`sys.config.prod`) + `agent_pb`/`gateway_pb`/`management_pb` regen so per-agent mTLS enrollment forwards through the gateway + fail-closed-on-unverified startup guard + TLS-posture logging. (Shipped images/composes stay plaintext until PR5b wires it.) | shipped |
| PR5c | One-way (server-authenticated) TLS on the agent listener — vendored+patched grpcbox (`_checkouts/grpcbox`) makes `verify`/`fail_if_no_peer_cert` configurable; agent listener enabled in `sys.config.prod`. Closes the plaintext agent↔gateway edge with no client cert required (bootstrap-safe). Live-wiring + CA distribution + boot-test land in PR5b. | shipped |
| PR5b | Distribution flip — drop `--no-tls`/`--no-https` across compose/Dockerfile + shared cert volume + **wire PR5c one-way TLS live + distribute the CA to agents** (HTTPS healthcheck, volume timing; needs a booted stack — no CI boots the deploy composes). **Partial — shipped:** `--cert-san` + Dockerfile.server cert-dir ownership (boot-test-validated). | in progress |
| PR6 (M2) | Subordinate-CA — export the CA CSR (`GET /ca/root-csr`) + import an enterprise-signed intermediate (`POST /ca/import-chain`, validates carries-our-key + is-CA + chains-to-parent) → `CaMode::Subordinate`; issued leaves chain to the corporate root, issuing key unchanged. Engine `cert_matches_key`/`cert_is_ca`/`verify_chain_to_bundle`; `ca_root.chain_pem` (migration v4); dashboard import panel. See "Subordinate-CA" above. | in review |

Deferred follow-ups tracked across the ladder: `POST /api/v1/ca/issue` with
namespace separation; **gateway mgmt-listener mTLS for the server
command-forwarding client** (one-way TLS would leave the privileged mgmt plane
unauthenticated — use strict mTLS there, not the agent-listener one-way posture);
**MCP approval re-dispatch** — the `revoke_certificate`
tool's success path (revoke → CRL republish → `audit_persisted`) is fully
implemented but today the generic supervised-tier approval gate returns before
the dispatch body runs, so it has no end-to-end MCP coverage (the identical
logic IS covered on the REST path); building the approval re-dispatch unlocks
both the execution and its test (#1240 M3/M4/L4); centralized revocation/identity
gRPC interceptor + `--require-agent-identity`; **through-gateway revocation +
per-agent identity enforcement** (per-agent mTLS is direct-connect-authoritative
— a gateway-proxied agent presents the single `default-gateway` leaf upstream, so
the data-plane `is_revoked` gate cannot see its serial; revoking it does not cut
it off, and the gateway needs agent-identity *attestation* — not just transport
mTLS — before it forwards enrollment (the **R-6 confused-deputy** residual: a
compromised/on-path gateway can swap the agent's CSR for its own keypair and have
the server issue a CA leaf for the victim's `agent_id` — valid for persistent
direct gateway-bypassing reconnect — or strip `csr_pem` to downgrade the agent to
no-mTLS. **PR5d shipped the gateway-path signing without this gate, so the CSR-swap
forgery is now a LIVE, bounded, accepted M1 residual** — see R-5 in
`docs/security-reviews/pki-pr5-gateway-tls.md`; compensating controls are that the
gateway is upstream-mTLS-authenticated and every forged leaf is recorded in
`ca_issued` + revocable, and a revoked `agent_id` is then re-issue-blocked by the
#1239 HIGH-2 guard. Closed durably by gateway-mTLS / the QUIC through-gateway
identity migration, #376); **gateway `_pb.erl` regen CI guard** — gpb generates
self-contained modules, so a field added to the agent-listener `agent_pb` but not
the `ProxyRegister` marshaller `gateway_pb` is silently stripped in transit (the
PR5 `csr_pem` catch; `agent.proto:96`); a per-module roundtrip test covers it but a
CI regen+diff job (elevated **before PR5d**) is the structural fix; **durable
cross-instance CRL numbering** (`next_crl_number()` = `MAX(version)+1` is serialised
within one instance via `crl_publish_mu_`, but an HA/multi-instance/DB-restore
scenario can still collide — `record_crl` rejects a duplicate rather than
clobbering, #1240 UP-4); revoke-superseded-cert-on-renewal; the `is_revoked`
heartbeat hot-path in-memory revoked-set memoization (pairs with the open-stream
sweep); a distinct gateway **upstream TLS-handshake-failure metric**
(`yuzu_gw_upstream_tls_handshake_failures_total`, R-3) so cert-expiry / CA-rotation
/ wrong-SAN failures don't collapse into a generic circuit-open; an env-substituted
`sys.config.src` so `YUZU_GW_TLS_*` actually drive the grpcbox cert paths (today
they set an advisory `yuzu_gw` env that nothing consumes, R-2);
`enrollment_request_id`→enrollment-decision correlation; `crlNumber` in the
`ca.crl.published` audit detail; a `yuzu_server_ca_cert_revoked_total` counter +
`/readyz` `ca_crl_published` signal; a dedicated public-CA rate-limit bucket;
dropping expired entries from the CRL; `ca.db` expired-row pruning;
`yuzu_server_ca_*_expiry_seconds` gauges + alerting; a `docs/security-reviews/`
PKI record + risk-register entries; ACME (P3).

**Closed by the #1240 review round:** active teardown of a live Subscribe stream
on revocation (the periodic sweep, PR3 H-1); periodic CRL re-publish before
`nextUpdate` + startup-503 self-heal (the freshness check); the revoked-identity
re-provision guard (PR3 H-2); `idx_ca_issued_issued_at` for the inventory sort.
**Addressed by the #1243/#1244 round:** the agent↔gateway edge encryption
(one-way TLS capability, PR5c — vendored+patched grpcbox, agent listener enabled
in `sys.config.prod`) with live wiring + CA-to-agent distribution in PR5b;
`--cert-san` for cross-host default leaves; the PR5 over-claim corrected (gateway
CSR survives transit but is not signed until PR5d). (The plaintext-`:50051`
agent-listener bind-default was reviewed and kept at `0.0.0.0` — agents must
reach it; the plaintext exposure is gated behind the deliberate `--no-tls`
banner.)
