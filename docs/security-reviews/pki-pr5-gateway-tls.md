# Security review — PKI PR5: gateway upstream mTLS + per-agent enrollment through the gateway

- **Date:** 2026-06-04
- **Change:** `feat/pki-pr5` (gateway upstream mutual TLS reference config, `agent_pb`/`gateway_pb`/`management_pb` regen so per-agent enrollment forwards through the gateway, fail-closed-on-unverified startup guard, accurate TLS-posture logging)
- **Reviewers:** Hermes ×2 (adversarial + Anthropic cybersecurity skill-pack); `/governance` Gates 2–6 (security-guardian, docs-writer, gateway-erlang, architect, happy/unhappy/consistency, compliance/sre/enterprise-readiness)
- **SOC 2 controls:** CC6.1, CC6.6, CC6.7 (transmission encryption), CC6.8 (key/crypto management), CC3.2 (risk identification), CC7.2 (change management)

## Scope

The Erlang gateway is an **optional** scale-out command fan-out plane between agents
and the C++ server. This change (a) enables mutual TLS on the gateway→server upstream
hop as a reference config, (b) fixes a silent field-drop so per-agent mTLS enrollment
works through the gateway, and (c) makes the gateway's TLS posture honest + fail-closed.
It does **not** change the agent↔gateway transport (still plaintext — see residual risk
R-1) and does **not** flip the shipped images/composes to TLS-by-default (that is PR5b).

## Threats considered

- **Passive eavesdropping / active MITM on the gateway→server hop.** Mitigated:
  mutual TLS (CA-issued `default-gateway` leaf, `verify_peer`, TLS 1.2 floor,
  ECDHE-ECDSA AEAD/PFS cipher whitelist, depth 2). A real EC mutual-TLS handshake +
  certless-client-rejection are unit-proven. Boot **fails closed** if the channel is
  `https` without `verify_peer` (`evaluate_upstream_posture/2`).
- **Silent downgrade to plaintext.** Mitigated: the latent bug (listener
  `transport_opts` missing grpcbox's required `ssl => true`) is removed; `log_tls_state/0`
  classifies and warns on `unverified`/`plaintext`; the upstream guard refuses boot on
  `unverified`.
- **Confused-deputy via forwarded `csr_pem`.** Not exploitable: the gateway forwards the
  CSR verbatim and never parses/validates/acts on it; the server is the sole POP-verifier
  and signer and ignores CSR subject/SAN (PR3). `issued_certificate` is a response-only
  field a request cannot usefully set.
- **Proto field-drop in transit.** Was the live bug (gpb self-contained modules); fixed by
  regenerating all three embedding modules + per-module roundtrip tests. CI codegen-guard
  is follow-up F-3.

## Residual risks (risk register)

| ID | Risk | Likelihood | Impact | Compensating control | Remediation |
|---|---|---|---|---|---|
| **R-1** | **Plaintext agent↔gateway listener (`:50051`).** On an untrusted-network-exposed gateway, an on-path attacker can inject `CommandRequest`s (fleet RCE), read inventory, or impersonate the gateway. No transport auth/confidentiality on that hop. | Med (deployment-dependent) | **Critical** | Deployment-layer: TLS-terminating proxy in front of `:50051`, or keep on a trusted network (VPN/private subnet/mesh). Documented in `gateway.md`, `security-hardening.md`, `sys.config.prod`, CHANGELOG. Direct agent→server is full mTLS. | Native one-way TLS on the listener — needs a grpcbox patch (configurable `fail_if_no_peer_cert`/`verify`) or the QUIC transport (#376). Tracked as **PR5c**. |
| **R-2** | **`YUZU_GW_TLS_*` env vars are inert** — they set an advisory `yuzu_gw` env nothing consumes; an operator may believe they enabled TLS. | Low | Med (plaintext upstream by surprise) | `log_tls_state/0` warns unconditionally when the env is set; fail-closed guard catches the resulting `unverified`/plaintext on the upstream. | Env-substituted `sys.config.src` so `YUZU_GW_TLS_*` drive grpcbox cert paths (P1 before any gateway-enabled enterprise deployment guide). |
| **R-3** | **Upstream-TLS failures are not distinctly observable** — expired/wrong-SAN cert / missing volume collapse to a generic circuit-open; an operator can't tell "cert broke" from "server down". | Med | Med (extended incident / MTTR) | Existing circuit-breaker telemetry + `/readyz` 503; startup posture log. | Dedicated `yuzu_gw_upstream_tls_handshake_failures_total` counter + runtime posture gauge (follow-up F-1). |
| **R-4** | **Cert-SAN ↔ dial-name** mismatch silently strands a cross-host gateway (OTP enforces SNI under `verify_peer`). | Med | Med | Documented SAN/`hostname:` requirement in `sys.config.prod` + `pki-architecture.md`. | `--cert-san` flag to add SANs to default certs (tracked). |

## Tracked follow-ups

- **F-1** — `yuzu_gw_upstream_tls_handshake_failures_total` counter (classify `tls_alert`/`handshake_failure` in `do_rpc`) + a runtime TLS-posture gauge (R-3, sre).
- **F-2** — message-size cap (`max_recv_message_length`) on the gateway listener so an oversized `csr_pem`/any field can't pressure memory (pre-existing for all fields).
- **F-3** — CI guard: regenerate all gateway `_pb.erl` from the vendored protos + diff against committed, and assert every multi-module-embedded message has an identical `{name,fnum,type}` set matching canonical (would convert R-of-drift into a hard CI failure).
- **F-4** — `via=gateway_proxy` in the server's `ca.cert.issued` audit `detail` when signing arrives via `ProxyRegister` (direct vs proxied issuance traceability).
- **F-5** — CAIQ/security-questionnaire answer for "is all agent traffic encrypted in transit?" (see "Customer assurance" below).

## Customer assurance (questionnaire answer)

> Agent-to-server connections are protected by mutual TLS (per-agent certificates issued
> by Yuzu's internal CA). When the optional Erlang gateway scale-out plane is deployed,
> the gateway-to-server upstream is also mutual TLS. The agent-to-gateway listener is
> plaintext in the current release pending a grpcbox one-way-TLS patch (tracked); for any
> gateway-exposed deployment this hop must be protected at the network layer (TLS-terminating
> proxy or private/VPN network). Direct-connect deployments (no gateway) are fully
> encrypted end-to-end.

## Verdict

Net security improvement; no CRITICAL/HIGH unresolved. R-1 is a **documented, deployment-mitigated**
residual risk with a tracked native fix (PR5c); it is acceptable for M1 provided the deployment
mitigation is enforced for any exposed gateway. The shipped reference config + proto fix are
unit-proven (197 eunit pass, dialyzer clean, real EC mTLS handshake).
