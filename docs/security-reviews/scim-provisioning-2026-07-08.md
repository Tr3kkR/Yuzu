# Security review — SCIM v2 provisioning (SOC 2 CC6.2/CC6.8)

**Date:** 2026-07-08
**Change:** SCIM 2.0 (RFC 7643/7644) User provisioning — an enterprise IdP
(Okta/Entra/OneLogin) can auto-provision and auto-deprovision Yuzu operator
accounts over `/scim/v2/*`, gated by `--scim-enable`/`--scim-token`.
**Branch:** `feat/auth-scim-v2`
**Controls:** SOC 2 **CC6.2** (provisioning — accounts created through a
controlled, auditable IdP-driven process rather than ad hoc admin action),
**CC6.8** (termination — deprovisioning that reliably disables access and
revokes live sessions on IdP-side offboarding). Closes `/auth-and-authz`
gap-matrix **P1 #7** (Users slice; Groups→role mapping is a deferred
follow-up).

## What shipped

- **`--scim-enable`** (`YUZU_SCIM_ENABLE`, default `false`) + **`--scim-token`**
  (`YUZU_SCIM_TOKEN`) gate the entire `/scim/v2/*` route surface — when
  disabled, no SCIM route exists at all. Two fail-closed boot guards: (1)
  `--scim-enable` without `--scim-token` refuses to start (no way to gate an
  account-mutating surface without a credential); (2) `--scim-enable` with
  `--no-https` refuses to start (the bearer token must never cross the wire
  in plaintext). The active posture is logged once at boot for CC6.2
  evidence.
- **Bearer auth on every route, including discovery.** `Authorization: Bearer
  <token>` validated **constant-time** (`CRYPTO_memcmp`) against a SHA-256
  hash — mirrors `ApiTokenStore`'s hashing pattern (verify-only; the raw
  token is never stored). Failure is a uniform `401` +
  `WWW-Authenticate: Bearer` regardless of cause (missing header, malformed
  header, wrong token) — no oracle distinguishing "SCIM not configured" from
  "wrong token." Every authenticated call maps to a fixed `scim-service`
  audit principal, entirely separate from operator API tokens and session
  cookies.
- **Provisioning floor: `role=user`, always.** `POST /scim/v2/Users` creates
  the account at the fixed, read-only `user` role with a discarded
  CSPRNG-generated password (the account authenticates via SSO, never a
  local password). There is no field in the SCIM User schema, nor any code
  path, that can set a SCIM-provisioned account to `role=admin`. A duplicate
  `userName` is rejected `409` rather than silently upserting an existing
  account's data.
- **The provenance guard (the load-bearing invariant).** Every
  deactivate/reactivate/update/delete call re-verifies
  `provisioning_source == "scim"` (a new `users` column,
  `AuthDB::set_provisioning_source`/`get_provisioning_source`, auth.db
  migration v7) **immediately before** mutating the target account. A
  mismatch refuses with **`404`, never `403`** (a `403` is an existence
  oracle — it confirms the resource is real but protected) plus a
  `scim.user.provenance_denied` audit row, so the attempt is still
  recorded even though the caller sees a plain not-found.
- **Deprovision cascades sessions; reactivation does not resurrect MFA.**
  `active:false` (via `PATCH`, `PUT`, or `DELETE`) soft-deletes the auth
  account **and** revokes any live session for that user — a terminated
  employee's in-flight session does not outlive the IdP's call. `active:true`
  restores the account and clears stale lockout state, but deliberately does
  **not** restore TOTP enrollment — a reactivated user re-enrolls MFA from
  scratch, so a dormant device/secret from before termination is never
  trusted again. Session revocation is the *auth session* cascade — see the
  API-token caveat under Residual risks below for a related, narrower gap.
- **The provenance guard now also re-checks `role`.** Every deactivate/
  reactivate/update/delete re-verifies `provisioning_source == "scim"` **and**
  `role == "user"` immediately before mutating, refusing `404` on either
  mismatch. This closes a gap where a SCIM-provisioned account later
  promoted by a human admin (e.g. to `admin`) could still be torn down by an
  IdP push — that account now drops out of SCIM's write authority the
  moment it is elevated, regardless of how it was originally created.
- **Reprovisioning a returning employee is supported.** `POST` against a
  `userName` matching an existing, currently-**deactivated** SCIM-provisioned
  account revives it rather than `409`ing — a `409` is reserved for a
  collision against a currently-**active** account. This closes a usability
  gap (a `409` on rejoin would have forced manual admin intervention) without
  weakening the uniqueness guarantee against active accounts.
- **Audit posture: set-and-proceed, evidence integrity enforced by an
  alert on the failure metric.** All lifecycle actions (provision, update,
  deactivate, reactivate, delete) complete even if their audit write fails,
  and every failure unconditionally bumps `yuzu_scim_audit_write_failures_total`.
  A fail-closed `500` on a *termination* audit-write failure was evaluated
  and deliberately **rejected**: the IdP's retry re-reads the now-terminated
  post-state, takes the non-termination (no-op/`404`) branch, and so never
  re-attempts the missing audit — the `500` cannot re-land the evidence row it
  was meant to guarantee, it only fails the request. The correct control for
  CC6.8 evidence integrity is therefore an **alert on
  `yuzu_scim_audit_write_failures_total > 0`** (same-day human follow-up on a
  missed termination record), not a fail-closed request path. Deploy that
  alert rule alongside enabling SCIM.
- **New metrics close an observability gap.** `yuzu_scim_requests_total{op,
  status}`, `yuzu_scim_auth_failures_total`, `yuzu_scim_audit_write_failures_total`,
  and `yuzu_scim_provenance_denied_total` give an operator a Prometheus-native
  signal for auth failures, guard denials, and audit-write failures on this
  surface without having to scrape the audit log directly — this is a
  strengthened control added in this hardening round, not present in the
  original review.
- **Storage rides `auth.db`, not a new store.** `scim_resources` (id/
  externalId ↔ username mapping) and `scim_tokens` (sha256 hashes) live
  inside the same `auth.db` file `AuthDB` manages, under their own
  `MigrationRunner` component (`"scim"`) independent of AuthDB's own
  `"auth_db"` track — so user identity stays on one substrate and rides
  `auth.db`'s eventual Postgres migration (ADR-0006) rather than needing a
  second migration path or second `.db` file.
- **Audit actions:** `scim.user.provisioned`, `.updated`, `.deactivated`,
  `.reactivated`, `.deleted`, `.provenance_denied`, and (new this round)
  `scim.auth.denied` — all `target_type=User`, `principal=scim-service`.
  Result values are `success` | `failure` | `denied` (not `ok`/`error`).

## Threats considered

- **Compromised or misconfigured IdP connector deactivating an account it
  didn't create.** Closed by the provenance guard: the mutation re-checks
  `provisioning_source` at the mutation site (not just at lookup), and a
  mismatch is a plain `404` rather than a `403` that would confirm the
  target account's existence to an attacker probing SCIM ids.
- **Compromised IdP minting an admin account.** Closed structurally —
  `POST /scim/v2/Users` has no admin-granting field or code path; every
  SCIM-provisioned account is `role=user`.
- **Break-glass / local-admin lockout via a spoofed or malicious SCIM
  push.** Closed by the same provenance guard — the break-glass account and
  any locally-created admin have `provisioning_source != "scim"`, so no
  SCIM deactivate/delete call can ever reach them, independent of how the
  attacker obtained or guessed their SCIM-facing `id`.
- **Enumeration via response shape.** The `404`-not-`403` provenance
  response and the uniform `401` auth-failure envelope both avoid handing
  an attacker a signal distinguishing "exists but protected" from "does not
  exist," or "wrong token" from "SCIM disabled."
- **Terminated user's session outliving the IdP's deprovisioning call.**
  Closed — `active:false` cascades session revocation in the same request
  that soft-deletes the account, rather than relying on the session's own
  expiry or a separate reconciliation pass.
- **Stale MFA reused after a reactivation.** Closed — reactivation clears
  lockout but explicitly does not restore TOTP enrollment state; the
  returning user must re-enroll.
- **SCIM token replay / theft.** Standard bearer-token exposure surface,
  mitigated the same way any bearer credential is: HTTPS is mandatory (boot
  guard), the token is stored only as a verify-only hash (a `auth.db` leak
  does not disclose the raw token), and comparison is constant-time to
  avoid a timing side channel on the hash comparison itself.

## Residual risks (accepted / tracked)

> **Correction to this review's original framing.** An earlier draft of
> this document characterized deprovision as unconditionally "cascading
> session revocation / revoking any live session," which overstates the
> guarantee in three respects corrected below: (a) it does not revoke a
> live **API token**; (b) the auth-session cascade itself has an
> irreducible crash-window (not a bug, a property of the two-connection
> design); (c) it says nothing about the `userName`-charset limitation
> that can block provisioning entirely for a naively-configured IdP. All
> three are recorded here rather than silently left as an inflated claim.

- **API-token revocation on user delete/deactivate is a pre-existing,
  shared gap — not new to SCIM — and a live limitation on this review's
  CC6.8 (termination) claim.** SCIM's deactivate/delete path revokes the
  user's **auth sessions** but does not revoke that user's live **API/MCP
  tokens** (`ApiTokenStore` rows are not touched). Concretely: a terminated
  employee who had previously minted a personal API token keeps the ability
  to authenticate with it after SCIM deprovisions their account — the
  termination evidence this review cites for CC6.8 covers session/login
  access only, not token-based access. This is not a SCIM-specific
  omission: the dashboard's own manual "disable user" path has the same
  gap today. Tracked as
  [#2022](https://github.com/Tr3kkR/Yuzu/issues/2022) (give `AuthManager` a
  non-owning `ApiTokenStore*` and revoke-by-principal inside
  `remove_user`, fixing both paths at once) — not something this SCIM slice
  introduced or is uniquely responsible for closing. Operator-facing
  guidance (manual token revocation until #2022 ships) is documented in
  `docs/user-manual/scim-provisioning.md` "Deprovisioning and termination".
- **The two-connection deactivate/reactivate path has an irreducible
  crash-window.** `ScimStore` and `AuthDB` are separate `sqlite3`
  connections onto the same `auth.db` file; a crash between "soft-delete
  the account" and "revoke sessions" is not covered by a single atomic
  transaction. This is accepted, not deferred-as-a-bug: the recovery
  mechanism is the IdP's own periodic re-sync (SCIM connectors poll/re-push
  state on a schedule), which re-issues the deactivate call and closes the
  gap within one sync interval, rather than a code-level fix in this slice.
- **`userName` is email-incompatible; a naive IdP setup 400s on every
  provisioning call.** Yuzu usernames are slug-shaped (no `@`); Okta/Entra's
  default `userName=email` mapping fails closed (`400`) rather than
  silently truncating or mangling the value — correct fail-closed behavior,
  but a real setup-friction point until native email-`userName` support
  ships. Tracked in `docs/auth-architecture.md` "Residual risks / deferred".
- **`location_base` trusts `Host`/`X-Forwarded-Proto`.** The `Location`
  header on a `201` and the `meta.location` field in SCIM User bodies are
  built from the request's `Host`/`X-Forwarded-Proto`, which are
  client-influenceable in general. Accepted here because the caller is
  already the single authenticated IdP bearer-token holder — there is no
  additional principal this could be used to confuse, and the field is
  advisory (a client-convenience URL, not used in any authorization
  decision). Same accepted pattern as other server-constructed `Location`
  headers in the REST v1 surface.
- **No SCIM-specific rate limit.** SCIM calls share the server's global
  rate-limit only; there is no throttle tuned to expected IdP-connector call
  volume/shape. A compromised or malfunctioning connector could still hit
  the global limit but has no SCIM-specific amplification path beyond that.
  Tracked as a follow-up (`docs/auth-architecture.md` "Residual risks /
  deferred (next slice)").
- **SCIM bearer token stored as a verify-only hash, not a reversible
  encrypted blob.** This is actually the *stronger* posture (nothing to
  decrypt if `auth.db` leaks), so it is not itself a gap — noted because a
  future reversible form (if ever needed for token display/rotation UX)
  would ride `auth.db`'s Postgres/`SecretCodec` migration (ADR-0010),
  alongside the TOTP-secret-at-rest follow-up.
- **Groups→role mapping is out of scope this slice.** Every
  SCIM-provisioned account is `role=user`; there is no path (by design) to
  provision or promote an admin via SCIM in this release. Tracked as the
  next SCIM slice, mirroring the OIDC/SAML group→role mechanisms.
- **`userName` rename via `PUT` is rejected, not supported.** A `400
  mutability` response requires the IdP-side workflow to delete + re-create
  rather than rename in place. No security impact — a narrower surface, not
  a gap.

## Validation

- Unit tests: `tests/unit/server/test_scim_store.cpp` (token hashing +
  constant-time validate, resource CRUD, provenance-relevant fields),
  `test_scim_json.cpp` (codec + filter parsing + discovery documents),
  `test_scim_routes.cpp` (wire path: bearer auth on every route including
  discovery, provisioning at fixed `role=user`, `409` uniqueness, `400`
  invalid filter/mutability, `404` provenance-guard rejection, deactivate/
  reactivate/delete semantics, audit rows).
- Storage layer opens its own `sqlite3` connection to the same `auth.db`
  file `AuthDB` manages, under an independent `"scim"` `MigrationRunner`
  component — verified against `migration_runner.{hpp,cpp}` not to collide
  with AuthDB's own `"auth_db"` migration track on the same file.

## Reviewer

Junior-developer implementation across three code slices (storage / JSON
codec / routes) plus this documentation and compliance-evidence pass, on
`feat/auth-scim-v2`.
