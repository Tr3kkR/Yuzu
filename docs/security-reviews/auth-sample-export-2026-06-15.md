# Security review — Sampled auth-log evidence export (SOC 2 CC7.2)

**Date:** 2026-06-15
**Change:** `GET /api/v1/audit/auth-sample` + `AuditQuery` sampling/prefix knobs
**Branch:** `feat/auth-log-sample-export`
**Control:** SOC 2 **CC7.2** (monitoring → anomaly detection; sampled auth-log
evidence for auditors). Closes the `/auth-and-authz` P0 gap "sampled auth-log
evidence export".

## What shipped

- **REST:** `GET /api/v1/audit/auth-sample?from=<epoch>&to=<epoch>&limit=N`
  (default 100, cap 1000). Returns a pseudo-random sample of authentication-
  surface audit events over an optional window, in random order so a bounded
  `limit` is representative of the window rather than the latest N.
- **Scope:** the `auth.`, `mfa.`, and `session.` action prefixes (login,
  login_failed, logout, OIDC login, admin/permission-gate denials, lockout,
  MFA enrol/login/step-up, session revocation). Noise (e.g. `instruction.*`,
  `tag.*`, `ca.*`) is excluded.
- **Data layer:** `AuditQuery` gains `action_prefixes` (parameterised
  `action LIKE ?||'%'` OR-group) and `random_sample` (`ORDER BY RANDOM()`),
  both in `audit_store.{hpp,cpp}`. All SQL parameterised.

## Control / authz decision

- **Gated on `AuditLog:Read`, NOT `require_admin`.** The original gap note
  suggested `require_admin`; this implementation deliberately uses the RBAC
  `AuditLog:Read` permission instead, consistent with the sibling
  `GET /api/v1/audit`. Rationale: **separation of duties** — an organisation
  can grant a dedicated read-only auditor principal `AuditLog:Read` to pull
  evidence WITHOUT also granting full administrative authority. This is a
  stronger SOC 2 posture (CC6.3 least-privilege) than admin-only, not a
  weakening: `AuditLog:Read` is itself a privileged, RBAC-gated permission and
  the sibling audit-query endpoint already uses it.
- **Evidence access is itself audited** — every export emits
  `audit.auth_sample.exported` (`result=ok`, target `AuditLog/auth-sample`,
  detail = `from`/`to`/`limit`/`returned` count). So pulling evidence is on the
  audit chain (CC7.2 chain-of-custody). Emission is best-effort and never fails
  the read.

## Hard-invariant check

- All SQL parameterised; prefixes are code-controlled constants (no LIKE
  metacharacter injection); an all-empty prefix list fails closed to an
  always-false predicate (never silently widens to "all actions"). ✅
- `503` when the audit store is unwired; `400` on non-numeric / negative
  `from`/`to`; structured JSON error envelope throughout. ✅
- No `AuditStore` mutex held while emitting the export audit (the audit_fn call
  happens after `query()` returns). ✅
- A2 discovery: the endpoint is enumerable in `GET /api/v1/openapi.json`. ✅

## Tests

- `test_audit_store.cpp` — prefix scoping (auth surface only, noise excluded),
  all-empty-prefix fails closed, and `random_sample` stays within `[since,until]`
  + prefix scope + `limit`.
- `test_rest_audit_sample.cpp` — 200 scoped result, `limit` honoured, the
  export emits `audit.auth_sample.exported`, `AuditLog:Read` 403 gate, `503` on
  no store, `400` on malformed `from`.
- `test_rest_api_events.cpp` — A2 OpenAPI discovery lists `/audit/auth-sample`.

## Hermes adversarial pass (pre-submission gate)

Pass 1 (adversarial) found no CRITICAL/HIGH. Addressed before submission:
- **M-1 (DoS via `ORDER BY RANDOM()`):** replaced with a bounded indexed scan
  (`ORDER BY timestamp DESC LIMIT <=10000`) + C++ shuffle/truncate, so the
  reader-lock hold and CPU are bounded regardless of window size. Documented
  recency bias only when the window exceeds the 10k candidate cap.
- **M-2 (info disclosure):** the response field set now matches the sibling
  `GET /api/v1/audit` exactly — `session_id` and `source_ip` are NOT exposed, so
  `AuditLog:Read`'s disclosure surface is unchanged.
- **L-2 (malformed `limit`):** now returns 400 (stricter than the legacy endpoint).
- **L-3 (inverted `from>to`):** now returns 400.
- **L-1 (`from`/`to` overflow):** non-issue — `std::stoll` throws `out_of_range`
  on overflow (unlike `strtoll`), caught → 400; also reject trailing junk via the
  `consumed == size` check.
- **I-1:** `AuditQuery.action_prefixes` LIKE-injection contract documented in the
  header (callers must pass only code-controlled literals).

## Governance pipeline (Gate 1–8)

Full `/governance` run after Hermes. No CRITICAL/HIGH. Addressed in a hardening round:
- **Docs BLOCKING** — `audit.auth_sample.exported` added to the authoritative
  `docs/user-manual/audit-log.md` logged-actions table (+ rest-api.md inline table + curl).
- **Recency-bias (compliance/architect/enterprise/happy SHOULD)** — the response now
  carries a `sampling` object (`candidates_considered`, `scan_cap`, `recency_capped`) so
  an auditor can detect a non-uniform (recency-biased) sample; the cap + non-reproducibility
  are documented at the API surface (OpenAPI + rest-api.md). `kAuditSampleScanCap` is now a
  public constant; `query()` reports the pre-truncation pool size via an out-param.
- **UP-5 BLOCKING (prepare-failure → silent empty)** — `query()` now logs `spdlog::error`
  on `sqlite3_prepare_v2` failure so a DB fault is observable rather than masquerading as
  "no audit activity". (A fully-broken store is already pulled from `/readyz`.)
- **Consistency S1** — audit `result` is `"success"` (dominant vocabulary + the analogous
  `ca.root_csr.exported`), not `"ok"`.
- **cpp-expert S-1 / UP-9** — `from`/`to`/`limit` now reject leading whitespace / sign
  (digits-only), so "non-numeric → 400" is literally true.
- **QA SHOULDs** — added tests: `Sec-Audit-Failed` on audit-fn false/throw, clean export
  sets no header, over-cap pool path (recency_capped + bounded), `_`/`\` wildcard drop,
  scoping count bound, `sampling`/`recency_capped` response block.

### Deferred to follow-up issues (governance SHOULD/NICE, scoped out)
- **sre:** `yuzu_server_audit_auth_sample_exports_total{result}` Prometheus counter +
  per-principal rate limiting on the endpoint (shared-lock pressure under a hammering
  AuditLog:Read caller).
- **UP-5 full contract:** error-signaling `query()` so the REST layer can return 503 (not
  200-empty) on a store read error, not just log it.
- **Reproducible sample:** optional `seed`/result-set id so an auditor can re-fetch an
  identical sample.
- **CSV export form** + a dashboard audit-log view with a sample control.
- Operator-configurable `kAuditSampleScanCap`.

## Residual / follow-ups

- No CSV export form (JSON only); auditors that need CSV can transform
  client-side. Add a `format=csv` param if a customer requires it.
- Sampling is uniform-random within the window; no stratification by
  action-type. Sufficient for representative-sample evidence; revisit if an
  auditor requires guaranteed per-category coverage.
