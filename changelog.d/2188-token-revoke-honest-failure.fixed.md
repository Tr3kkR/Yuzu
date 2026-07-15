- **API-token and "Sign out everywhere" revocation now reports a database write failure instead of a
  false success.** When the token store cannot persist a revoke (a Postgres lease timeout or query
  error), `DELETE /api/v1/tokens/{id}` returns `503` with `Retry-After` (previously a misleading
  `404 not found`), `DELETE /api/v1/sessions/me` audits the action as `partial` and reports a new
  `api_tokens_db_persisted: false` field (previously it audited `success` and dropped the API-token
  outcome entirely), and the dashboard's token-revoke control shows a retry error rather than a
  success toast. An operator revoking a stolen device's credential is now told when the revoke did
  not actually land (ADR-0030 §Posture). Token reads (`GET /api/v1/tokens`, the ownership check on a
  single-token revoke, and the dashboard token panel) likewise surface a Postgres outage as a
  retryable `503` rather than an empty list or a false `404` (ADR-0012 §1).
