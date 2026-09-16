- **Self-service REST rotation for human API tokens (P2 #11, SOC 2 CC6.3).**
  `POST /api/v1/tokens/{id}/rotate` mints a successor token alongside the
  still-valid predecessor for an overlap window (default 7 days, 24h floor /
  10y ceiling), gated on **`ApiToken:Rotate`** — a new RBAC operation,
  deliberately distinct from `ApiToken:Write` (which stays scoped to
  create/list/revoke), so an MCP token's operator-tier allowance for these
  routes can never widen `POST /api/v1/tokens`'s mint surface too — with MFA
  step-up re-validated on every call including an idempotent re-serve; `POST
  /api/v1/tokens/{id}/confirm` is the explicit maker-checker attestation that
  closes the rotation and revokes the predecessor. Both routes are
  self-service only — unlike `DELETE /api/v1/tokens/{id}`, there is no admin
  override, since a human token's raw secret authenticates as that user — and
  both return an identical `404 token not found` for a nonexistent token and
  one owned by someone else, closing the same enumeration-oracle gap the
  existing DELETE route closes. Rotation is deliberately lifetime-neutral:
  the successor always inherits the predecessor's `expires_at` verbatim, with
  no request field able to override it, so a credential rotation can never be
  read as a disguised lifetime extension in CC6.3 evidence. `GET
  /api/v1/tokens` now surfaces `rotation_group`/`supersedes_token_id`/
  `overlap_expires_at`/`confirmed_at` on a token while a rotation is (or was)
  in flight for it. See `docs/user-manual/rest-api.md` "API Tokens".
