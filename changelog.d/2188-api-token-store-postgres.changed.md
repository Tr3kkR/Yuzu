- **BREAKING: `ApiTokenStore` (API/MCP bearer tokens) now lives in PostgreSQL, not SQLite.** As part of
  the engine-principals program (PR 4.1), the token store migrated from `api-tokens.db` to the
  server's Postgres substrate and gained a `principal_kind` column (`human` today; `engine`
  arrives in a later release). This is a **fresh-start cutover with no data backfill** —
  **all existing API tokens and MCP tokens are invalidated by the upgrade. Re-mint every API/MCP
  bearer token after upgrading** (`POST /api/v1/tokens`) and update the credential wherever it is
  stored (CI secrets, cron jobs, MCP clients). Because it is a fresh-start cutover, every
  bearer-token integration breaks at once — plan a maintenance window and notify automation owners
  in advance. Interactive cookie-session login (dashboard, OIDC/SAML SSO) is unaffected. See the
  `## ⚠️ Breaking` section in `docs/user-manual/upgrading.md` and ADR-0030.
