- **Breaking — `GET /api/v1/agent/plugin-policy`'s response body is now enveloped, not flat.**
  This pre-existing route (the trust-bundle-PEM distribution path for agent config management) is
  hardened onto the same `data`/`meta` success envelope and standard A4 error envelope every other
  `/api/v1/*` route uses, as part of #4028's Settings read-twin work. Every existing field
  (`enabled`, `required`, `trust_bundle_pem`, `cert_count`, `sha256`) moves one level deeper, under
  `.data`; two fields are new (`subjects`, `bundle_unreadable`/`bundle_error`). Authorization moves
  from a hard `require_admin` gate to the RBAC `PluginSigning:Read` permission (seeded
  Administrator-only; an MCP-tier token is denied earlier regardless). The route also gains two new
  `503` (retryable) responses where it previously answered `200` with a value it could not stand
  behind: a concurrent trust-bundle upload/clear racing the PEM re-read, and a `runtime_config_store`
  outage backing the `required` flag. See the upgrade note in `docs/user-manual/server-admin.md`.
