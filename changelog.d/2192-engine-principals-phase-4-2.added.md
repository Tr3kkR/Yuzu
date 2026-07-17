- **Engine principal class — store, RBAC resolution, and attribution plumbing (engine principals
  PR 4.2).** A new `EnginePrincipalStore` (born-on-PG, `engine_principal_store` schema) records
  autonomous/agentic identities in the reserved `engine:<slug>` namespace, and `RbacStore`/
  `ManagementGroupStore` gain the resolution + guard chokepoints that let a fleet-wide engine
  principal be granted (non-system) roles and have those roles resolve and attribute correctly in
  audit rows. Engine tokens (`ApiTokenStore`, principal_kind="engine") are referentially checked
  against the store at mint time, are always `mcp_tier=readonly`, and always carry a ≤90-day
  expiry — no perpetual, no service-scoped engine tokens. This release ships **no operator-facing
  surface** (no dashboard/REST CRUD for minting or managing engine principals — that lands in PR
  4.3) and **no scoped (management-group) engine role assignment** — engine grants are fleet-wide
  only in this release; scoped resolution is a Phase-5 deliverable.
  **Upgrade note:** the `engine:` prefix is now a reserved namespace for local usernames and local
  RBAC group names — the server **refuses to start** if a pre-existing `engine:`-named user or
  local group is found at boot. See the `## ⚠️ Breaking` section in
  `docs/user-manual/upgrading.md` and `docs/ops-runbooks/engine-principal-store-recovery.md` for
  the pre-upgrade check and recovery procedure.
