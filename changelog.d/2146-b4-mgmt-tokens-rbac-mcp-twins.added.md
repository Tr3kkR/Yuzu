- **Management-group, API-token, RBAC-check, and account-unlock MCP twins (#2146 Batch B4).**
  Eleven new MCP tools give an agentic worker parity with the remaining `/api/v1/management-groups*`,
  `/api/v1/tokens*`, `/api/v1/rbac/check`, and `/api/v1/users/{name}/unlock` REST v1 surface
  (`list_management_groups`/`preview_management_group_agent_count`/`rotate_api_token`/
  `confirm_api_token_rotation` already had twins): `create_management_group`, `get_management_group`,
  `update_management_group`, `add_management_group_member`, `list_management_group_roles`,
  `assign_management_group_role`, `list_api_tokens`, `create_api_token`, `revoke_api_token`,
  `check_permission`, and `unlock_account`. Each mirrors its REST handler's real authorization gate
  exactly, verified by reading the full handler rather than inferring from the route path or securable
  name: `list_management_group_roles` and `assign_management_group_role` both run the REST route's
  compound gate (a fleet-wide permission OR the caller already holding `ITServiceOwner` on the group
  in question, the fallback skipped for a service-scoped token) on top of `list_management_group_roles`'s
  own leading `ManagementGroup:Read` gate (#2376 - the caller must be allowed to see the group AND
  allowed to see role assignments); `assign_management_group_role`
  additionally restricts `role_name` to `Operator`/`Viewer` only, matching REST, with the underlying
  store's `RbacStore::validate_assignment` dangerous-role-block chokepoint as defense in depth;
  `check_permission` mirrors `POST /api/v1/rbac/check`'s deliberate zero-RBAC-gate posture (a self-check
  of the caller's own authority, open to any authenticated caller); `create_api_token` mirrors the
  REST route's multi-store (`RbacStore` + `ManagementGroupStore`) authority check for a service-scoped
  token; `list_api_tokens` and `create_api_token` are unconditionally self-scoped to the calling
  principal, matching REST exactly (there is no admin all-owner-token view on this route - that
  capability exists only as an HTMX dashboard fragment with no REST v1 route yet, so no MCP twin).
  `list_management_group_roles`/`list_api_tokens`/`check_permission`/`get_management_group` are
  read-only; the other seven, including `create_api_token`, are approval-gated at the supervised MCP
  tier like every other privileged mutation (`ApiToken:Write` is now in `mcp_policy.hpp`'s
  supervised-tier `requires_approval()` list - closing a gap, shared with the identically-gated REST
  route, where a supervised-tier caller could self-mint a fresh, untiered, non-expiring credential
  with neither MFA step-up nor human approval; `ApiToken:Rotate` stays deliberately ungated per its
  own documented rationale, which does not transfer to minting a brand-new credential).
  `McpServer::LockoutClearFn` (mirroring `RestApiV1::LockoutClearFn`) is a new
  trailing `build_handler`/`register_routes` parameter backing `unlock_account`.
  Known limitation, tracked separately (#4309, not introduced by this batch): MCP
  tier/approval enforcement is architecture-wide inert for an MCP-tier-less caller
  (a cookie session, a plain non-MCP-tiered API token, or an engine token -
  `mcp_tier` is only ever set on an actual MCP token), so the
  approval-gating described above applies to MCP-token callers specifically, not
  to every caller of the underlying REST route - **except** for `create_api_token`,
  `revoke_api_token`, `unlock_account`, `rotate_api_token`, and
  `confirm_api_token_rotation` specifically, where a governance review round found
  this gap meaningfully widened (raw credential-minting, account-lockout-clearing,
  and credential rotation/reveal with no MFA step-up at all - not just an inert
  approval step) and a scoped fix landed in the same batch: an MCP-tier-less
  caller is now denied outright on these five tools rather than falling through to
  RBAC-only enforcement (`rotate_api_token`/`confirm_api_token_rotation` were
  fixed in a follow-up review round after the other three, once the identical
  pattern was found there too - `ApiToken:Rotate` was and remains deliberately
  NOT approval-gated per its own documented rationale, so this closes the
  missing-step-up gap without adding an approval requirement that was never
  intended for rotation). The architecture-wide gap remains open for every other
  approval-gated MCP tool (`execute_instruction`, `quarantine_device`,
  `revoke_certificate`, and the four `ManagementGroup:Write` mutations in this
  same batch).
