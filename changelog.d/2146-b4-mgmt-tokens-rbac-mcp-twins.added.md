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
  in question, the fallback skipped for a service-scoped token); `assign_management_group_role`
  additionally restricts `role_name` to `Operator`/`Viewer` only, matching REST, with the underlying
  store's `RbacStore::validate_assignment` dangerous-role-block chokepoint as defense in depth;
  `check_permission` mirrors `POST /api/v1/rbac/check`'s deliberate zero-RBAC-gate posture (a self-check
  of the caller's own authority, open to any authenticated caller); `create_api_token` mirrors the
  REST route's multi-store (`RbacStore` + `ManagementGroupStore`) authority check for a service-scoped
  token; `list_api_tokens` and `create_api_token` are unconditionally self-scoped to the calling
  principal, matching REST exactly (there is no admin all-owner-token view on this route — that
  capability exists only as an HTMX dashboard fragment with no REST v1 route yet, so no MCP twin).
  `list_management_group_roles`/`list_api_tokens`/`check_permission`/`get_management_group` are
  read-only; the other seven are approval-gated at the supervised MCP tier like every other
  privileged mutation. `McpServer::LockoutClearFn` (mirroring `RestApiV1::LockoutClearFn`) is a new
  trailing `build_handler`/`register_routes` parameter backing `unlock_account`.
