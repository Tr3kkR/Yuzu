- **Fleet-wide engine-principal role assignment (#2202).** `GET`/`POST`/`DELETE
  /api/v1/engine-principals/{id}/roles` (`Security:Read`/`Security:Write`, mutations
  admin + MFA step-up gated) plus MCP twins `list_engine_roles`/`assign_engine_role`/
  `unassign_engine_role` let an admin actually grant an engine principal the fleet-wide RBAC
  authority the design promised — without this surface, `RbacStore::assign_role` had no
  production caller for the `engine` principal class, so a written grant could never take
  effect. Engine principals can never be assigned `admin`, any built-in system role, or a
  wildcard role — such a request is rejected outright, never silently narrowed. See
  `docs/user-manual/rest-api.md` "Engine Principals" and `docs/user-manual/mcp.md` for the
  full contract.
