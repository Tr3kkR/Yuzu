- **RBAC seeding fix (prerequisite for the workflow read-twin routes below):** `Workflow` was
  used as an RBAC securable throughout `workflow_routes.cpp` but was never seeded into
  `RbacStore`'s securable-types catalogue or its MCP mirror — meaning no role, including
  Administrator, could be granted `Workflow:Read` while RBAC was enabled. Seeded, with `Read`
  granted to Administrator (via the standard CRUD seed), PlatformEngineer, Operator,
  ITServiceOwner, and Viewer (the same footprint `Schedule:Read` already has). Applies
  automatically on upgrade — every existing RBAC-enabled deployment picks up these grants on
  its next restart, with no migration step and no opt-out; review your role assignments if
  you've already narrowed them for these four roles. Scoped to `Workflow` only — the identical
  `ProductPack`/`Directory` gap is fixed independently by #4029/#4031.
