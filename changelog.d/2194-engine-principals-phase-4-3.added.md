- **Engine-principal lifecycle surface — REST, MCP, and admin console (engine principals
  PR 4.3).** Nine `/api/v1/engine-principals` REST routes (create, list, get, revoke,
  mint-credential, rotate-credential, confirm-rotation, transfer-owner, and the `audit/no-admin`
  auditor) and nine MCP twin tools
  give operators (and, for the mutating tools, supervised-tier maker-checker-approved automation)
  full lifecycle control over the engine-principal identities introduced in PR 4.1–4.2, plus a new
  "Engine Principals" section in the Settings console (create form, list with owner/classification/
  active-credential count, mint/rotate buttons behind a one-time secret-reveal panel, revoked rows
  showing `superseded_by` and the recorded revoke detail). Credential rotation follows an
  overlap-pair model (design doc §7): at most two active credentials per principal, a 24-hour
  minimum overlap window (rejected outright, never truncated, below the floor), a ~120-second
  grace window that re-serves the same successor secret on a same-caller retry, and a 60-second
  background sweep that auto-revokes the predecessor once its overlap window elapses and warns on
  an unused successor nearing expiry. A new `GET /api/v1/engine-principals/audit/no-admin`
  auditor (REST + MCP `audit_engine_no_admin`) independently proves, by resolving each engine
  principal's actual roles and effective permissions against the RBAC reference tables, that "no
  admin, ever" holds — literal admin/system-role grants and a full securable×operation wildcard
  grant are both checked, and the auditor fails closed (`503`, "cannot verify") rather than
  reporting a false clean bill if RBAC reference data can't be resolved. Every mutating REST route
  is admin + MFA-step-up gated; every REST route, including the read routes, structurally denies a
  caller authenticated as an engine-classed session (`principal_kind="engine"` /
  `auth_source="engine_token"`) — an engine principal can never touch its own or any other engine
  principal's lifecycle surface, not even to list. Deleting a user (dashboard) who owns an active
  engine principal is now blocked with `409` until ownership is transferred; the automated SCIM
  deprovision path instead applies a detective control — it always succeeds (a CC6.8 termination is
  never blocked) but emits an `engine_principal.owner_deprovisioned` audit and a
  `yuzu_engine_principal_owner_deprovisioned_total` metric when the departing user still owns active
  engine principals, for out-of-band reassignment.
