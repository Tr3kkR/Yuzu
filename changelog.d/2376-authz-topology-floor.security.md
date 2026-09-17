- **Breaking — authorization-topology reads now require admin even when RBAC is disabled, and the
  engine-principal reads moved to a new `EnginePrincipal:Read` securable (#2376).** RBAC ships
  **disabled** by default, and with it disabled the legacy permission fallback allowed *every*
  `Read` to any authenticated non-engine session — so on a default install a plain `user` could read
  the authorization topology itself: the fleet-wide access-review export (which exists to be SOC 2
  CC6.2 evidence), `GET /api/v1/rbac/roles`, and the engine-principal grant graph.
  `{AccessReview:Read, UserManagement:Read, EnginePrincipal:Read}` now require an `admin` effective
  role whenever that legacy branch is in effect, enforced at one chokepoint
  (`authz_topology_floor.hpp`). The floor engages **only** inside the legacy fallback, so it never
  overrides a live RBAC grant — a non-admin holding the seeded `Reviewer` role's `AccessReview:Read`
  is unaffected — and it is deliberately not configurable. Separately, the engine-principal
  inventory and grant-graph reads (`GET /api/v1/engine-principals`, `.../{id}`, `.../{id}/roles`,
  and the MCP twins `list_engine_principals`/`get_engine_principal`/`list_engine_roles`) moved off
  the over-broad `Security:Read` onto the narrower `EnginePrincipal:Read` — the same cut #2324 made
  taking `AccessReview` away from `AuditLog:*`. `Security:Read` also gates unrelated operational
  reads (quarantine visibility, CA issued-certs, `/ca/root-csr`, KEK status), which this change
  deliberately does **not** floor. **Two upgrade paths:** on an RBAC-**off** install that relied on a
  non-admin reaching any of the three floored reads, either accept the admin-only floor or enable
  RBAC and grant the matching role; on an RBAC-**on** deployment, any **custom** role granted
  `Security:Read` specifically to reach the engine-principal routes must now also be granted
  `EnginePrincipal:Read` — the built-in `Administrator` and `Viewer` roles pick the new securable up
  automatically on next boot via the existing idempotent `seed_defaults()` re-seed, so no schema
  migration is involved, but custom roles are not auto-updated. Floored denials carry a distinct
  audit reason (`"topology floor: …"` on `auth.permission_required` /
  `auth.scoped_permission_required`) and increment the new
  `yuzu_auth_topology_floor_denied_total{permission}`. **`GET /api/v1/discover/permissions` and the MCP `discover_permissions` twin
  are split by the same rule:** the `securable_types`/`operations` taxonomy still needs only the
  route's `Infrastructure:Read`, but the `roles[].permissions[]` grid now additionally requires
  `UserManagement:Read`. Without it the route still returns `200` and the full taxonomy, with the
  grid replaced by `"roles_omitted": true` and a reason — the omission is declared, never silent, so
  a caller cannot mistake it for "the fleet has no RBAC roles". This closed a bypass: that grid is
  strictly more than `/api/v1/rbac/roles` discloses, and `Infrastructure:Read` is held by every
  authenticated session on an RBAC-off install, so the floor was reachable around.
  See
  `docs/security-reviews/authz-topology-floor-2026-08-05.md` for the recorded decision and
  `docs/user-manual/server-admin.md` "Upgrade Notes" for the remediation steps. **`GET /api/v1/management-groups/{id}/roles` now additionally requires `UserManagement:Read`:** its whole body is the scoped principal→role assignment graph, and `ManagementGroup:Read` alone is not floored, so on an RBAC-off install any authenticated session could enumerate every scoped role assignment. There is no non-topology half here, so this is a second required permission rather than a split — satisfied by `UserManagement:Read` **or** by being an `ITServiceOwner` of that group, the same group-scoped-admin fallback the POST/DELETE handlers on that path already use.
