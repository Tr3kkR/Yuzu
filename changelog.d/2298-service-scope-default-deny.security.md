- **Breaking — service-scoped API tokens are now denied fleet-wide access by default, not admitted
  by default.** `AuthRoutes::require_permission`'s service-scoped branch previously admitted any
  operation the `ITServiceOwner` role happened to grant — since that role holds broad CRUD across
  most securables, this meant a token bound to one IT service's agents could, in practice, reach
  fleet-wide data with no per-agent narrowing at all. A `(securable, operation)` pair must now
  *also* clear a server-side allow-list that ships **empty**, so every route not yet migrated to
  real per-request confinement denies a service-scoped token outright rather than admitting it
  unfiltered. This is a strictly larger blast radius than the confinement fixes in the prior
  release's Upgrade Notes: those closed an enumerated route list, this flips the *default* for
  every `require_permission`/`require_scoped_permission` route at once, including ones not yet
  found or named anywhere. Mirrored at the MCP `tools/call` dispatch layer via a new per-tool
  `ServiceScopeClass` classification. Every route that reached agent/fleet/execution/result data
  via no permission gate at all — including several found by a residual sweep beyond the
  originally-scoped list, and one distinct pre-existing CWE-862 missing-authorization bug on the
  same surface — now has an explicit deny. Any integration authenticating with a service-scoped
  token against a not-yet-allow-listed route starts receiving `403` on this upgrade — see the
  Upgrade Notes entry in `docs/user-manual/server-admin.md` for what to do. See
  `docs/adr/1006-service-scope-default-deny.md` for the full design and
  `docs/security-reviews/service-scope-flip-route-inventory-2026-08.md` for the closed route
  inventory. (guardian-confinement-2298 PR 3 — "the flip")
