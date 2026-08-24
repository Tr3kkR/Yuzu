- **Dashboard facet surfaces confined to the caller's management-group scope (#1712, #3489, ADR-0017).**
  Three dashboard surfaces read the fleet-wide `response_facets` index on a flat permission gate
  with no per-agent confinement: `GET /fragments/results/filter-bar` populated facet dropdowns
  (values and line counts) from every agent's responses, `GET /fragments/create-group-form`
  rendered a fleet-wide matching-agent count, and `POST /api/dashboard/group-from-results`
  materialised out-of-scope agents into a new management group the confined operator then owned.
  All three now resolve the caller's session and confine reads to the caller's
  `Response:Read`-visible agent set: aggregates are scoped in SQL before aggregation
  (ADR-0017 INV-3, `docs/adr/0017-management-group-confinement-list-reads.md`), the
  group-materialisation id list is intersected against the scope with a `denied` audit row
  recording the drop count, and an all-dropped result falls into the existing "no agents match"
  response (no scope oracle). A degraded management-group store fails closed (empty visible
  set), kept distinct from a degraded response store (unchanged 503 / "unavailable" rendering).
  A partial membership-materialisation failure (some `add_member` calls failing) is now reported
  honestly with a `failure` audit row and an error response instead of claiming full success.
  Ships without an API version bump under the security carve-out in
  `docs/api-versioning-policy.md` (minimal tightening closing the cited vulnerability;
  supersedes the read-only framing of #3489).
