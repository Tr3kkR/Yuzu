- **Periodic access reviews (SOC 2 CC6.2).** A fleet-wide access-review capability
  across all three RBAC principal types — user, group, and engine. `GET
  /api/v1/access-reviews/export?format=json|csv` returns every principal with a
  **current live grant** (grant-table-driven, not a roster walk — a principal with
  zero grants is out of scope, and a grant belonging to a principal outside every
  roster is surfaced as `source="orphan"` rather than silently dropped): roles,
  effective permission count, last activity, classification, lifecycle state,
  provenance. CSV exports neutralize spreadsheet formula injection (CWE-1236).
  `GET /api/v1/access-reviews` lists every past campaign, newest-first, capped at
  500. Both are gated `AuditLog:Read` and self-audited (`access_review.exported`/
  `.list`) — fail-loud (`503`) on any partial read, never a silent incomplete
  export. `POST /api/v1/access-reviews` opens a durable attestation campaign that
  freezes the complete current grant population as reviewable rows in one
  transaction, so every grant that existed at open time is provably reviewable;
  reviewers record `attested`/`flagged_revoke` decisions via `POST
  /api/v1/access-reviews/{id}/attestations` (an UPSERT — overwrites a prior
  decision) and close the campaign via `POST /api/v1/access-reviews/{id}/close`
  (`GET /api/v1/access-reviews/{id}` for the full evidentiary state) — all gated
  `AuditLog:Attest` except the reads. Every route, reads included, structurally
  denies a caller whose own session is engine-classed. **`flagged_revoke` records
  evidence only and never itself revokes the grant** — acting on a flag is a
  separate, explicit operator action. MCP twins: `export_access_review`,
  `open_access_review`, `record_attestation` (`destructiveHint:true` — it
  overwrites a prior decision), `get_access_review`, `list_access_reviews`,
  `close_access_review` (JSON only; CSV stays REST-only). New `AuditLog:Attest`
  RBAC operation and a seeded `Reviewer` role (`AuditLog:Read` + `AuditLog:Attest`
  only) support separation-of-duties review without granting full admin.
  Persisted in a new born-on-Postgres `AccessReviewStore` (fail-closed
  construction, no prune — the evidence persists indefinitely). Four new
  Prometheus metrics: `yuzu_access_review_export_total{format}`,
  `_export_duration_seconds`, `_campaigns_opened_total`,
  `_attestations_total{decision}`. Export/campaign-open/campaign-list are
  deliberately gated on a **global** `AuditLog:Read`/`AuditLog:Attest` rather than
  the management-group-confined list-read chokepoint — a scoped slice of the
  grant population would be useless as fleet-wide CC6.2 evidence.
