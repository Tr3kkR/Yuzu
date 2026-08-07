- Audit retention is now a floor, not a ceiling. Expired rows
  age out at up to 25,000 per pass instead of all at once, so a large backlog
  clears in bounded steps rather than in a single statement. That cap implies
  a quiet-operation ceiling of roughly 6.9 audit events/second (25,000 rows per
  hourly pass) — but a genuine backlog re-arms the sweep every 5 seconds instead
  of hourly until it clears, raising the effective ceiling to roughly 5,000/second;
  see `docs/user-manual/audit-log.md` § Capacity for both figures.
  `yuzu_server_audit_retention_cap_reached_total` rising means backlog-recovery
  mode engaged, not that the backlog will never clear.
  (Reducing `--audit-retention-days` never expired existing rows in the first place
  -- `ttl_expires_at` is stamped at INSERT and is never rewritten -- so a reduction
  still does not reclaim disk retroactively.)
