- Audit retention is now a floor, not a ceiling. Expired rows
  age out at up to 25,000 per hourly pass instead of all at once, so a large backlog
  clears over hours rather than in a single statement. That fixed drain rate implies
  a sustained ceiling of roughly 6.9 audit events/second; above it the backlog never
  clears, which is what `yuzu_server_audit_retention_cap_reached_total` reports.
  (Reducing `--audit-retention-days` never expired existing rows in the first place
  -- `ttl_expires_at` is stamped at INSERT and is never rewritten -- so a reduction
  still does not reclaim disk retroactively.)
