- **`ResultSetStore` (scope-walking result sets) migrated from SQLite to PostgreSQL**
  (schema `result_set_store`, ADR-0036), with a one-time first-boot backfill of the
  legacy `result_sets.db`. Authorization/targeting-relevant reads (`get`, `contains`,
  `resolve_alias`, `member_set_owned`, and `AgentRegistry::evaluate_scope`) now
  type-distinguish a database error from "not found"/"no match", so a transient
  database blip during a `from_result_set:` scope resolution now fails a dispatch
  closed (**HTTP 503**) instead of the previous silent empty/degraded result — a
  scope combining `NOT` with a `from_result_set:` reference can no longer be
  silently expanded to the entire fleet by a database hiccup or a missing operator
  identity. Every such abort is now audited (`scope.evaluation_aborted`) and counted
  (`yuzu_scope_eval_degraded_total{reason}`).
