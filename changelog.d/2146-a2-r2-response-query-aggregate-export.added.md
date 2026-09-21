- **REST v1 twins for the command/instruction-ID-keyed Responses API (#2146 A2-R2).** `GET
  /api/v1/responses/{id}`, `GET /api/v1/responses/{id}/aggregate`, and `GET
  /api/v1/responses/{id}/export` bring the legacy, unversioned `GET /api/responses/{id}*` family
  to REST+MCP parity - same `Response:Read` fleet-read confinement (resolve-then-scope,
  ADR-0017 INV-3) and query semantics as the legacy routes (unmodified, frozen reference code for
  this PR). Distinct from the pre-existing, execution-ID-keyed `GET /api/v1/executions/{id}/responses`.
  `GET /api/v1/responses/{id}` and MCP `query_responses` share one JSON row builder
  (`response_query_row_json`); `GET /api/v1/responses/{id}/aggregate` and MCP `aggregate_responses`
  share another (`response_aggregate_row_json`) - both new, in `response_query_model.{hpp,cpp}`,
  per `docs/api-twin-recipe.md` Rule 1.
- **`query_responses` rows now carry `id`, `instruction_id`, `error_detail`, `plugin`, and
  `received_at_ms`**, alongside the pre-existing `agent_id`/`execution_id`/`status`/`output`/
  `timestamp` - all were already present on `StoredResponse` but never surfaced to an MCP caller.
- **`aggregate_responses` gained an `op_column` parameter** (`timestamp`/`status`/`id`, default
  `id`), validated against `ResponseStore::allowed_op_column()`. Previously `op_column` was never
  read from the tool's arguments at all, so a `sum`/`avg`/`min`/`max` aggregate silently operated
  on the store's own default operand column regardless of what a caller requested. A
  present-but-wrong-JSON-type `op_column` (e.g. a number) is rejected with `kInvalidParams`
  rather than silently read as absent and defaulted to `id` (same defect class as #2970B/#2146
  A2-R1's `param_int_strict`/`param_bool_strict`/`param_string_strict` family). The pre-existing
  `aggregate` parameter had the identical wrong-type gap (a number/array/object/boolean silently
  became `count`) - tracked and fixed the same way in this PR rather than deferred (#4643). A
  well-typed but unrecognized `aggregate` string (e.g. `"bogus"`) still falls through to `count`
  unchanged, matching the legacy route's own behavior - that separate, narrower enum-validation
  gap is pre-existing, untracked, and deliberately out of scope for this fix.
- `GET /api/v1/responses/{id}` and `GET /api/v1/responses/{id}/export` clamp a caller-supplied
  `limit` on **both** bounds (`[1,1000]` and `[1,10000]` respectively) - the legacy `GET
  /api/responses/{id}/export` route only floors its own *default* at 10000; an explicit
  `?limit=` there has no ceiling at all and can attempt an unbounded fetch. That pre-existing
  legacy-route bug is deliberately NOT fixed by this PR (the legacy handlers are frozen reference
  code here) and is not propagated to the new v1/MCP surfaces; tracked separately as #4310 (broadened
  to also cover the plain legacy query route, which shares the same unbounded-limit shape).
- **`data_export::csv_escape` now neutralizes CSV/formula injection (CWE-1236, #4311)** - a leading
  `=`/`+`/`-`/`@`/tab/CR on an agent-controlled field (`output`, `error_detail`, `plugin`) is
  prefixed with a literal `'` before RFC 4180 quoting, so Excel/Sheets renders it as text instead of
  executing it as a formula. Promoted from `access_review_model.cpp`'s existing, tested
  `neutralize_formula`/`is_formula_trigger` (the original precedent for this fix) into the shared
  `data_export.hpp` chokepoint - fixes the new v1 export route, the legacy `GET
  /api/responses/{id}/export` route, `access_review_model.cpp`'s own compliance export, and
  `data_export::json_array_to_csv`'s dashboard-driven generic export all at once, and removes the
  access-review file's local duplicate of the same logic.
