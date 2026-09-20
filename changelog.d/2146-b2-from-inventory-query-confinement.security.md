- **Security fix: `create_result_set_from_inventory_query` (MCP) and `POST /api/v1/result-sets/from-inventory-query` (REST) now confine matches to the caller's visible agents (#2146).**
  Both surfaces gated on a bare `Inventory:Read` permission check and evaluated the query
  against every agent's inventory records fleet-wide, with no per-device scoping - a
  management-group-confined caller holding a real but narrower `Inventory:Read` grant could
  enumerate device-identity plus inventory-attribute correlation for devices outside their
  visible set. Fixed to gate via the admit-then-filter `fleet_read_fn`/`fleet_read_fn_`
  chokepoint and narrow the candidate records to the caller's admitted scope before
  evaluation, matching `GET /api/v1/inventory/software` and this same PR's
  `preview_scope_targets`/scope-preview fix. Also fixes an uncaught `nlohmann::json::type_error`
  on both surfaces when a `conditions` array element is not an object or a field carries the
  wrong JSON type - previously an unhandled exception (bare empty-body 500), now a clean 400 /
  `kInvalidParams` response.
