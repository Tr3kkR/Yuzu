- **`InstructionStore` migrated from SQLite to PostgreSQL** (schema `instruction_store`,
  ADR-0058). No legacy-SQLite backfill (ADR-0009's fresh-start-by-default class): the
  pre-migration `instructions.db` is never read; the bundled catalog reseeds fresh on first
  boot and operator-authored content must be re-created via the normal API. `create_definition`/
  `update_definition`/`create_set`/`import_definition_json`/`import_definition_json_trusted`/
  `query_definitions`/`get_definition`/`list_sets`/`delete_definition`/`delete_set`/
  `export_definition_json` are all typed `std::expected`, so a genuine database or lease
  failure 503s distinctly from a validation (400) or not-found (404) result — REST callers
  across `rest_api_v1.cpp`, `server.cpp`, `workflow_routes.cpp`, `compliance_routes.cpp`,
  `schedule_runner.cpp`, and `mcp_server.cpp` were updated accordingly (see
  `docs/user-manual/rest-api.md` for the full per-route response table).
- **Breaking, deliberate: deleting a definition or set no longer resurrects on the next boot.**
  Every replica independently reseeds `kBundledDefinitions`/`kBundledSets` on every boot; the
  pre-migration SQLite behaviour treated an operator-deleted bundled id as indistinguishable
  from a never-seeded one, silently re-inserting the original bundled content. A new
  `deleted_seed_content(kind, id)` tombstone now suppresses that reseed permanently — an
  operator can still freely (re)create content under any id, including a previously-deleted
  bundled one, via the ordinary create path. `DELETE /api/instructions/{id}` and
  `DELETE /api/instruction-sets/{id}` also change from `200 {"deleted": false}` to `404` on an
  unknown id (`PUT /api/instructions/{id}` gains the same 404 case). See
  `docs/user-manual/upgrading.md` for the full behaviour-change note and recovery path.
