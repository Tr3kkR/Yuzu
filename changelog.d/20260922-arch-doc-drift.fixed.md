- **Architecture and convention docs reconciled with the code.** `docs/architecture.md`'s storage
  table still described server responses, audit, identity/auth and policy state as SQLite "pending"
  a Postgres migration that completed in 2026-08; all four now hold a `pg::PgPool&`, and NVD/CVE is
  called out as the one server store deliberately still on SQLite. Also corrected: the MCP
  `ExecuteGate` approval-row count (~42 → ~50) and Destructive-row count (17 → 20);
  `docs/authz-model.md`'s stale securable ordinals (34th/35th → 37th/38th, 33→35 → 36→38); the CI
  Meson pin in two places (1.11.1 → 1.12.0, matching `requirements-ci.txt`);
  `docs/capability-map.md`'s own reproduction command output, which no longer matched what the
  command prints; a Pattern-B generated file listed as a Pattern-A hand-written TU in
  `docs/cpp-conventions.md`; and `docs/test-coverage.md`, which listed the SSE `EventBus` as
  untested five months after `tests/unit/server/test_execution_event_bus.cpp` landed.
