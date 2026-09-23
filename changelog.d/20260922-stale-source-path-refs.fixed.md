- **Corrected stale source-path references across the docs and agent instructions.** Ten cited
  paths named files that no longer exist or had moved: `cert_store.cpp` and `sdk_utilities`
  (agent "Key Files" lists pointed at `server/core/src/` and `sdk/src/` rather than their real
  homes), `rbac.cpp` / `session_manager.cpp` / `metrics.cpp` (renamed or header-only, so the cited
  files never existed on `dev`), the auth test-pattern references (pre-Postgres paths), the
  gateway Python harness (`scripts/`, not `gateway/`), the Chrome-IR chain fixture
  (`tests/unit/server/`, not `tests/integration/`, and it now exists rather than being aspirational),
  and `sdk/README.md`'s `include/yuzu/sdk.hpp` row — a header the SDK has never shipped, now
  replaced by the helper headers it actually exposes through `yuzu_sdk_dep`.
