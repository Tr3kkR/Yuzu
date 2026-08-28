- **`PatchManager` (OS-patch inventory + deployment tracking, `/api/patches/*`) now runs on the
  PostgreSQL substrate** (schema `patch_manager`) instead of its own `patches.db` SQLite file.
  Construction is now fail-closed — the server refuses to start if the schema can't be
  created/opened, instead of silently serving a store nothing ever health-checked. No data is
  carried over from a pre-Postgres install (fresh-start-by-default, ADR-0009); patch inventory is
  agent-reported and self-heals on the next scan, and any in-flight deployment must be
  re-created via `POST /api/patches/deploy` after upgrading. `patch_manager` is now reported by
  both `/readyz` and `/healthz`. See ADR-0062.
- **Removed:** `PatchManager::execute_deployment()` (reboot-orchestration workflow: scan → install
  → verify → reboot) and its `PatchDispatchFn`/`AgentOsLookupFn` callback types. It had zero
  production callers on `dev` — nothing ever wired a dispatch callback to it — so this is a
  deliberate feature de-scope, not a behavior change for any real deployment; see ADR-0062 and
  #3669 for the tested-but-unwired functionality this removes.
