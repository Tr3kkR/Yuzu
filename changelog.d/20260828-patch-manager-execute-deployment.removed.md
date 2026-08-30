- **`PatchManager::execute_deployment()`** (reboot-orchestration workflow: scan → install → verify
  → reboot) and its `PatchDispatchFn`/`AgentOsLookupFn` callback types are removed. It had zero
  production callers on `dev` — nothing ever wired a dispatch callback to it — so this is a
  deliberate feature de-scope, not a behavior change for any real deployment; see ADR-0062 and
  #3669 for the tested-but-unwired functionality this removes.
