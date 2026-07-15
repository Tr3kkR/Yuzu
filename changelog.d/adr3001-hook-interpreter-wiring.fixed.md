- **Claude Code hooks now fire on Windows.** The `.claude/settings.json` hook
  commands invoked `python3`, which on Windows resolves to the Microsoft Store
  App-Execution-Alias stub — it exits nonzero and emits no output, so every
  hook failed open and was silently dead on Windows (the changelog-fragment
  guard and the dialyzer reminder both). The wiring now resolves a real
  interpreter across platforms (`py -3` where the Windows launcher exists,
  `python3` otherwise). A local self-check
  (`scripts/hooks/selfcheck-issue-guard.py`) proves the hook fires through the
  actual wiring — the class of failure CI, being Linux-only, cannot see.
