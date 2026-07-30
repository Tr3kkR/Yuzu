- **Plugin ABI 4: per-action OS capability declarations + a typed plugin→host result status.**
  `YuzuPluginDescriptor` gains an append-only `action_descriptors` array — each entry
  declares an action's per-OS support (`supported`/`constrained`/`planned`/`unsupported`),
  implementation rung, mechanism, and optional fallback note — with the ABI bumped to 4
  (minimum still 1; an ABI3 plugin's int-only `execute()` keeps working unchanged, proven
  against a real frozen-layout fixture, not just a recompiled stand-in). Plugins can now also
  report a typed runtime result (ok/unavailable/permission-denied/constrained, plus
  completeness and provenance) via a new `yuzu_ctx_set_result_status()` callback instead of
  the bare int return code; the status flows through to `CommandResponse` and is persisted
  alongside each response and execution record. A new `tools/capmatrix-gen` host tool plus a
  CI drift gate (ratchet mode) keep `docs/os-capability-matrix.md`'s generated section honest
  against what actually built. The TAR plugin's `OsSupportStatus` is now pinned 1:1 to the new
  descriptor enum as the single source of truth for its `compatibility` action.
