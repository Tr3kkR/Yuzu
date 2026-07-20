- **`__guardian_journal__` is now a reserved plugin name.** The Guardian lifecycle
  journal's `kv_store` namespace was not in the reserved set, and plugin storage is
  keyed by a plugin's own declared name on the same `kv_store` connection the journal
  borrows. A native plugin declaring that name could therefore read, delete, or forge
  the arm/disarm records the journal later replays over the authenticated stream. Not a
  sandbox escape (native plugins are trusted), but an audit-evidence-integrity gap: such
  a plugin is now rejected at load with the standard `reserved plugin name` reason. A
  compile-time assertion pins the reserved-name list against the journal's namespace
  constant so the two cannot drift apart.
