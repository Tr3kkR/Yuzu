- **Three agent-internal `kv_store` namespaces are now reserved plugin names.**
  `__guardian__` (GuardianEngine rule state), `__guardian_journal__` (the Guardian
  lifecycle audit journal), and `__sync__` (daily-sync scheduler state) were not in
  the reserved set, and plugin storage is keyed by a plugin's own declared name on
  the same `kv_store` connection these subsystems use. A native plugin declaring one
  of those names could therefore read, delete, or forge the state the subsystem loads
  as authoritative - including forging the Guardian policy rules the engine enforces
  at boot, or the arm/disarm records the journal replays over the authenticated
  stream. Not a sandbox escape (native plugins are trusted; the plugin ABI has no
  isolation), but an audit-integrity gap: such a plugin is now rejected at load with
  the standard `reserved plugin name` reason. A compile-time assertion pins each
  reserved name against its source namespace constant so the two cannot drift apart.
