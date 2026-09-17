- **The retired `tar_events` table is no longer recreated on every agent restart.** Schema v3
  dropped it, but `kCreateSchema` still created the table and its three indexes on *every* open
  while the drop was gated on `schema_version == 2` — so once a database reached v3, each reopen
  resurrected all four objects with nothing left to remove them. `is_queryable_table()` excludes
  `tar_events` precisely so its "no such table" error cannot become an existence oracle (#760
  UP-8), and that reasoning holds only while the table is genuinely absent. Nothing has written to
  `tar_events` since v3 retired it, so a resurrected copy is always empty: this clears a stray
  empty table, not data. The DDL is removed, and the table and its indexes are now dropped wherever
  they are still found — gated on presence rather than on a version number, so rolling an agent
  back to an older binary and forward again cannot strand them. Schema version bumps to 5. (#2093)
