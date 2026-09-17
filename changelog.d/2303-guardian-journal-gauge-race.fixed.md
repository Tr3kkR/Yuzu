- **The Guardian journal's write-ceiling gauges no longer lose a concurrent write to a
  pruning pass.** The gauges that bound the shared `kv_store.db` were updated by retention
  with an absolute store, which could silently overwrite an increment from a write happening
  on another thread. The ceiling would then under-count and let the journal grow past its
  hard cap, at which point writes fail and the bounded in-memory staging can drop the oldest
  records. The gauges are now maintained as running counters updated only with atomic
  read-modify-write operations (a retention pass rebases to the on-disk size it observed and
  subtracts exactly what it removes), so a concurrent write is never lost. They are also now
  signed internally so a conservative fail-closed startup seed is walked back down to reality
  by the next successful retention pass rather than pinning writes off permanently.
