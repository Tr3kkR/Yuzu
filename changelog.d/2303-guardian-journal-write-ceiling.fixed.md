- **The Guardian lifecycle journal's write ceiling no longer forgets the journal already
  on disk.** Its size gauges were only ever reconstructed by a successful retention pass,
  so every process start opened a window in which the hard write ceiling read zero and
  an agent crash-looping over a full journal could grow the shared `kv_store.db` past
  that ceiling, taking unrelated plugins' storage with it. The gauges are now seeded at
  construction from a new aggregate `KvStore` size probe (which reads the size without
  materialising any values). If the journal cannot be sized at all, the journal fails
  closed and assumes it is at the ceiling, staging records in memory and counting the
  refusals, rather than assuming an unreadable journal is empty.

- **A failed retention scan no longer lets the Guardian journal replay unpruned records.**
  The prune-before-replay barrier declined to latch when its scan failed, but the same
  pass fell through and replayed anyway, handing out exactly the over-retention records a
  successful prune would have evicted. That pass now replays nothing and retries on the
  next one.
