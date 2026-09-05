- `confined_fs` now supplies each entry's modification time to a caller's match
  predicate, so a consumer can express a minimum-age policy without re-opening
  the entry by path.
