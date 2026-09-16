- **ClusterFuzzLite PR job gates affected-target pruning on coverage age.** A
  `cifuzz-coverage-latest` artifact older than 30 days is now treated as too
  stale to trust for pruning — the job falls back to fuzzing every target
  instead of a possibly-outdated affected subset, logging which branch it
  took. Closes the one below-status-quo hazard accepted when PR-side pruning
  went live: a stale-but-unexpired coverage map could actively prune a
  target the PR had actually changed.
