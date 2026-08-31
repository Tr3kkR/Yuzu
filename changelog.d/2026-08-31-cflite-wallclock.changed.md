- **ClusterFuzzLite CI reworked for wallclock and signal.** The PR fuzzing job now
  triggers only on the fuzzed compile closure (six parser families under
  `server/core/src/`, `tests/fuzz/`, `.clusterfuzzlite/`) instead of all of
  `server/`/`agents/`/`sdk/`/`proto/`, and its build step is wired with the token
  and `actions: read` permission that corpus download and affected-target pruning
  silently required. A new `cflite-batch.yml` workflow (push-to-dev on the same
  paths, plus manual dispatch and a weekly cron for when it reaches `main`) grows a
  persistent corpus in batch mode, publishes the coverage report the PR job prunes
  against, and prunes the corpus on a slower cadence.
