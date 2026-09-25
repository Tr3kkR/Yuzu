- **Agent logging is now asynchronous, with a new self-exit code 5 (#4666).** The agent no longer
  writes log lines on the thread that produced them; a dedicated worker thread now drains a
  bounded, fixed-size queue instead, so a stalled log destination (a full disk, a stuck pipe under
  a container's log driver) can no longer stall the agent itself. Under sustained overload the
  queue drops the oldest still-queued lines rather than blocking or growing. Agent shutdown gains
  one more possible self-exit code, `5`, distinct from the existing `1`/`3`/`4`, if tearing down
  the logger does not complete within its own short internal deadline. Not a breaking change: same
  log format, same `--log-file`/rotation behaviour, no new flags. Operators with a supervisor
  script or alert keyed to a fixed agent exit-code set should widen it to include `5`. See
  "Stopping a wedged agent" in `docs/user-manual/server-admin.md`.
