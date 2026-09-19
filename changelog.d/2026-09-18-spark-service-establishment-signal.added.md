- **Service Spark watches now report a positive establishment signal.** Arming a
  systemd-unit or Windows-service watch previously told the caller only that the
  request was *accepted*, not that live OS-level notification coverage (a real
  `PropertiesChanged` match on Linux, a real `NotifyServiceStatusChangeW`
  registration on Windows) actually exists yet. `SparkEngine::subscription_establishment(id)`
  is a new pull query returning when the subscription was armed, whether it has
  ever been confirmed established, and its current tri-state coverage
  (none / notification / poll-fallback) — a third, independent fact alongside the
  existing accepted/resolved timestamps, not a redefinition of either. Additive:
  every other mechanism (Registry, File) and every existing consumer is
  unaffected. Registry/File get the same signal in a tracked follow-up (#4340).
