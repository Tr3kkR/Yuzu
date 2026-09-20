- **Registry and File spark mechanisms report a positive establishment signal (#4340).**
  `SparkEngine::subscription_establishment()` (added for the Service mechanism, rung 9c
  PR-6 item 1) now also answers for Registry and File watches: `armed_at`, a first-wins
  `established_at` (stamped once live OS-level notification coverage is confirmed, never
  re-stamped by a later re-arm or recovery), and the mechanism's current `SparkCoverage`
  tri-state (`None`/`Notification`). Registry's `RegNotifyChangeKeyValue` is one-shot, so
  its coverage genuinely flaps `Notification -> None -> Notification` on every consumed
  fire; File's `ReadDirectoryChangesW` reissue is synchronous, so its coverage stays
  `Notification` across an ordinary fire and only drops on a genuine backend failure or
  teardown. No production consumer reads this channel yet for either mechanism (additive
  observability only).
