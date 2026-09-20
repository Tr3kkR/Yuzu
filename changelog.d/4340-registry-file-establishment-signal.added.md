- Windows agents only, no operator-visible change: the Registry and File spark mechanisms
  now feed the existing `SparkEngine::subscription_establishment()` query (added for
  Service): `armed_at`, a first-wins `established_at` (stamped once Target-mode
  notification coverage is confirmed), and `coverage` (`None`/`Notification`). Registry
  coverage transiently drops to `None` on each consumed Target-mode fire; File's stays
  `Notification` across an ordinary fire. No consumer reads the channel yet; guard
  detection and enforcement are unchanged.
