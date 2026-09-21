- **Registry-key and file Spark watches now report an establishment signal (#4340).** The Windows
  agent's Registry and File Spark mechanisms (Spark is the agent's event-driven change detection)
  now feed the existing `SparkEngine::subscription_establishment()` query, added for Service
  watches, with `established_at` (stamped once notification coverage is first confirmed) and
  `coverage` (`None` or `Notification`); the engine itself stamps `armed_at`. A registry watch's
  coverage drops to `None` briefly after each fire it consumes while the target key still exists,
  and stays `None` after the key is deleted; a file watch stays `Notification` across an ordinary
  fire. There is no operator-visible change: nothing in production reads the query yet, and no watch
  is armed through these mechanisms until Spark detection is turned on, which it is not in
  production agents, so guard detection and enforcement are unchanged.
