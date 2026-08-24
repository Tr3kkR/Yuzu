- **`POST /api/product-packs` now honors an optional `Idempotency-Key` header** (max 200
  characters). A retried request carrying the same key and a byte-identical `yaml_bundle` returns
  the original pack id without re-running install delegation against any sibling store — this is
  what stops a client retry from compounding orphaned content under a retry storm. The same key
  reused with a different body is rejected as a `400`. The key is global, not scoped per caller.
  Omitting the header preserves prior behavior exactly: every call mints a fresh pack id with no
  dedup.
