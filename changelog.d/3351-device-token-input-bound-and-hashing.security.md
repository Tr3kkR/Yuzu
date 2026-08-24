- **`DeviceTokenStore` hardening ahead of activation (#3351).** `create_token` and the legacy
  SQLite backfill now reject any free-text field over 256 bytes instead of accepting it
  unbounded; `sanitize_pg_text`'s NUL-scrubbing pass is now linear time (was quadratic on a
  NUL-dense field); the backfill's legacy-field read no longer silently truncates at an embedded
  NUL. `hash_token`'s Windows-only BCrypt path — four unchecked calls that fell through to a
  constant all-zero hash on any failure — is replaced by the store's existing checked SHA-256
  path on every platform (output bytes are unchanged, so no existing hash is invalidated).
  `DeviceTokenStore` remains dormant — not yet constructed in production — so this closes an
  activation gate ahead of a future wiring change rather than fixing a live issue.
