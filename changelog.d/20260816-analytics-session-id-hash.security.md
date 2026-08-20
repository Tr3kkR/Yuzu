- **`AnalyticsEventStore` no longer stores the raw session cookie.** `AnalyticsEvent.session_id`
  is now `AuthManager::sha256_hex(session_cookie)` rather than the live bearer token verbatim.
  On Postgres (ADR-0049), analytics rows are retained indefinitely and readable by any
  `Infrastructure:Read` holder via `/api/analytics/recent` (and forwarded to any configured
  JSONL/ClickHouse sink), so the raw cookie was a durable, widely-readable session-hijack vector —
  including hijacking an elevated admin's session via `role.elevation.granted` events. The hash is
  still a same-session correlator (same cookie → same hash); it is no longer a redeemable
  credential. Rows recorded before this fix, including any already drained to a sink, still carry
  the raw value — rotate any session whose token may have reached a shared sink or a broadly-read
  analytics row before this change. `AuditStore`'s `session_id` field has the identical
  raw-cookie pattern (a separate, already-migrated store) and is not fixed here — tracked as a
  follow-up (ADR-0049 §Secrets).
