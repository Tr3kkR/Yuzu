- **The NVD sync is more resilient under rate-limiting, and sync failures are now observable.** On
  HTTP 429 the server-side NVD sync now backs off (honouring a `Retry-After` header, else exponential
  to a 30-minute cap) and retries the same page instead of failing the window and re-hammering NVD
  every tick; an HTTP 403 (bad/revoked API key) is logged distinctly and not retried. A new
  `yuzu_nvd_sync_failures_total` counter (labelled by `reason`: connection / http_429 / http_403 /
  http_other / parse) exposes sync failures. Shutdown now aborts a long backfill/freshness pass
  promptly — between pages, and during the rate-limit/backoff sleeps — instead of blocking on the
  in-flight wait. Internal: the per-CVE upsert prepares its statements once per batch (backfill
  speedup) and de-duplicates records sharing a CVE id. No config change or action required.
