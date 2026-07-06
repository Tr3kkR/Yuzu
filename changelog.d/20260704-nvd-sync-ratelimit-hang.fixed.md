- **Fixed the server-side NVD CVE sync hanging on its very first request.** `NvdClient::rate_limit()`
  used a `steady_clock::time_point::min()` sentinel for "no prior request"; on the first call
  `now - last_request_time_` overflowed `int64`, producing a garbage-negative elapsed time and a
  `sleep_for` of roughly **292 years**. The NVD sync therefore never issued its first HTTP request on
  any deployment — `/api/nvd/status` `total_cves` stayed at the built-in seed and the sync thread sat
  asleep indefinitely. The throttle now skips the wait when there is no prior request (and the timing
  logic is covered by a regression test). This was also the real reason the sync appeared to ignore
  its HTTP connection/read timeouts (there was no request in flight to time out) — see #1867.
