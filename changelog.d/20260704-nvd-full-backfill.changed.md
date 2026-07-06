- **The NVD sync now builds the full CVE catalog (newest-first), not ~20 keywords.** The server-side
  NVD sync was keyword-scoped (~20 hardcoded products); it now backfills every CVE published within a
  configurable window — `--nvd-backfill-years` / `YUZU_NVD_BACKFILL_YEARS` (default **8 years**; `0` =
  full history) — **newest-first and resumable across restarts**, then settles into a periodic
  last-modified freshness re-check. Product matching is prefix-anchored so it stays index-fast at
  catalog scale. **Operator-visible:** `GET /api/nvd/status` `total_cves` grows substantially and the
  local NVD database reaches into the hundreds of MB; the initial backfill is NVD-rate-limited (hours
  without an `--nvd-api-key`, minutes with one) and resumes where it left off if interrupted. Set
  `--no-nvd-sync` to disable, `--nvd-proxy` for restricted egress. The mirror is never reported
  `backfill_complete` while it holds no real NVD CVEs (the built-in fallback rules don't count),
  so a vulnerability scan can't silently trust a mirror that never populated, and an
  out-of-band-emptied catalog self-heals by re-fetching. On a local write failure the
  mirror holds its cursor and stays incomplete (never dropping fetched CVEs), and a
  prolonged upstream outage is detected and surfaced on `GET /api/nvd/status`
  (`last_error`) rather than re-walking the full range every tick. An older window that
  returns empty *after* real data has landed (a stale cache/proxy serving an empty page
  for a populated range) is re-confirmed before it's trusted, so the backfill can't skip
  a populated range and falsely report complete; a genuinely-empty boundary window is
  still accepted so the walk terminates.
