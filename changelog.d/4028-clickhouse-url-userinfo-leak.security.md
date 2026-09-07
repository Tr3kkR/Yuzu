- **Settings analytics view no longer leaks ClickHouse URL credentials.** The Settings →
  Analytics dashboard fragment (and its new `GET /api/v1/settings/analytics` REST twin) rendered
  the configured ClickHouse URL verbatim, masking only the separate `clickhouse_password` field —
  a URL carrying embedded userinfo credentials (`clickhouse://user:pass@host:9000/db`) leaked the
  credential regardless of that masking. The URL is now stripped of embedded userinfo before
  either surface renders it for the common shapes (a bare `user@`/`user:pass@` authority, a
  password containing an unescaped `@`, `/`, or `?`, and a query-string credential form
  `?user=...&password=...`), and the raw password is never read into a response at all (only
  whether it is set). Fix-round hardening (governance Gate 2-8, two rounds) rewrote the sanitizer
  twice: a boundary-first approach with a "does this look like a host" heuristic proved unfixable
  (a digit-only password segment before a `/` is lexically identical to a real `host:port`, so no
  heuristic patch could tell them apart) and was replaced with a simpler rule — the LAST `@`
  anywhere in the URL ends userinfo, and any query string or fragment is dropped afterward. This
  deliberately over-strips a URL whose path also happens to contain a literal `@` (e.g.
  `.../db@table` now becomes `.../table`).
  **Known residual gap, NOT closed by this change (governance ledger
  `governance.d/4028-settings-read-twins.BAbeot.jsonl`, findings
  `g8b-sanitizer-scheme-boundary` and the query-vs-userinfo ordering finding, both `open`):** a
  schemeless URL whose query string itself contains a nested `://` can fool scheme-boundary
  detection into skipping the strip entirely, and a query string that itself contains an `@` can
  cause the query-strip to run against the wrong (already-mutated) string and leave a password
  fragment exposed. Two independent governance reviewers found these; the fix (very likely
  requires computing both cut points against the ORIGINAL string and unioning them, rather than
  sequential string mutation) was not applied this session — the fix-round cap was reached after
  two full redesigns of this function each surfaced new bypasses, and a third rushed patch was
  judged higher-risk than stopping to flag it for deliberate review. Do not treat this sanitizer as
  fully hardened; treat it as materially improved over the pre-#4028 state.
