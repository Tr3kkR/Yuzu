- **Settings analytics view no longer leaks ClickHouse URL credentials.** The Settings →
  Analytics dashboard fragment (and its new `GET /api/v1/settings/analytics` REST twin) rendered
  the configured ClickHouse URL verbatim, masking only the separate `clickhouse_password` field —
  a URL carrying embedded userinfo credentials (`clickhouse://user:pass@host:9000/db`) leaked the
  credential regardless of that masking. The URL is now stripped of embedded userinfo before
  either surface renders it for the common shapes (a bare `user@`/`user:pass@` authority, a
  password containing an unescaped `@`, `/`, or `?`, and a query-string credential form
  `?user=...&password=...`), and the raw password is never read into a response at all (only
  whether it is set). Fix-round hardening (governance Gate 2-8, three rounds, plus an independent
  two-model adversarial-review pass) rewrote the sanitizer twice before landing on the current
  design: a boundary-first approach with a "does this look like a host" heuristic proved unfixable
  (a digit-only password segment before a `/` is lexically identical to a real `host:port`, so no
  heuristic patch could tell them apart); the LAST-`@`-ends-userinfo replacement then shipped with
  two further bypasses an adversarial-review round found (a schemeless URL whose query string
  embeds a nested `://` could fool scheme-boundary detection into skipping the strip entirely, and
  a query string containing its own `@` could cause the query-strip to run against the wrong,
  already-mutated string and leave a password fragment exposed — both independently reproduced by
  two external reviewers against the compiled object, `/home/dgr/advrev-4028`). The current design
  closes both: the scheme boundary is a bounded RFC-3986-shaped prefix scan from position 0 (never
  an unbounded search for `://` anywhere in the string), and both cut points — the userinfo `@`
  and the query/fragment start — are computed against the ORIGINAL string and unioned, never
  sequentially against a once-mutated result. This deliberately over-strips a URL whose path also
  happens to contain a literal `@` (e.g. `.../db@table` now becomes `.../table`), and — new in this
  round — a URL where a `?`/`#` appears at or before the apparent userinfo-ending `@` now drops
  everything past the scheme (that shape is lexically indistinguishable from a query string that
  itself contains a later `@`, so it is resolved the same conservative way). A follow-up
  adversarial-review pass on this exact fix then found the scheme scan itself accepted a
  digit/`+`/`-`/`.` as the first scheme byte instead of requiring RFC 3986's mandatory leading
  letter, so a schemeless credential URL whose "username" happened to be scheme-shaped and
  digit-led (e.g. `9name://pass@host:9000/db`) had that prefix wrongly preserved — closed by
  requiring the scheme scan's first byte be alphabetic.
