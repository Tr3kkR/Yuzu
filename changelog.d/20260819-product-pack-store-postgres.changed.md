- **`ProductPackStore` (operator-installed product packs) migrated from SQLite to PostgreSQL**
  (schema `product_pack_store`, ADR-0054), with a mandatory first-boot backfill of the legacy
  `product-packs.db` — installed packs are operator-authored content, not expendable telemetry,
  so losing one on cutover would silently drop it from the catalog. `GET /api/product-packs`,
  `GET /api/product-packs/{id}`, and `DELETE /api/product-packs/{id}` now return **HTTP 503**
  on a genuine database outage instead of a misleadingly-empty pack list / a false "not found" —
  `POST /api/product-packs` already returned an error on a store outage pre-migration and keeps
  that shape. **`DELETE /api/product-packs/{id}` on a missing id now returns 404** (previously
  400) — an operator or automation client can now tell "that pack doesn't exist" apart from "the
  request itself was invalid" or "the database is unavailable, retry". Installing a bundle whose
  documents assign the same item id twice now fails the whole install with a database error
  instead of silently discarding the duplicate item (a pre-migration bug, not a preserved
  behavior). No change to the `#802`/W7.4 signed-pack enforcement default, the Ed25519 signature
  verification path, or the `--allow-unsigned-packs` / `YUZU_ALLOW_UNSIGNED_PACKS` operator
  escape hatch. A legacy `product-packs.db` written before 7.13 (predating the `verified` column)
  backfills correctly, defaulting `verified=false` for that vintage. On a multi-replica
  deployment, if two replicas' legacy files hold genuinely different content for the same pack
  id, the backfill refuses that row rather than silently discarding one replica's data — this
  should only ever surface as a startup log line naming the exact pack id and a
  repair-or-move-aside remediation.
