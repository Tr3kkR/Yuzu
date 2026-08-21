- **Breaking — `ProductPackStore` (operator-installed product packs) migrated from SQLite to
  PostgreSQL** (schema `product_pack_store`, ADR-0054), with a mandatory first-boot backfill of
  the legacy `product-packs.db` — installed packs are operator-authored content, not expendable
  telemetry, so losing one on cutover would silently drop it from the catalog. **On a
  multi-replica deployment, if two replicas' legacy files hold genuinely different content for
  the same pack or item id, the server REFUSES TO START on that replica** (fail-closed — the
  backfill never runs partially, and no replica serves on top of a possibly-wrong pack catalog):
  the startup log names the exact pack/item id and remediation is to repair or move aside the
  losing replica's legacy file, then restart. This is total boot refusal, not a
  warn-and-continue degraded mode — plan for it during a multi-replica cutover the same way you
  would any other fail-closed migration guard (`docs/postgres-store-playbook.md`).
  `GET /api/product-packs`, `GET /api/product-packs/{id}`, and `DELETE /api/product-packs/{id}`
  now return **HTTP 503** on a genuine database outage instead of a misleadingly-empty pack list
  / a false "not found". **`DELETE /api/product-packs/{id}` on a missing id now returns 404**
  (previously 400) — an operator or automation client can now tell "that pack doesn't exist"
  apart from "the request itself was invalid" or "the database is unavailable, retry". **The
  error body on a rejected `POST /api/product-packs` or `DELETE /api/product-packs/{id}` is now
  the standard A4 envelope** (`{"error":{"code","message","correlation_id",...}}`) instead of the
  previous flat `{"error": "<message>"}` — a client parsing the old flat shape must switch to
  reading `error.message`; a genuine database error no longer echoes raw driver text to the
  caller (logged server-side instead). Installing a bundle whose documents assign the same item
  id twice now fails the whole install with a database error instead of silently discarding the
  duplicate item (a pre-migration bug, not a preserved behavior). No change to the `#802`/W7.4
  signed-pack enforcement default, the Ed25519 signature verification path, or the
  `--allow-unsigned-packs` / `YUZU_ALLOW_UNSIGNED_PACKS` operator escape hatch. A legacy
  `product-packs.db` written before 7.13 (predating the `verified` column) backfills correctly,
  defaulting `verified=false` for that vintage.
