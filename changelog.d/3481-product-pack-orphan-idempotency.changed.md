- **`ProductPackStore::install()` now best-effort compensates sibling-store content it already
  installed if the final Postgres persist fails.** A new `compensate_fn` callback (wired in
  `POST /api/product-packs` from the same per-kind delete dispatch `DELETE
  /api/product-packs/{id}` already used) is invoked once per already-installed item, in reverse
  install order, when the pack-row persist transaction fails after `install_fn` has already
  committed content into `InstructionStore`/`PolicyStore`/`WorkflowEngine`. **Known gap, not
  closed by this change:** compensation is best-effort — a sibling store's own delete can itself
  fail (e.g. a referential-integrity refusal outside the bundle's own dependency chain); a
  residual orphan from that is logged at `spdlog::error` and counted in
  `yuzu_server_product_pack_install_compensation_total{result}` for operator follow-up, not
  automatically retried.
- **`POST /api/product-packs` now honors an optional `Idempotency-Key` header.** A retried POST
  with the same key and an identical body returns the original pack id without re-running
  `install_fn` against any sibling store; the same key reused with a different body is rejected
  as a 400. Missing header preserves prior behavior exactly — no dedup, a fresh random pack id
  every call.
- `uninstall()`'s late-metadata-delete-failure gap (a Postgres transaction failing after sibling
  content has already been removed) is accepted as a store-scoped residual risk — documented in
  `product_pack_store.hpp` alongside the existing retry-self-heals mitigant — with a sharper,
  more specific operator-facing error log naming exactly how many sibling items were already
  removed. No behavior change.
