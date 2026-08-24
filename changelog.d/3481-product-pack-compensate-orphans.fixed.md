- **`ProductPackStore::install()` no longer silently orphans sibling-store content on a late
  failure.** Any failure reached after `install_fn` has already committed one or more documents
  into `InstructionStore`/`PolicyStore`/`WorkflowEngine` — the final Postgres persist transaction
  failing, or the duplicate-item-id validation check — now best-effort compensates (undoes) every
  already-installed item, in reverse install order, via the same per-kind delete dispatch
  `DELETE /api/product-packs/{id}` already used (now shared through one helper so the two paths
  can't drift). **Known gap, not closed by this change:** compensation is best-effort — a sibling
  store's own delete can itself fail (e.g. a referential-integrity refusal outside the bundle's
  own dependency chain); a residual orphan from that is logged at `spdlog::error` and counted in
  the new `yuzu_server_product_pack_install_compensation_total{result}` metric for operator
  follow-up, not automatically retried. A client that retries the install after a partial
  compensation failure gets a fresh `install_fn` pass over the whole bundle rather than a repair
  of just the residual item — the surviving orphan and the retry's new copy can coexist as
  duplicate sibling-store content, which the compensation metric surfaces for operator cleanup
  but does not itself prevent.
- `uninstall()`'s mirror-image gap — its metadata-delete transaction failing after sibling
  content has already been removed — is accepted as a store-scoped residual risk (documented in
  `product_pack_store.hpp` alongside the existing retry-self-heals mitigant, since no
  compensating action is possible once the content is gone) rather than closed, with a sharper,
  more specific operator-facing error log naming exactly how many sibling items were already
  removed. No behavior change.
