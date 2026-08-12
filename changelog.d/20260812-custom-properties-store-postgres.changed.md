- **`CustomPropertiesStore` migrated to PostgreSQL** (ADR-0006/ADR-0043). Device custom
  properties and property schemas now live in the `custom_properties_store` Postgres schema
  instead of a SQLite file. Existing data is backfilled automatically on first boot after
  upgrade (one-time, idempotent) — **if the backfill cannot complete, the server refuses to
  boot** and retries on the next start; see `docs/user-manual/upgrading.md` § "Custom
  properties migrate to Postgres" for what to expect and
  `docs/ops-runbooks/custom-properties-store-backfill-recovery.md` if it happens. `props.<key>`
  scope-expression resolution (used in targeting and dispatch) now fails closed on a database
  read error instead of silently treating the property as absent — watch
  `yuzu_server_custom_properties_read_degrade_total{reason}` and
  `yuzu_server_custom_properties_backfill_total{result}` (`docs/user-manual/metrics.md` §
  "Custom properties metrics").
