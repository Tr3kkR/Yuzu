- **`CustomPropertiesStore` migrated to PostgreSQL** (ADR-0006/ADR-0043). Device custom
  properties and property schemas now live in the `custom_properties_store` Postgres schema
  instead of a SQLite file; existing data is backfilled automatically on first boot after
  upgrade (one-time, idempotent). `props.<key>` scope-expression resolution (used in targeting
  and dispatch) now fails closed on a database read error instead of silently treating the
  property as absent.
