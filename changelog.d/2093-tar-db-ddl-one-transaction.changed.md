- **`TarDatabase::open()` creates its schema in one transaction instead of ~75.** SQLite gives every
  bare statement its own implicit transaction, and WAL defaults to `synchronous=FULL`, so handing
  `sqlite3_exec` the schema batch cost roughly 75 separate commits each with its own fsync. Measured
  on the Windows CI runner (91 iterations, best of 3): **72.4 ms per open against 11.0 ms** for the
  identical DDL wrapped in a single transaction. Every agent paid this at boot on every endpoint,
  and the `tar` unit suite paid it ~95 times — which is what pushed that suite into its 90 s meson
  budget on 48 of 437 Windows CI runs. The wrapper is also an atomicity fix: a batch that fails
  partway through now rolls back instead of leaving a half-built schema for the next open to
  inherit. (#2093)
