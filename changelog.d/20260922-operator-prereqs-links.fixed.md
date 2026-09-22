- **Break-glass CLI prerequisites corrected, and two broken doc links fixed.**
  `server-admin.md` told operators that `--mfa-reset` requires `--config` + `--data-dir` and that
  `--break-glass-arm` requires `--data-dir`. Both are pre-ADR-0006 language: each actually requires
  the Postgres auth store (`--postgres-dsn` / `YUZU_POSTGRES_DSN`), and neither consults
  `--data-dir` at all. Wrong prerequisites on a lockout-recovery path are costly precisely when
  they are read. Also repointed `rest-api.md`'s Tag-source-precedence link (the guide is one
  directory up) and `upgrading.md`'s Server Administration link (the file is `server-admin.md`).
