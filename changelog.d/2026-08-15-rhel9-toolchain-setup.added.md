- RHEL 9 / Rocky 9 / AlmaLinux 9 build support: `scripts/setup-rhel9.sh` provisions the full C++
  toolchain (gcc-toolset-14 for C++23, CRB-sourced ninja, the vcpkg port prerequisites, pip-pinned
  meson + PyYAML, vcpkg at the pinned baseline, optional ccache from EPEL, and optionally a local
  PostgreSQL 18 for the server test suite). The script is idempotent, has a `--check` verify-only
  mode for confirming parity on a second machine, and emits a provenance manifest. Runbook:
  `docs/rhel9-build-setup.md`, which documents the four RHEL-specific traps — the system GCC 11
  cannot build C++23; only `meson/native/linux-gcc13.ini` is usable (the gcc14 file hard-codes
  `gcc-14`/`g++-14` binary names that Software Collections do not provide, and the gcc15/clang21
  files require mold); `postgresql-setup --initdb` leaves host auth on `ident`; and the test role
  needs `pg_signal_backend` on top of `CREATEDB`, without which `PostgresTestDb`'s
  `DROP DATABASE ... WITH (FORCE)` silently leaks a database per test until the `[pg]` shard blows
  its 600 s timeout. Also records a platform limitation: RHEL 9's system SQLite (3.34.1) predates
  `RETURNING` (3.35+), so the Python test-telemetry tooling cannot run there; the C++ suites are
  unaffected because they link vcpkg's SQLite 3.52.0.
