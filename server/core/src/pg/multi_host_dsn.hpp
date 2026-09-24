#pragma once

/// @file multi_host_dsn.hpp
/// HA WS-8: the server refuses to run a multi-host Postgres DSN that could put
/// its connections on a server that cannot take writes.
///
/// WHY. With `host=n1,n2,n3` and no `target_session_attrs`, libpq takes the
/// FIRST host that accepts a connection — a standby included. The pool then
/// holds connections whose writes fail, and nothing the `/readyz` probe does can
/// see all of them (it holds one connection; the pool holds many, possibly on
/// different hosts). Governance rounds 2–4 of WS-8 found four HIGH false-green
/// shapes, all this one root cause. The documented HA pattern
/// (docs/user-manual/ha-postgres.md) already sets
/// `target_session_attrs=read-write`; this makes it the enforced behaviour.
///
/// POLICY (operator decision, 2026-09-24):
///   - one host, and no `load_balance_hosts`: unchanged;
///   - multi-host (or `load_balance_hosts` other than `disable`) with NO
///     `target_session_attrs`: `target_session_attrs=read-write` is APPENDED
///     (a DSN keyword overrides a `PGTARGETSESSIONATTRS` environment value, so
///     the environment cannot weaken it);
///   - multi-host with `read-write` or `primary`: unchanged;
///   - multi-host with any other value (`any`, `read-only`, `standby`,
///     `prefer-standby`): REFUSED — the caller exits with the returned message.
/// A host list that arrives through `PGHOST`/`PGHOSTADDR` counts as multi-host.
/// A list from a `service=` entry cannot be seen here (libpq resolves it at
/// connect time) — documented residual.
///
/// The error message names only the offending `target_session_attrs` value,
/// never the DSN (it can carry a password).

#include <cstddef>
#include <expected>
#include <string>

namespace yuzu::server::pg {

struct MultiHostDsn {
    std::string dsn;      ///< the DSN to use (possibly with the attribute appended)
    bool appended{false}; ///< true when target_session_attrs=read-write was added
    std::size_t hosts{1}; ///< hosts seen (DSN list, else PGHOST/PGHOSTADDR)
};

/// Apply the policy above. An unparseable DSN is returned unchanged (the pool
/// reports it at boot, as before).
std::expected<MultiHostDsn, std::string> enforce_multi_host_read_write(const std::string& dsn);

} // namespace yuzu::server::pg
