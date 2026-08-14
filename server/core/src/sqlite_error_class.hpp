#pragma once

#include <sqlite3.h>

namespace yuzu::server {

/// True for a SQLite extended errcode that will NOT clear on an unchanged
/// retry — the store is degraded, not merely contended (#2786 "PR 1c").
/// False (including 0, "not a SQLite fault") means transient: BUSY, LOCKED,
/// a generic ERROR, and similar clear once the contention or the underlying
/// condition passes, so a caller-facing "retry this call unchanged" is
/// honest for them.
///
/// Masked on the PRIMARY code (`& 0xff`) rather than matched on the exact
/// extended code: an extended variant (SQLITE_CORRUPT_VTAB,
/// SQLITE_READONLY_DBMOVED, ...) classifies with its family, so a future
/// SQLite adding a new variant of an already-permanent primary does not
/// silently fall through to the transient arm.
///
/// Deliberately excluded even though they can look permanent in the moment:
/// - SQLITE_IOERR: a filesystem hiccup (NFS blip, USB drive hiccup) is
///   ordinarily transient; a genuinely dying disk progresses to CORRUPT. A
///   false "escalate to an operator" burns a human; a false "retry" is
///   bounded by the client-side retry envelope this project already
///   documents, so the asymmetry favours staying on the transient arm here.
/// - SQLITE_CANTOPEN: rare on an already-open handle (this classifier is
///   only reached once a read has already failed on a live connection), and
///   its causes (a concurrent DBMOVED/unlink) are not reliably permanent.
/// - SQLITE_BUSY / SQLITE_LOCKED: transient by definition.
[[nodiscard]] constexpr bool is_permanent_sqlite_error(int extended_errcode) {
    switch (extended_errcode & 0xff) {
    case SQLITE_CORRUPT:
    case SQLITE_NOTADB:
    case SQLITE_READONLY:
    case SQLITE_FULL:
        return true;
    default:
        return false;
    }
}

} // namespace yuzu::server
