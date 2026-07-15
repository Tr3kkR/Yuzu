#pragma once

// GuardianStateReader - the production IStateReader for the Guardian spark
// runtime (rung 5). Resolves live endpoint state for the three event-driven
// guard types the runtime re-reads on every initial / event / convergence pass
// (an event is a hint; the verdict always comes from a live re-read):
//   * file     - handle-scoped, #807-safe (file_hash.hpp); cross-platform.
//   * registry - RegOpenKeyExW + RegQueryValueExW, G4-encoded; Windows only
//                (Unknown on other platforms, where a registry rule cannot arm).
//   * service  - sd_bus ActiveState (Linux) / SCM QueryServiceStatusEx (Windows);
//                a truly absent unit/service folds to Stopped (R5); other
//                platforms report Unknown.
//
// STATELESS -> thread-safe by construction: every call resolves from its own
// params/plan using only locals plus OS handles it opens and closes within the
// call, so the convergence lanes and the consumer handler may call it
// concurrently for different keys with no shared mutable state.
//
// BOUNDED/CANCELLABLE (partial): the sd_bus point-read carries an explicit 5s
// method-call timeout (not the ~25s libsystemd default). The file open/read and
// the Windows SCM calls are synchronous with no per-read deadline; they are
// bounded in practice on a local filesystem / a responsive SCM, but a network /
// FUSE mount stall or a wedged SCM can still block a lane join or the consumer
// detach until the agent's hard-exit shutdown backstop (PR-A) fires. Full
// per-read cancellation (a stop token + platform cancellable I/O, or a
// lifetime-safe bounded I/O executor) is a recorded follow-up, NOT yet done. The
// reader still never fabricates an absent/stopped from a failure - it degrades to
// Unknown.
//
// Unknown vs Known is the load-bearing distinction: a DEFINITIVE negative (file
// ENOENT, registry key/value not found, systemd NoSuchUnit, SCM
// ERROR_SERVICE_DOES_NOT_EXIST) is a KNOWN snapshot (absent / stopped) that the
// evaluator turns into a real verdict; a TRANSIENT fault (EMFILE, ACCESS_DENIED,
// a bus transport blip, a mid-transition *_PENDING / activating state) is
// UNKNOWN, so the evaluator leaves the compliance verdict untouched and raises
// guard.unhealthy instead of a false drift.

#include <yuzu/plugin.h> // YUZU_EXPORT

#include "guardian_spark_runtime.hpp" // IStateReader + seam types (plan/snapshot/params)

namespace yuzu::agent {

class YUZU_EXPORT GuardianStateReader : public IStateReader {
public:
    ReadResult<FileSnapshot> read_file(const FileSparkParams& p, const FileReadPlan& plan) override;
    RegistryRead read_registry(const RegistrySparkParams& p, const RegistryReadPlan& plan) override;
    ReadResult<ServiceRunState> read_service(const ServiceSparkParams& p) override;
};

} // namespace yuzu::agent
