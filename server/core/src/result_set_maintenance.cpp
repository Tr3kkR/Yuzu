#include "result_set_maintenance.hpp"

#include <chrono>
#include <string>

#include <yuzu/metrics.hpp>

#include "audit_store.hpp"
#include "result_set_store.hpp"

namespace yuzu::server {

int run_result_set_gc(ResultSetStore& store, AuditStore* audit, yuzu::MetricsRegistry& metrics) {
    const int swept = store.gc_sweep();
    if (swept <= 0)
        return swept;

    metrics.counter("yuzu_result_set_gc_total").increment(static_cast<double>(swept));

    // Aggregate forensic row for the sweep (design §9). System-initiated, so no
    // session/ip/user-agent; the count carries the outcome. Best-effort: a failed
    // audit write must not wedge the maintenance thread.
    if (audit) {
        AuditEvent ev;
        ev.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                           std::chrono::system_clock::now().time_since_epoch())
                           .count();
        ev.principal = "__system__";
        ev.action = "result_set.gc_sweep";
        ev.target_type = "ResultSet";
        ev.detail = "count=" + std::to_string(swept);
        ev.result = "success";
        (void)audit->log(ev);
    }
    return swept;
}

} // namespace yuzu::server
