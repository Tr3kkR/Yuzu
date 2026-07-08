/**
 * spark_startup.cpp — the agent_startup spark type (see spark_types.hpp).
 *
 * One-shot: fires once when the engine starts (or at arm time if the engine is
 * already running — the arm itself is the "startup" a late subscriber can
 * observe), then never reschedules. No watcher thread, no payload
 * (stage0-trigger-inventory.md: the `agent_startup` triggerType missing from
 * the original Stage-1 file list).
 */

#include "spark_types.hpp"

namespace yuzu::agent {

SparkFireDecision startup_process_due() {
    SparkFireDecision d;
    d.emit = true;
    d.reschedule = std::nullopt; // one-shot — never scheduled again
    return d;
}

} // namespace yuzu::agent
