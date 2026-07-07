#include "agent_decommission.hpp"

#include <exception>
#include <utility>

#include <spdlog/spdlog.h>

#include "app_perf_daily_store.hpp"
#include "device_inventory_store.hpp"
#include "inventory_store.hpp"
#include "software_inventory_store.hpp"
#include "software_licensing_store.hpp"

namespace yuzu::server {

const char* to_string(DecommissionOutcome o) noexcept {
    switch (o) {
    case DecommissionOutcome::Deleted:
        return "deleted";
    case DecommissionOutcome::Skipped:
        return "skipped";
    case DecommissionOutcome::Failed:
        return "failed";
    }
    return "unknown";
}

AgentDecommission::AgentDecommission(const AgentDecommissionStores& stores) {
    // Fixed registration order: the SQLite generic store first, then each
    // born-on-PG typed projection. Every store is registered even when null so
    // the result reports it as Skipped. The lambdas bind the raw store pointer
    // by value (non-owning). InventoryStore takes `const std::string&`; the four
    // PG stores take `std::string_view` — the adapter unifies them under one
    // `void(std::string_view)` deleter signature.
    using Fn = std::function<void(std::string_view)>;

    targets_.push_back({"inventory", stores.inventory
                                         ? Fn([p = stores.inventory](std::string_view id) {
                                               p->delete_agent(std::string(id));
                                           })
                                         : nullptr});
    targets_.push_back({"software_inventory",
                        stores.software_inventory
                            ? Fn([p = stores.software_inventory](std::string_view id) {
                                  p->delete_agent(id);
                              })
                            : nullptr});
    targets_.push_back({"app_perf_daily",
                        stores.app_perf_daily ? Fn([p = stores.app_perf_daily](std::string_view id) {
                            p->delete_agent(id);
                        })
                                              : nullptr});
    targets_.push_back({"device_inventory",
                        stores.device_inventory
                            ? Fn([p = stores.device_inventory](std::string_view id) {
                                  p->delete_agent(id);
                              })
                            : nullptr});
    // The Decision 11 store: its agent_licenses / agent_license_state rows carry
    // the per-user `user_ref` pseudonyms, so a decommission MUST reach it.
    targets_.push_back({"software_licensing",
                        stores.software_licensing
                            ? Fn([p = stores.software_licensing](std::string_view id) {
                                  p->delete_agent(id);
                              })
                            : nullptr});
}

void AgentDecommission::add_store(std::string name, std::function<void(std::string_view)> deleter) {
    targets_.push_back({std::move(name), std::move(deleter)});
}

DecommissionResult AgentDecommission::decommission(std::string_view agent_id) {
    DecommissionResult result;
    result.agent_id = std::string(agent_id);
    result.stores.reserve(targets_.size());

    if (agent_id.empty()) {
        // Mirror each store's own empty-id guard: nothing to erase, and an empty
        // agent_id must never reach a `DELETE ... WHERE agent_id = ''`. Every
        // target is reported Skipped so the audit trail is complete.
        spdlog::warn("AgentDecommission: empty agent_id — nothing to decommission");
        for (const auto& t : targets_) {
            result.stores.push_back({t.name, DecommissionOutcome::Skipped, {}});
            ++result.skipped;
        }
        return result;
    }

    for (const auto& t : targets_) {
        DecommissionStoreResult r;
        r.store = t.name;
        if (!t.deleter) {
            r.outcome = DecommissionOutcome::Skipped;
            ++result.skipped;
            result.stores.push_back(std::move(r));
            continue;
        }
        // Best-effort: an exception from one store must not abort the fan-out —
        // the remaining stores are still attempted. delete_agent itself already
        // swallows transient PG failures internally; a throw here is the
        // exceptional case (an unexpected bug/bad_alloc), reported not fatal.
        try {
            t.deleter(agent_id);
            r.outcome = DecommissionOutcome::Deleted;
            ++result.deleted;
        } catch (const std::exception& e) {
            r.outcome = DecommissionOutcome::Failed;
            r.error = e.what();
            ++result.failed;
            spdlog::error("AgentDecommission: store '{}' delete_agent threw for agent={}: {}",
                          t.name, agent_id, e.what());
        } catch (...) {
            r.outcome = DecommissionOutcome::Failed;
            r.error = "unknown exception";
            ++result.failed;
            spdlog::error("AgentDecommission: store '{}' delete_agent threw a non-std exception for "
                          "agent={}",
                          t.name, agent_id);
        }
        result.stores.push_back(std::move(r));
    }

    // One audit-friendly summary line per decommission.
    if (result.failed == 0)
        spdlog::info("AgentDecommission: agent={} decommissioned (deleted={} skipped={})", agent_id,
                     result.deleted, result.skipped);
    else
        spdlog::warn(
            "AgentDecommission: agent={} decommission PARTIAL (deleted={} skipped={} failed={})",
            agent_id, result.deleted, result.skipped, result.failed);
    return result;
}

} // namespace yuzu::server
