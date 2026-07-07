#pragma once

/// @file agent_decommission.hpp
/// The agent-decommission cascade (ADR-0024 Decision 11 / roadmap D-3): a single
/// entry point that fans `delete_agent(agent_id)` across EVERY per-agent store,
/// so an operator decommission durably erases a machine's stored rows. This is
/// the GDPR-erasure half the per-store `delete_agent` methods could not deliver
/// on their own: those methods exist on each store but had ZERO production
/// callers before this seam (they were invoked only from unit tests), which made
/// the ADR's "offline agents purge ... via decommission" story fictional. §27
/// builds the fan-out and registers its stores with it.
///
/// BEST-EFFORT, aggregated. Each per-store `delete_agent` is individually "best
/// effort on agent removal": it swallows its own transient failure (a PG lease
/// it cannot acquire in time, a SQL error) at debug level and returns void. This
/// cascade preserves that posture across the fan-out — it attempts EVERY
/// registered store even when an earlier one throws, aggregates the outcomes,
/// and returns a structured result the caller can audit (which stores were
/// deleted / skipped / failed).
///
/// LEASE DISCIPLINE (ADR-0012). Each `delete_agent` acquires and releases its
/// OWN lease/lock inside the call and returns before the cascade moves on, so
/// the cascade never holds one store's lease across another store's call — the
/// "never holding a lease across another store call" rule.
///
/// NULL-TOLERANT, like the sibling ingest seams. A store that is not configured
/// on this deployment (a null pointer) is recorded as `Skipped`, never a crash —
/// so the same cascade works on a Postgres-less deployment (only the SQLite
/// `InventoryStore` present) and on a full SLE deployment.

#include <cstddef>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server {

// Non-owning forward declarations — the .cpp includes the store headers so it
// can call each `delete_agent`.
class InventoryStore;
class SoftwareInventoryStore;
class AppPerfDailyStore;
class DeviceInventoryStore;
class SoftwareLicensingStore;

/// Per-store outcome of one decommission fan-out.
enum class DecommissionOutcome {
    Deleted, ///< delete_agent was invoked and returned normally. Best-effort:
             ///< the store may itself have logged+swallowed a transient failure,
             ///< which is invisible here (delete_agent returns void).
    Skipped, ///< the store was not configured on this deployment (null pointer).
    Failed,  ///< delete_agent threw — every OTHER store was still attempted.
};

/// Human-readable outcome tag for logs/audit ("deleted"|"skipped"|"failed").
[[nodiscard]] const char* to_string(DecommissionOutcome o) noexcept;

/// One store's line in the aggregated result.
struct DecommissionStoreResult {
    std::string store; ///< store name, for the audit trail / logs
    DecommissionOutcome outcome{DecommissionOutcome::Skipped};
    std::string error; ///< populated iff outcome == Failed
};

/// Aggregate result of a single `decommission(agent_id)` call — one entry per
/// registered store, plus rolled-up counts so a caller can audit at a glance.
struct DecommissionResult {
    std::string agent_id;
    std::vector<DecommissionStoreResult> stores;
    std::size_t deleted{0};
    std::size_t skipped{0};
    std::size_t failed{0};

    /// True iff no registered store threw. A cascade of only Skipped/Deleted
    /// stores is `ok()`. Because each `delete_agent` swallows its own transient
    /// PG failure, `ok()` does NOT assert every row is gone — it asserts the
    /// fan-out completed without an exception escaping any store.
    [[nodiscard]] bool ok() const noexcept { return failed == 0; }
};

/// The per-agent stores the cascade fans `delete_agent` across. NON-OWNING: the
/// caller (server.cpp) owns every store for the process lifetime and outlives
/// the cascade. Any pointer may be null — a null store is skipped, not a crash.
/// Extend this struct (and the constructor's registration list) when a new
/// per-agent store with a `delete_agent` joins the ladder.
struct AgentDecommissionStores {
    InventoryStore* inventory{nullptr};                  ///< SQLite generic inventory
    SoftwareInventoryStore* software_inventory{nullptr}; ///< PG installed_software
    AppPerfDailyStore* app_perf_daily{nullptr};          ///< PG per-device app-perf
    DeviceInventoryStore* device_inventory{nullptr};     ///< PG device_ci
    SoftwareLicensingStore* software_licensing{nullptr}; ///< PG detected licences (SLE)
};

/// A single decommission entry point that fans `delete_agent` across a fixed set
/// of per-agent stores. Construct it with the stores this deployment owns; call
/// `decommission(agent_id)` on an operator decommission.
class AgentDecommission {
public:
    /// Register the fixed set of per-agent stores. Null pointers are registered
    /// too so the structured result still reports them as `Skipped` (auditable:
    /// "this deployment has no such store" is distinct from "the store had
    /// nothing to delete"). The SoftwareLicensingStore is included — it carries
    /// the Decision 11 per-user `user_ref` rows, the whole reason this cascade
    /// exists.
    explicit AgentDecommission(const AgentDecommissionStores& stores);

    /// Empty cascade — register targets with `add_store`.
    AgentDecommission() = default;

    /// Register an additional decommission target by name. Used by tests (to
    /// inject a store that throws, or a null/unconfigured target) and as the
    /// forward-compat seam for a per-agent store not yet modelled by
    /// AgentDecommissionStores. A null `deleter` is registered as an
    /// always-Skipped target.
    void add_store(std::string name, std::function<void(std::string_view)> deleter);

    /// Fan `delete_agent(agent_id)` across every registered store. Best-effort:
    /// attempts every store even if one throws. Returns the per-store outcomes.
    /// An empty `agent_id` is a no-op that logs and reports every target Skipped
    /// (mirrors each store's own empty-id guard; a `WHERE agent_id = ''` DELETE
    /// would be a footgun, never a fleet wipe).
    [[nodiscard]] DecommissionResult decommission(std::string_view agent_id);

    /// Number of registered targets (incl. skipped/null ones).
    [[nodiscard]] std::size_t target_count() const noexcept { return targets_.size(); }

private:
    struct Target {
        std::string name;
        std::function<void(std::string_view)> deleter; ///< null ⇒ always Skipped
    };
    std::vector<Target> targets_;
};

} // namespace yuzu::server
