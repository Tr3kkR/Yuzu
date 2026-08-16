/**
 * test_capability_catalogue.cpp — PR1.9's cross-cutting invariant gate over
 * the WHOLE capability catalogue: the six independently-authored sources
 * (the five per-plugin-group `capability_decls/plugin_action_catalogue_*.hpp`
 * fragments plus the core-owned `capability_decls/core_dispatch_capabilities
 * .hpp`) composed into one `CommandCapabilityRegistry`, exactly as a real
 * dispatch chokepoint eventually will.
 *
 * Nobody who authors a single fragment can see the other five, so nobody is
 * positioned to catch a row that under-declares risk for its operation, uses
 * a securable or operation that was never seeded, calls itself Destructive
 * without being Irreversible, or falsely claims `system_reserved`. This file
 * is where those checks live.
 *
 * Pure — no Postgres, no sleeps, no spawns, no clock. Every fragment is a
 * `constexpr` array over static storage; `CommandCapabilityRegistry` is a
 * plain composing view.
 */

#include "capability_decls/core_dispatch_capabilities.hpp"
#include "capability_decls/plugin_action_catalogue_a.hpp"
#include "capability_decls/plugin_action_catalogue_b.hpp"
#include "capability_decls/plugin_action_catalogue_c.hpp"
#include "capability_decls/plugin_action_catalogue_content_dist.hpp"
#include "capability_decls/plugin_action_catalogue_d.hpp"
#include "command_capability.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <span>
#include <string>
#include <string_view>
#include <vector>

using namespace yuzu::server;

namespace {

// Mirrors rbac_store.cpp's `seed_defaults()` `types[]` (the securable types
// actually seeded into `rbac.db`) — this test file may not include or edit
// rbac_store.cpp (it is a .cpp with a live SQLite dependency, not a header,
// and this package's boundaries forbid editing it regardless), so the list
// is reproduced read-only here. If `types[]` ever changes, this mirror needs
// updating too — that is the intended failure mode: a securable this
// catalogue references but rbac_store.cpp stops seeding should fail loudly,
// not silently pass.
constexpr std::array<std::string_view, 25> kSeededSecurableTypes{{
    "Infrastructure",
    "UserManagement",
    "InstructionDefinition",
    "InstructionSet",
    "Execution",
    "Schedule",
    "Approval",
    "Tag",
    "AuditLog",
    "Response",
    "ManagementGroup",
    "ApiToken",
    "Security",
    "Policy",
    "DeviceToken",
    "SoftwareDeployment",
    "License",
    "FileRetrieval",
    "GuaranteedState",
    "Inventory",
    "AccessReview",
    "SoftwareLicensing",
    "PluginConfig",
    "PluginSecret",
    "UploadGrant",
}};

// Mirrors rbac_store.cpp's `seed_defaults()` `ops[]` — the full seven-value
// `authz::Operation` vocabulary that store seeds grants over.
constexpr std::array<std::string_view, 7> kSeededOperations{{
    "Read", "Write", "Execute", "Delete", "Approve", "Push", "Attest",
}};

[[nodiscard]] bool is_seeded_securable(std::string_view securable) noexcept {
    return std::find(kSeededSecurableTypes.begin(), kSeededSecurableTypes.end(), securable) !=
           kSeededSecurableTypes.end();
}

[[nodiscard]] bool is_seeded_operation(authz::Operation op) noexcept {
    const auto name = authz::to_string(op);
    return std::find(kSeededOperations.begin(), kSeededOperations.end(), name) !=
           kSeededOperations.end();
}

/// One entry per span this test composes, paired with a human label for
/// failure messages and whether the span is the core (system-reserved)
/// source — everything else is the two-way `system_reserved` boundary this
/// file enforces.
struct LabeledSpan {
    std::string_view label;
    std::span<const CommandCapability> rows;
    bool is_core;
};

[[nodiscard]] std::vector<LabeledSpan> all_labeled_sources() {
    return {
        {"content_dist", capdecls::plugin_action_catalogue_content_dist(), false},
        {"a", capdecls::plugin_action_catalogue_a(), false},
        {"b", capdecls::plugin_action_catalogue_b(), false},
        {"c", capdecls::plugin_action_catalogue_c(), false},
        {"d", capdecls::plugin_action_catalogue_d(), false},
        {"core", capdecls::core_dispatch_capabilities(), true},
    };
}

[[nodiscard]] CommandCapabilityRegistry build_registry(const std::vector<LabeledSpan>& sources) {
    // CommandCapabilityRegistry's constructor only accepts a brace-enclosed
    // std::initializer_list (see command_capability.hpp), so this can't be
    // built from the vector programmatically — it mirrors all_labeled_sources()
    // literally, six sources exactly as a live composition site would use.
    return CommandCapabilityRegistry{
        capdecls::plugin_action_catalogue_content_dist(),
        capdecls::plugin_action_catalogue_a(),
        capdecls::plugin_action_catalogue_b(),
        capdecls::plugin_action_catalogue_c(),
        capdecls::plugin_action_catalogue_d(),
        capdecls::core_dispatch_capabilities(),
    };
}

} // namespace

TEST_CASE("capability catalogue: every row's risk_tier is at or above its operation's floor",
          "[server][dispatch][capability]") {
    for (const auto& source : all_labeled_sources()) {
        for (const auto& row : source.rows) {
            INFO("source=" << source.label << " plugin=" << row.plugin
                            << " action=" << row.action);
            CHECK(static_cast<uint8_t>(row.risk_tier) >=
                  static_cast<uint8_t>(authz::min_risk_tier_for(row.operation)));
        }
    }
}

TEST_CASE("capability catalogue: every securable and operation is one rbac_store.cpp actually "
          "seeds",
          "[server][dispatch][capability]") {
    for (const auto& source : all_labeled_sources()) {
        for (const auto& row : source.rows) {
            INFO("source=" << source.label << " plugin=" << row.plugin
                            << " action=" << row.action << " securable=" << row.securable);
            CHECK(is_seeded_securable(row.securable));
            CHECK(is_seeded_operation(row.operation));
        }
    }
}

TEST_CASE("capability catalogue: every Destructive row is Irreversible",
          "[server][dispatch][capability]") {
    for (const auto& source : all_labeled_sources()) {
        for (const auto& row : source.rows) {
            if (row.dispatch_class != DispatchClass::Destructive)
                continue;
            INFO("source=" << source.label << " plugin=" << row.plugin
                            << " action=" << row.action);
            CHECK(row.mutability == Mutability::Irreversible);
        }
    }
}

TEST_CASE("capability catalogue: system_reserved is true only for core_dispatch_capabilities.hpp "
          "rows",
          "[server][dispatch][capability]") {
    for (const auto& source : all_labeled_sources()) {
        for (const auto& row : source.rows) {
            INFO("source=" << source.label << " plugin=" << row.plugin
                            << " action=" << row.action);
            CHECK(row.system_reserved == source.is_core);
        }
    }
}

TEST_CASE("capability catalogue: classify() resolves every declared plugin.action across all six "
          "sources",
          "[server][dispatch][capability]") {
    auto registry = build_registry(all_labeled_sources());
    for (const auto& source : all_labeled_sources()) {
        for (const auto& row : source.rows) {
            INFO("source=" << source.label << " plugin=" << row.plugin
                            << " action=" << row.action);
            auto result = registry.classify(row.plugin, row.action);
            REQUIRE(result.has_value());
            CHECK(result->plugin == row.plugin);
            CHECK(result->action == row.action);
        }
    }
}

TEST_CASE("capability catalogue: a locally-constructed duplicate span makes the registry report "
          "Ambiguous, never first-wins",
          "[server][dispatch][capability]") {
    // Deliberately collides with content_dist's real `content_dist.stage` row
    // — a locally-constructed fixture, never an edit to the fragment itself
    // (this package may not touch capability_decls/*.hpp).
    static constexpr std::array<CommandCapability, 1> kDuplicateStageSpan{{
        {
            .plugin = "content_dist",
            .action = "stage",
            .dispatch_class = DispatchClass::ReadOnly,
            .mutability = Mutability::None,
            .securable = "Response",
            .operation = authz::Operation::Read,
            .risk_tier = authz::RiskTier::Low,
            .system_reserved = false,
        },
    }};

    CommandCapabilityRegistry registry{
        capdecls::plugin_action_catalogue_content_dist(),
        capdecls::plugin_action_catalogue_a(),
        capdecls::plugin_action_catalogue_b(),
        capdecls::plugin_action_catalogue_c(),
        capdecls::plugin_action_catalogue_d(),
        capdecls::core_dispatch_capabilities(),
        std::span<const CommandCapability>(kDuplicateStageSpan),
    };

    auto result = registry.classify("content_dist", "stage");
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == ClassificationError::Ambiguous);

    // A different content_dist action, untouched by the duplicate, still
    // resolves normally — ambiguity is per plugin.action, not registry-wide.
    auto other = registry.classify("content_dist", "list_staged");
    REQUIRE(other.has_value());
    CHECK(other->dispatch_class == DispatchClass::ReadOnly);
}
