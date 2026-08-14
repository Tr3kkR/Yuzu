#pragma once

#include <array>
#include <cstdint>
#include <expected>
#include <initializer_list>
#include <span>
#include <stdexcept>
#include <string_view>

#include "authz_model.hpp"

/// @file command_capability.hpp
/// PR1.9a: the core-owned command capability CLASSIFICATION — the seam
/// `ServerImpl::dispatch_confined` (and every other dispatch chokepoint) will
/// eventually consult to decide a `plugin.action` pair's `DispatchClass` /
/// `Mutability` before it ever reaches an agent. Header-only, zero
/// `server.cpp` involvement: this file defines the vocabulary and the pure
/// lookup, nothing wires it into a live dispatch path yet.
///
/// WHAT THIS IS NOT: a place that DECLARES `plugin.action` rows. The real
/// catalogue ships as several per-group fragment headers under
/// `capability_decls/` (this package owns only the three system-initiated
/// ones — see `capability_decls/core_dispatch_capabilities.hpp`); every other
/// plugin's rows are authored elsewhere and injected into a
/// `CommandCapabilityRegistry` instance at composition time. This header
/// never aggregates them itself — no file-scope singleton, no global
/// registry instance — so a future composition point picks exactly which
/// fragments it wants classified.
namespace yuzu::server {

/// Whether a dispatch reads or changes device state. Deliberately NOT
/// inferred from `authz::Operation` (ADR-0033 §1: "the one typing that must
/// not be self-certified") — a fragment's author sets this explicitly per
/// row.
enum class DispatchClass : uint8_t {
    ReadOnly,
    Mutating,
    Destructive,
};

/// Whether a mutating dispatch can be undone by a subsequent dispatch of the
/// same or a compensating action. `None` pairs with `DispatchClass::ReadOnly`
/// in every seeded row; a `Mutating`/`Destructive` row is `Reversible` or
/// `Irreversible` depending on the actual device-side effect, never inferred
/// from `DispatchClass` alone.
enum class Mutability : uint8_t {
    None,
    Reversible,
    Irreversible,
};

/// One classified `plugin.action` row — view/enum over static storage only,
/// so a `std::span<const CommandCapability>` fragment can live in a
/// `constexpr` array with no static-init-order or heap concern.
struct CommandCapability {
    std::string_view plugin;
    std::string_view action;
    DispatchClass dispatch_class;
    Mutability mutability;
    /// Reuses an existing `RbacStore` securable type (see `rbac_store.cpp`'s
    /// `seed_defaults()` `types[]`) — this struct never mints a new one.
    std::string_view securable;
    authz::Operation operation;
    authz::RiskTier risk_tier;
    /// True for a dispatch the server issues to itself (never a
    /// caller-attributable RBAC decision) — see
    /// `capability_decls/core_dispatch_capabilities.hpp`.
    bool system_reserved{false};
};

/// `CommandCapabilityRegistry::classify`'s failure modes. A miss is
/// `Unclassified`, never a permissive default (ADR-0033 §2: "a missing or
/// unparseable classification means the capability does not exist"). Two
/// fragments independently declaring the same `plugin.action` is
/// `Ambiguous`, never first-wins — a silent first-wins would let whichever
/// fragment header happens to be listed first in the composing
/// `initializer_list` win over a conflicting, equally-valid declaration
/// elsewhere, exactly the kind of un-auditable outcome ADR-0033 §2 rules
/// out.
enum class ClassificationError : uint8_t {
    Unclassified,
    Ambiguous,
};

/// Composes SEVERAL independently-authored `CommandCapability` fragments
/// (the catalogue ships as multiple per-group `capability_decls/*.hpp`
/// headers) into one lookup surface. Constructed once from an
/// `initializer_list` of spans — never a file-scope singleton, so the
/// composition point (not this header) decides which fragments are live.
///
/// `classify` is `const noexcept` and performs no heap allocation: every
/// span it holds is a view over fragment-owned static storage, and the
/// case-insensitive comparison it runs is a plain byte loop, never a
/// `std::string` materialization.
class CommandCapabilityRegistry {
public:
    /// A handful of fragments compose here (five per-group headers plus this
    /// package's own `core_dispatch_capabilities()`); `kMaxSources` is a
    /// generous ceiling, not a tight fit, so an additional fragment group
    /// does not silently overflow it. Exceeding it is a construction-time
    /// programmer error — fail loud via an exception, never silently drop a
    /// fragment (a dropped fragment would make every one of its rows
    /// `Unclassified`, indistinguishable from an honest miss).
    static constexpr std::size_t kMaxSources = 16;

    explicit CommandCapabilityRegistry(
        std::initializer_list<std::span<const CommandCapability>> sources) {
        if (sources.size() > kMaxSources) {
            throw std::invalid_argument(
                "CommandCapabilityRegistry: too many capability sources (raise kMaxSources)");
        }
        for (auto src : sources) {
            sources_[source_count_++] = src;
        }
    }

    /// Case-insensitive on both `plugin` and `action`, matching the
    /// lowercase normalisation `server.cpp` (`:6360-6368`) applies to the
    /// action before dispatch — extended here to the plugin half too, so
    /// `classify("TAR", "Fleet_Snapshot")` and `classify("tar",
    /// "fleet_snapshot")` resolve to the same row regardless of which case a
    /// caller used.
    [[nodiscard]] std::expected<CommandCapability, ClassificationError>
    classify(std::string_view plugin, std::string_view action) const noexcept {
        const CommandCapability* found = nullptr;
        for (std::size_t i = 0; i < source_count_; ++i) {
            for (const auto& cap : sources_[i]) {
                if (ci_equal(cap.plugin, plugin) && ci_equal(cap.action, action)) {
                    if (found != nullptr) {
                        // A second, independent match for the same
                        // plugin.action — never silently first-wins.
                        return std::unexpected(ClassificationError::Ambiguous);
                    }
                    found = &cap;
                }
            }
        }
        if (found == nullptr) {
            return std::unexpected(ClassificationError::Unclassified);
        }
        return *found;
    }

private:
    [[nodiscard]] static constexpr char to_lower_ascii(char c) noexcept {
        return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
    }

    [[nodiscard]] static bool ci_equal(std::string_view a, std::string_view b) noexcept {
        if (a.size() != b.size())
            return false;
        for (std::size_t i = 0; i < a.size(); ++i) {
            if (to_lower_ascii(a[i]) != to_lower_ascii(b[i]))
                return false;
        }
        return true;
    }

    std::array<std::span<const CommandCapability>, kMaxSources> sources_{};
    std::size_t source_count_{0};
};

} // namespace yuzu::server
