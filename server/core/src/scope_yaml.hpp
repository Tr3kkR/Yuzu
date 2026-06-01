#pragma once

#include <optional>
#include <string>
#include <vector>

namespace yuzu::server {

// Scope-walking YAML DSL surface (PR-E, design docs/scope-walking-design.md §7).
//
// A `spec.scope:` block may carry a `fromResultSet:` reference (a result-set id
// or per-operator alias) and/or a `selector:` (platform + tags), composed with
// AND. This module parses that block, validates the design's rules, and lowers
// it to a scope-engine expression string the existing parser/resolver already
// consume (scope_engine.cpp `from_result_set:` / `ostype` / `EXISTS tag:`).
//
// Resolution is lazy: lowering produces a string only; result-set membership is
// resolved at dispatch by AgentRegistry::evaluate_scope. A definition carrying a
// `fromResultSet:` that has since expired is still valid YAML.

/// Parsed `spec.scope` block. All fields default to "absent".
struct ScopeBlock {
    bool has_from_result_set{false};
    std::string from_result_set; // raw value: a canonical `rs_<...>` id or an alias
    bool has_selector{false};
    std::string selector_platform;          // selector.platform (e.g. "windows")
    std::vector<std::string> selector_tags; // selector.tags (presence-checked)
};

/// Parse the `spec.scope` block out of a full definition/policy `yaml_source`.
/// A scalar `scope:` (a raw scope-engine expression) yields an empty ScopeBlock
/// — callers handle the scalar form separately for backward compatibility.
ScopeBlock parse_scope_block(const std::string& yaml_source);

/// Enforce the design §7 rules when `fromResultSet` is present:
///   1. `fromResultSet` + `assignment.managementGroups` is forbidden.
///   2. `fromResultSet` requires `assignment.mode` to be `static` (reject
///      `dynamic`; an omitted mode defaults to static and is accepted).
/// Also rejects an empty / over-long `fromResultSet` value. `assignment_mode`
/// and `assignment_has_mgmt_groups` are passed in so the caller controls
/// section isolation (these fields live under `spec.assignment`, not `scope`).
/// Returns an error message, or std::nullopt when the block is valid.
std::optional<std::string> validate_scope_block(const ScopeBlock& sb,
                                                const std::string& assignment_mode,
                                                bool assignment_has_mgmt_groups);

/// Lower a (validated) ScopeBlock to a scope-engine expression string, AND-ing
/// the parts: `from_result_set:<ref>`, `ostype == "<platform>"` (platform
/// lower-cased), and `EXISTS tag:<name>` per selector tag. Returns "" for an
/// empty block.
std::string lower_scope_block(const ScopeBlock& sb);

} // namespace yuzu::server
