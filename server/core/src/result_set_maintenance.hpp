#pragma once

/// @file result_set_maintenance.hpp
/// Background maintenance for scope-walking result sets (Phase 15.G).
///
/// HTTP-agnostic so the server's result-set maintenance thread and unit tests
/// share one code path (cf. preflight `persist_and_maybe_complete`, deployment
/// `advance`).

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server {

class ResultSetStore;
class AuditStore;

/// Run one GC-sweep tick: delete expired unpinned result sets (pinned sets are
/// never swept), then — only when at least one was removed — increment
/// `yuzu_result_set_gc_total` by the count and write a single aggregate
/// `result_set.gc_sweep` audit row under the `__system__` principal (design
/// docs/scope-walking-design.md §9). Returns the number of sets removed.
///
/// `audit` may be null (audit-off, or the audit DB failed to open) — the sweep
/// and the metric still run; only the audit row is skipped.
int run_result_set_gc(ResultSetStore& store, AuditStore* audit, yuzu::MetricsRegistry& metrics);

} // namespace yuzu::server
