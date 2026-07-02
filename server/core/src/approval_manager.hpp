#pragma once

#include <sqlite3.h>

#include <cstdint>
#include <expected>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server {

struct Approval {
    std::string id;
    std::string definition_id;
    std::string status;
    std::string submitted_by;
    int64_t submitted_at{0};
    std::string reviewed_by;
    int64_t reviewed_at{0};
    std::string review_comment;
    std::string scope_expression;
    // One-time-consumption stamp for the MCP approval-ticket flow (#289 / Issue
    // 13.5): epoch-seconds when an approved ticket was recalled-and-executed,
    // 0 while unconsumed. Additive column (migration v2) — keeps the eventual
    // Postgres port trivial.
    int64_t consumed_at{0};
};

struct ApprovalQuery {
    std::string status;
    std::string submitted_by;
};

class ApprovalManager {
public:
    explicit ApprovalManager(sqlite3* db);
    ~ApprovalManager() = default;

    ApprovalManager(const ApprovalManager&) = delete;
    ApprovalManager& operator=(const ApprovalManager&) = delete;

    void create_tables();

    std::expected<std::string, std::string> submit(const std::string& definition_id,
                                                   const std::string& submitted_by,
                                                   const std::string& scope_expression);

    std::vector<Approval> query(const ApprovalQuery& q = {}) const;

    /// Single-approval lookup by id (read-only). Two callers: the versioned
    /// GET /api/v1/approvals/{id} status_url target (query()'s LIMIT 100 would
    /// false-404 an id that has aged past the top window), and the MCP
    /// approval-ticket recall path (#289), which reads
    /// status/definition_id/scope_expression/consumed_at to validate a ticket
    /// before consuming it. Returns std::nullopt when no row matches; does NOT
    /// touch the lifecycle (submit/approve/reject/consume are elsewhere).
    std::optional<Approval> get(const std::string& id) const;

    /// Newest PENDING approval matching (definition_id, submitted_by,
    /// scope_expression), or nullopt. The MCP approval-ticket mint dedup key
    /// (#289 / governance UP-1): reusing an extant pending ticket makes the mint
    /// idempotent and stops a supervised token flooding the global pending cap.
    std::optional<Approval> find_pending(const std::string& definition_id,
                                         const std::string& submitted_by,
                                         const std::string& scope_expression) const;

    int pending_count() const;

    std::expected<void, std::string> approve(const std::string& id, const std::string& reviewer,
                                             const std::string& comment);

    std::expected<void, std::string> reject(const std::string& id, const std::string& reviewer,
                                            const std::string& comment);

    /// Atomically consume an APPROVED, not-yet-consumed approval as a one-time
    /// MCP ticket (#289). Returns ok() iff THIS call transitioned consumed_at
    /// 0→now — the CAS (`WHERE status='approved' AND consumed_at=0 RETURNING 1`)
    /// carries the match signal in the step return code, so there is no
    /// `sqlite3_changes()` race on the shared FULLMUTEX connection (#1033). A
    /// replay of an already-consumed ticket, or an absent/non-approved id,
    /// returns unexpected. The caller validates definition_id + args BEFORE
    /// calling; this method guards the double-consume (concurrent-recall) race so
    /// a mutating tool executes at most once per ticket.
    std::expected<void, std::string> consume_ticket(const std::string& id);

private:
    std::expected<void, std::string> set_review_status(const std::string& id,
                                                       const std::string& status,
                                                       const std::string& reviewer,
                                                       const std::string& comment);

    sqlite3* db_;
    mutable std::mutex mtx_; // protects all db_ access (G4-UHP-MCP-005)
};

} // namespace yuzu::server
