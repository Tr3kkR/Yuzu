#pragma once

#include <sqlite3.h>

#include <cstdint>
#include <expected>
#include <mutex>
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
    int pending_count() const;

    std::expected<void, std::string> approve(const std::string& id, const std::string& reviewer,
                                             const std::string& comment);

    std::expected<void, std::string> reject(const std::string& id, const std::string& reviewer,
                                            const std::string& comment);

private:
    std::expected<void, std::string> set_review_status(const std::string& id,
                                                       const std::string& status,
                                                       const std::string& reviewer,
                                                       const std::string& comment);

    sqlite3* db_;
    mutable std::mutex mtx_; // protects all db_ access (G4-UHP-MCP-005)
};

} // namespace yuzu::server
