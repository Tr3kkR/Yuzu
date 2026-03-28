#pragma once

/// @file instruction_db_pool.hpp
/// RAII owner for the shared instructions.db connection used by
/// ExecutionTracker, ApprovalManager, and ScheduleEngine.
/// Fixes G3-ARCH-T2-002 (fragile raw sqlite3* lifetime).

#include <sqlite3.h>

#include <filesystem>

namespace yuzu::server {

/// Owns a WAL-mode sqlite3 connection to instructions.db.
/// Consumers (ExecutionTracker, ApprovalManager, ScheduleEngine) receive
/// the raw pointer via get() but do NOT own it.
/// Declare this member BEFORE the consumer unique_ptrs in the owning class
/// so that consumers are destroyed first.
class InstructionDbPool {
public:
    explicit InstructionDbPool(const std::filesystem::path& db_path);
    ~InstructionDbPool();

    InstructionDbPool(const InstructionDbPool&) = delete;
    InstructionDbPool& operator=(const InstructionDbPool&) = delete;

    /// Returns the raw sqlite3* handle. The caller must not close this.
    [[nodiscard]] sqlite3* get() const noexcept { return db_; }

    /// Returns true if the connection was opened successfully.
    [[nodiscard]] bool is_open() const noexcept { return db_ != nullptr; }

private:
    sqlite3* db_{nullptr};
};

} // namespace yuzu::server
