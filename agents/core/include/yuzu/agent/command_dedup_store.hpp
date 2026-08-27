#pragma once

/**
 * command_dedup_store.hpp -- Durable agent-side command idempotency + outcome replay
 *
 * HA delivery-matrix WS-0 (ADR-2002). Replaces the process-lifetime, in-memory
 * `dedup_current_`/`dedup_previous_` sets (cleared on every reconnect) with a
 * SQLite-backed store, file at {data_dir}/command_dedup.db, that survives an
 * agent restart AND remembers each command's TERMINAL outcome so a duplicate
 * replays the ORIGINAL result rather than a bare REJECTED.
 *
 * Why replay matters: the server's at-least-once delivery (and, later, the WS-1
 * transactional outbox) can redeliver a command whose first terminal ack was
 * lost. Without outcome replay the honest guarantee is only "effect-once,
 * result-maybe-lost": the side effect ran once, but the operator sees REJECTED
 * and the real SUCCESS/output is gone. This store closes that. It is
 * effectively-once, NOT exactly-once (ADR-2002 §Guarantees): a command claimed
 * but not yet resolved when the agent crashes is answered INDETERMINATE
 * (RUNNING) on redelivery and never silently re-executed — re-running a
 * destructive command is the one failure the whole HA design forbids.
 *
 * Lifecycle (one claim resolves exactly once):
 *   claim(id)  -> Claimed   : first sighting; the caller owns the in-flight
 *                             record and MUST resolve it via record_terminal()
 *                             (executed to a terminal outcome) or release()
 *                             (never executed — e.g. the dispatch queue was
 *                             full, a transient condition that must re-attempt).
 *              -> Duplicate : already known — the caller must NOT execute. If
 *                             Terminal, replay `response`; if InFlight, answer
 *                             RUNNING (indeterminate).
 *              -> Error     : store write failed; the caller proceeds WITHOUT
 *                             dedup for this one command (degraded, not wrong).
 *
 * Retention is a clock-free rowid ring (keep the most recent kMaxDedupRows) —
 * deliberately NOT a wall-clock delete, so it sidesteps the clock-guarded-
 * retention hazard (routed concern #2360/#2361) entirely on an endpoint whose
 * clock the user controls. `claimed_at` is diagnostic ONLY and MUST NEVER
 * become a retention cutoff.
 *
 * Thread-safe: a std::mutex serialises every sqlite3* operation. The reader
 * thread calls claim()/release() and the bounded dispatch-pool workers call
 * record_terminal() concurrently; the DB is the synchronisation point.
 * claim()/record_terminal()/release() are noexcept: a store failure degrades
 * durability, it never propagates into the command hot path.
 */

#include <yuzu/plugin.h>

#include <cstdint>
#include <expected>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>

struct sqlite3; // Forward declaration — avoids exposing sqlite3.h in the header

namespace yuzu::agent {

struct CommandDedupError {
    std::string message;
};

/// Durable state of a known command_id.
enum class DedupState {
    InFlight, ///< claimed, not yet resolved (executing now, or crashed mid-execution)
    Terminal, ///< reached a terminal outcome; `response` holds the replayable frame
};

/// Outcome of claim().
enum class ClaimStatus {
    Claimed,   ///< first sighting; caller owns the in-flight record and must resolve it
    Duplicate, ///< already known; see `state` (+ `response` when Terminal)
    Error,     ///< store write failed; caller proceeds WITHOUT dedup for this command
};

struct ClaimResult {
    ClaimStatus status = ClaimStatus::Error;
    DedupState state = DedupState::InFlight; ///< meaningful only when status==Duplicate
    /// Serialized terminal CommandResponse (CommandResponse::SerializeAsString()); populated
    /// only when status==Duplicate && state==Terminal. Bytes are exact (blob column), so an
    /// embedded NUL in the proto survives.
    std::string response;
};

class YUZU_EXPORT CommandDedupStore {
public:
    /**
     * Open (or create) the store at the given path. Sets WAL + busy_timeout=5000
     * and creates the schema if absent. Fails only on an unusable path/DB — the
     * caller treats a failure as "durable dedup unavailable" and runs degraded.
     */
    static std::expected<CommandDedupStore, CommandDedupError>
    open(const std::filesystem::path& db_path);

    ~CommandDedupStore();

    CommandDedupStore(CommandDedupStore&& other) noexcept;
    CommandDedupStore& operator=(CommandDedupStore&& other) noexcept;

    CommandDedupStore(const CommandDedupStore&) = delete;
    CommandDedupStore& operator=(const CommandDedupStore&) = delete;

    /**
     * Atomically claim `command_id` for first-time execution. On Claimed the
     * caller owns the in-flight record; on Duplicate the caller replays/answers
     * per `state`. An empty id or a closed store returns Error (proceed without
     * dedup). noexcept: never throws into the command path.
     */
    ClaimResult claim(std::string_view command_id) noexcept;

    /**
     * Flip a claimed in-flight record to its terminal outcome so a later
     * duplicate replays `serialized_response` (= CommandResponse::SerializeAsString()).
     * Best-effort: a failure only degrades durability (a redelivery may
     * re-execute). Never creates a row (only a prior claim's row is updated) and
     * never throws. No-op on an empty id / closed store.
     */
    void record_terminal(std::string_view command_id,
                         std::string_view serialized_response) noexcept;

    /**
     * Drop a claimed in-flight record that produced NO memoizable outcome (the
     * dispatch queue was full — transient), so a redelivery can be executed.
     * Only deletes a still-in-flight row — never a terminal one. Best-effort +
     * noexcept. No-op on an empty id / closed store.
     */
    void release(std::string_view command_id) noexcept;

    /** Row count (TEST/observability). nullopt on error/closed store. */
    [[nodiscard]] std::optional<std::int64_t> count() const;

    /**
     * The most recent kMaxDedupRows commands are retained; older rows are evicted
     * by rowid (insert order), never by clock. Exceeding this between a command's
     * execution and a possible redelivery is what would let a duplicate
     * re-execute, so it MUST stay well above the server's max retry/outbox
     * horizon (WS-1/WS-3). Substrate-tuned; do not copy the number elsewhere.
     */
    static constexpr std::int64_t kMaxDedupRows = 20000;

private:
    explicit CommandDedupStore(sqlite3* db);

    /// Clock-free ring eviction (keep newest kMaxDedupRows by rowid). Caller holds mu_.
    void prune_locked() noexcept;

    sqlite3* db_{nullptr};
    mutable std::mutex mu_;
    /// Prune cadence: prune after this many claims, so eviction is O(rows) amortised
    /// rather than per-claim. Bounds the table at kMaxDedupRows + kPruneInterval.
    static constexpr std::uint64_t kPruneInterval = 512;
    std::uint64_t claims_since_prune_{0};
};

} // namespace yuzu::agent
