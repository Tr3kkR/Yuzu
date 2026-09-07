#include "pg_retention_guard.hpp"

#include "pg_exec.hpp"
#include "pg_raii.hpp"

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <charconv>
#include <cstring>
#include <string>
#include <vector>

namespace yuzu::server::pg {

namespace {

std::int64_t to_i64(const char* s) {
    if (s == nullptr)
        return 0;
    std::int64_t v = 0;
    const char* end = s + std::strlen(s);
    auto [p, ec] = std::from_chars(s, end, v);
    return (ec == std::errc{} && p == end) ? v : 0;
}

// Compact, order-stable serialization of the full fact SET — the dedup key
// (part 4). Must include EVERY field, so a change in any one is a new set.
std::string serialize_facts(const audit_retention::Facts& f) {
    std::string s;
    s += "h";
    s += f.has_expired ? '1' : '0';
    s += "w";
    s += f.would_wipe ? '1' : '0';
    s += "s";
    s += f.big_step ? '1' : '0';
    s += "p";
    s += f.prev_unusable ? '1' : '0';
    s += "n";
    s += f.no_anchor ? '1' : '0';
    return s;
}

std::string q(std::string_view sv) { return std::string(sv); }

} // namespace

ClockGuardedPruneOutcome run_clock_guarded_prune(PgPool& pool, const ClockGuardedPruneSpec& spec,
                                                 std::chrono::milliseconds acquire_timeout) {
    ClockGuardedPruneOutcome out;
    // Threaded out of the lambda so the post-commit fields survive it.
    bool skipped_lock = false;
    bool declined = false;
    int deleted = 0;
    audit_retention::Anomaly anomaly = audit_retention::Anomaly::None;

    const bool ok = pool.with_txn_for(acquire_timeout, [&](PGconn* conn) -> bool {
        // SINGLE-WRITER: the advisory lock is the FIRST in-txn statement, so the
        // whole probe-decide-delete is serialised fleet-wide. try-and-skip: a
        // replica that loses the race skips this tick (the winner drains + moves
        // the anchor); a miss retries next cadence, far inside the window.
        pg::PgResult lk = pg::exec_params(
            conn, ("SELECT pg_try_advisory_xact_lock(" + q(spec.advisory_lock_key) + ")").c_str(),
            std::vector<std::string>{});
        if (lk.status() != PGRES_TUPLES_OK || PQntuples(lk.get()) != 1) {
            spdlog::error("clock_guarded_prune[{}]: advisory-lock query failed: {}", spec.store_label,
                          PQerrorMessage(conn));
            return false;
        }
        if (std::strcmp(PQgetvalue(lk.get(), 0, 0), "t") != 0) {
            skipped_lock = true;
            return true; // another replica holds the prune lock this tick
        }

        // Read "now" in the column's unit ONCE from Postgres (the shared clock,
        // #3715 — never a replica's system_clock), and bind it everywhere below.
        pg::PgResult now_res =
            pg::exec_params(conn, ("SELECT " + q(spec.now_expr)).c_str(), std::vector<std::string>{});
        if (now_res.status() != PGRES_TUPLES_OK || PQntuples(now_res.get()) != 1) {
            spdlog::error("clock_guarded_prune[{}]: now read failed: {}", spec.store_label,
                          PQerrorMessage(conn));
            return false;
        }
        const std::int64_t now_unit = to_i64(PQgetvalue(now_res.get(), 0, 0));
        const std::int64_t cutoff = now_unit - spec.retention_window;
        const std::int64_t future_ceiling = now_unit + spec.implausibility_bound;

        // Part 2 — persisted reading.
        pg::PgResult anchor_res = pg::exec_params(
            conn, ("SELECT value FROM " + q(spec.meta_table) + " WHERE key=$1").c_str(),
            std::vector<std::string>{q(spec.anchor_key)});
        if (anchor_res.status() != PGRES_TUPLES_OK) {
            spdlog::error("clock_guarded_prune[{}]: anchor read failed: {}", spec.store_label,
                          PQerrorMessage(conn));
            return false;
        }
        const bool have_anchor = PQntuples(anchor_res.get()) > 0;
        const std::int64_t last_pass_now = have_anchor ? to_i64(PQgetvalue(anchor_res.get(), 0, 0)) : 0;
        // Part 3 — sanitise: below the plausible floor is unusable, not absent.
        const bool prev_unusable = have_anchor && last_pass_now < spec.min_plausible_reading;

        // Re-anchor BEFORE the probes (rolled back with the whole txn on any
        // later failure) so a decline still advances the comparison point and a
        // poisoned value self-heals — matches the reconciler / audit_store.
        if (pg::exec_params(conn,
                            ("INSERT INTO " + q(spec.meta_table) +
                             " (key, value) VALUES ($1, $2) "
                             "ON CONFLICT (key) DO UPDATE SET value=excluded.value")
                                .c_str(),
                            std::vector<std::string>{q(spec.anchor_key), std::to_string(now_unit)})
                .status() != PGRES_COMMAND_OK) {
            spdlog::error("clock_guarded_prune[{}]: anchor stamp failed: {}", spec.store_label,
                          PQerrorMessage(conn));
            return false;
        }

        // Durable bootstrap-settled marker (part 6 carrier — NOT derived from the
        // anchor, which is stamped every attempt).
        pg::PgResult settled_res = pg::exec_params(
            conn, ("SELECT 1 FROM " + q(spec.meta_table) + " WHERE key=$1").c_str(),
            std::vector<std::string>{q(spec.settled_key)});
        if (settled_res.status() != PGRES_TUPLES_OK) {
            spdlog::error("clock_guarded_prune[{}]: settled read failed: {}", spec.store_label,
                          PQerrorMessage(conn));
            return false;
        }
        const bool bootstrap_settled = PQntuples(settled_res.get()) > 0;

        // Part 1 — probe by OUTCOME. total_datable excludes implausibly-future
        // rows (one forward-skewed row otherwise disarms would_wipe forever).
        pg::PgResult counts = pg::exec_params(
            conn,
            ("SELECT COUNT(*) FILTER (WHERE " + q(spec.ts_column) + " <= $1::bigint), "
             "COUNT(*) FILTER (WHERE " + q(spec.ts_column) + " < $2::bigint) FROM " +
             q(spec.target_table))
                .c_str(),
            std::vector<std::string>{std::to_string(future_ceiling), std::to_string(cutoff)});
        if (counts.status() != PGRES_TUPLES_OK || PQntuples(counts.get()) != 1) {
            spdlog::error("clock_guarded_prune[{}]: counts probe failed: {}", spec.store_label,
                          PQerrorMessage(conn));
            return false;
        }
        const std::int64_t total_datable = to_i64(PQgetvalue(counts.get(), 0, 0));
        const std::int64_t expired = to_i64(PQgetvalue(counts.get(), 0, 1));
        const bool has_expired = expired > 0;
        const bool would_wipe = has_expired && expired >= total_datable;

        const audit_retention::Facts facts{
            .has_expired = has_expired,
            .would_wipe = would_wipe,
            .big_step = have_anchor &&
                        audit_retention::moved_at_least(last_pass_now, now_unit, spec.big_step_floor),
            .prev_unusable = prev_unusable,
            // Part 6: Decline surfaces a from-boot missing anchor (with data) as
            // NoAnchor; Proceed never sets it (regenerable data — a decline buys
            // nothing).
            .no_anchor = spec.missing_anchor == MissingAnchorPolicy::Decline && !bootstrap_settled,
        };
        anomaly = audit_retention::classify(facts);
        const std::string facts_str = serialize_facts(facts);

        pg::PgResult last_facts_res = pg::exec_params(
            conn, ("SELECT value FROM " + q(spec.meta_table) + " WHERE key=$1").c_str(),
            std::vector<std::string>{q(spec.facts_key)});
        if (last_facts_res.status() != PGRES_TUPLES_OK) {
            spdlog::error("clock_guarded_prune[{}]: last-facts read failed: {}", spec.store_label,
                          PQerrorMessage(conn));
            return false;
        }
        const std::string last_facts =
            PQntuples(last_facts_res.get()) > 0 ? PQgetvalue(last_facts_res.get(), 0, 0) : std::string();

        // Verdict reached — settle the bootstrap marker HERE (every earlier
        // return false rolls back, leaving the trigger armed for the next pass).
        if (!bootstrap_settled &&
            pg::exec_params(conn,
                            ("INSERT INTO " + q(spec.meta_table) +
                             " (key, value) VALUES ($1, '1') ON CONFLICT (key) DO NOTHING")
                                .c_str(),
                            std::vector<std::string>{q(spec.settled_key)})
                    .status() != PGRES_COMMAND_OK) {
            spdlog::error("clock_guarded_prune[{}]: settle failed: {}", spec.store_label,
                          PQerrorMessage(conn));
            return false;
        }

        if (anomaly != audit_retention::Anomaly::None) {
            // Part 4 — decline once per DISTINCT fact set; an identical repeat
            // drains (paced by the cap) so a legitimately all-expired table
            // still ages out.
            if (facts_str != last_facts) {
                if (pg::exec_params(conn,
                                    ("INSERT INTO " + q(spec.meta_table) +
                                     " (key, value) VALUES ($1, $2) "
                                     "ON CONFLICT (key) DO UPDATE SET value=excluded.value")
                                        .c_str(),
                                    std::vector<std::string>{q(spec.facts_key), facts_str})
                        .status() != PGRES_COMMAND_OK) {
                    spdlog::error("clock_guarded_prune[{}]: anomaly record failed: {}",
                                  spec.store_label, PQerrorMessage(conn));
                    return false;
                }
                declined = true;
                return true; // commit anchor + settle + anomaly record; delete nothing
            }
            // suppressed repeat — fall through to the capped drain
        } else if (!last_facts.empty()) {
            // A clean pass after an anomaly — clear the fact set so the next
            // genuine anomaly is not read as a repeat of this one.
            if (pg::exec_params(conn,
                                ("DELETE FROM " + q(spec.meta_table) + " WHERE key=$1").c_str(),
                                std::vector<std::string>{q(spec.facts_key)})
                    .status() != PGRES_COMMAND_OK) {
                spdlog::error("clock_guarded_prune[{}]: anomaly clear failed: {}", spec.store_label,
                              PQerrorMessage(conn));
                return false;
            }
        }

        if (!has_expired)
            return true; // nothing to delete — commit the anchor/settle above

        // Part 5 — cap unconditionally (Postgres has no DELETE ... LIMIT; the
        // ctid-subselect is the standard capped-delete idiom).
        pg::PgResult del = pg::exec_params(
            conn,
            ("DELETE FROM " + q(spec.target_table) + " WHERE ctid IN (SELECT ctid FROM " +
             q(spec.target_table) + " WHERE " + q(spec.ts_column) +
             " < $1::bigint LIMIT $2::integer) RETURNING 1")
                .c_str(),
            std::vector<std::string>{std::to_string(cutoff), std::to_string(spec.cap_per_pass)});
        if (del.status() != PGRES_TUPLES_OK) {
            spdlog::error("clock_guarded_prune[{}]: capped delete failed: {}", spec.store_label,
                          PQerrorMessage(conn));
            return false;
        }
        deleted = PQntuples(del.get());
        return true;
    });

    if (!ok) {
        out.error = true;
        return out;
    }
    out.skipped_lock = skipped_lock;
    out.declined = declined;
    out.anomaly = anomaly;
    out.deleted = deleted;
    return out;
}

} // namespace yuzu::server::pg
