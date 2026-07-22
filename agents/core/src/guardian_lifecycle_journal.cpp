#include "guardian_lifecycle_journal.hpp"

#include "guardian_spark_runtime.hpp" // GuardianSparkRuntime::try_page_batch + OutboxEntry

#include <yuzu/agent/kv_store.hpp>
#include <yuzu/agent/plugin_loader.hpp> // kReservedPluginNames - for the pin below

#include <spdlog/spdlog.h>

#include <algorithm>
#include <cassert>
#include <chrono>
#include <format>
#include <limits>
#include <random>
#include <set>
#include <unordered_set>
#include <vector>

namespace yuzu::agent {

// #2303 C2. The journal namespace MUST be a reserved plugin name: yuzu_ctx_storage_* keys
// KvStore by the plugin's own declared name on the SAME connection this journal borrows, so a
// plugin able to claim it could read, delete, or forge the audit records replayed over the
// authenticated stream. plugin_loader.hpp (include/) cannot include guardian_journal_format.hpp
// (src/) without inverting the layering, so the literal is duplicated there and pinned here -
// this file is the only translation unit that sees both. Same bind-or-drift pattern as the
// kNetTag* heartbeat-key asserts.
static_assert(std::ranges::find(kReservedPluginNames, kJournalNamespace) !=
                  kReservedPluginNames.end(),
              "kJournalNamespace must appear in kReservedPluginNames (plugin_loader.hpp) - "
              "otherwise a native plugin can claim the journal's kv_store namespace");

namespace {

std::string make_journal_nonce() {
    std::random_device rd;
    const std::uint64_t v = (static_cast<std::uint64_t>(rd()) << 32) ^ static_cast<std::uint64_t>(rd());
    return std::format("{:016x}", v);
}

// Worst-case serialized byte count of a string field once JSON-escaped: a control char
// (< 0x20) can expand to \u00XX (6 bytes), '"' and '\\' to 2 (review M7). Fields are validated
// UTF-8, so multibyte code points pass through 1:1.
std::size_t json_escaped_bytes(std::string_view s) {
    std::size_t n = 0;
    for (unsigned char c : s)
        n += (c < 0x20) ? 6 : ((c == '"' || c == '\\') ? 2 : 1);
    return n;
}

// A byte estimate for one record's JSON entry, used to decide when to start a new batch. It
// must never UNDER-count (a batch estimated below kMaxJournalBatchBytes must actually serialize
// below it), so each field is counted at its worst-case escaped size.
std::size_t est_entry_bytes(const JournalRecord& r) {
    return json_escaped_bytes(r.rule_id) + json_escaped_bytes(r.event_id) +
           json_escaped_bytes(r.kind) + json_escaped_bytes(r.guard_type) +
           json_escaped_bytes(r.rule_name) + 160; // JSON keys/punctuation + worst-case number
                                                   // digits (review round 2 MINOR-2)
}

} // namespace

GuardianLifecycleJournal::GuardianLifecycleJournal(KvStore* kv)
    : kv_(kv), boot_nonce_(make_journal_nonce()) {
    // rev-4.1 #9 / review M8: confirm the durability precondition on the BUILT binary. SOFT warn
    // on != FULL (2); NEVER abort, since config drift must not kill an agent.
    if (kv_) {
        const int sync = kv_->pragma_synchronous();
        if (sync != 2)
            spdlog::warn("Guardian journal: kv_store PRAGMA synchronous = {} (expected 2/FULL); "
                         "power-loss durability of the lifecycle journal is not guaranteed",
                         sync);
    }
    seed_size_gauges_();
}

// #2303 C1. The size gauges are what the write-side ceiling in persist() reads, but they were
// only ever RECONSTRUCTED by a successful prune scan - they started at 0 on every construction.
// A journal that survived a restart was therefore invisible to the ceiling until the first
// successful prune, and start_local()'s arm-record flush persists BEFORE any tick or reconnect
// prune runs, so the gauge-at-zero window opened on EVERY restart. A crash-loop over an already
// full journal could then grow the SHARED kv_store.db past the "hard" ceiling, taking unrelated
// plugins' KV with it. Seeding here closes the window: the ceiling is honest from the first
// write of the process.
//
// namespace_size() is the aggregate probe rather than list_entries() on purpose - the hard
// ceiling is 2x the soft caps (2000 batches / 64 MiB), and materializing that to learn two
// numbers would be a multi-tens-of-MiB allocation on an endpoint at startup.
//
// Probe FAILURE is the interesting case, and it fails CLOSED: an un-scannable journal means we
// cannot bound what is already on disk, so we assume-at-ceiling and let persist() reject +
// count write_capacity_rejected_ until a successful prune reconstructs the true size. Records
// already staged are retried, not dropped, as long as a prune EVENTUALLY succeeds; only a
// SUSTAINED double-failure (this probe AND every subsequent prune both failing) past the bounded
// RAM staging (kMaxPendingJournalRecords) drops the oldest - and that drop is counted, not silent
// (journal_stage_dropped). Fail-OPEN here would be the strictly worse trade: it is precisely the
// un-scannable journal (chronic SQLITE_BUSY, a corrupt page) whose size we have least right to
// assume is zero.
void GuardianLifecycleJournal::seed_size_gauges_() {
    // #2303 UP-7: this is the ONLY non-RMW gauge writer (an absolute .store()). It is race-free
    // ONLY because it runs once, in the ctor, before the journal pointer is published to any
    // thread. A future re-seed while persist/prune threads are live would reintroduce the exact
    // lost-update class this fix removes. The call-once assert pins that contract in debug builds.
    assert(!size_seeded_.exchange(true, std::memory_order_relaxed) &&
           "seed_size_gauges_ must run once, at construction, before any thread sees the journal");
    if (!kv_)
        return; // no store to borrow: persist() writes nothing, so the gauges are moot

    auto sz = kv_->namespace_size(kJournalNamespace, kBatchKeyPrefix);
    if (!sz) {
        // Fail CLOSED at the ceiling. This is a CONSERVATIVE seed that a later successful
        // prune scan REBASES back to on-disk reality (rebase-as-delta) - do not treat it as
        // permanent, or an agent that boots once with a busy/corrupt kv_store.db would brick
        // its journal writes forever.
        journal_batch_count_.store(static_cast<std::int64_t>(hard_max_batches_),
                                   std::memory_order_relaxed);
        journal_bytes_.store(static_cast<std::int64_t>(hard_max_bytes_), std::memory_order_relaxed);
        spdlog::warn("Guardian journal: could not size the on-disk journal at startup ({}); "
                     "assuming AT the write ceiling until a successful prune - lifecycle records "
                     "will be staged in RAM and retried, not written",
                     sz.error().message);
        return;
    }
    journal_batch_count_.store(static_cast<std::int64_t>(sz->count), std::memory_order_relaxed);
    journal_bytes_.store(static_cast<std::int64_t>(sz->bytes), std::memory_order_relaxed);
    if (sz->count > 0)
        spdlog::debug("Guardian journal: resuming over {} batch(es) / {} bytes already on disk",
                      sz->count, sz->bytes);
}

std::size_t
GuardianLifecycleJournal::persist(std::span<const std::shared_ptr<const JournalRecord>> pending,
                                  std::vector<PersistedBatch>* out_batches) {
    if (!kv_ || pending.empty())
        return 0;

    // `written` is the count of leading pending SLOTS durably committed. The caller passes it
    // to erase_persisted_prefix, so it must map 1:1 to the front of `pending`; snapshot never
    // stages a nullptr, so a slot count equals a record count (N5). It advances ONLY after a
    // batch is confirmed Inserted (its terminal COMMIT surfaced by insert_if_absent, B1).
    std::size_t written = 0;
    std::size_t i = 0;
    while (i < pending.size()) {
        // Build + write ONE batch. Every step below allocates (vector copies, JSON dump, key
        // format); a throw must NOT lose the `written` count for batches already committed, so
        // the whole batch is firewalled and treated as a write failure (review B4). The rest
        // stay pending for the maintenance-tick retry.
        try {
            std::vector<JournalRecord> entries;
            std::size_t batch_bytes = 64; // envelope overhead
            std::size_t consumed = 0;     // pending slots this batch spans (incl. any skipped)
            while (i + consumed < pending.size() && entries.size() < kMaxJournalEntriesPerBatch) {
                const auto& rec = pending[i + consumed];
                if (!rec) { // invariant: never nullptr; belt-and-suspenders so a stray slot is
                    ++consumed; // still consumed (erased), never dereferenced
                    continue;
                }
                const std::size_t rb = est_entry_bytes(*rec);
                if (!entries.empty() && batch_bytes + rb > kMaxJournalBatchBytes)
                    break; // this record starts the next batch
                entries.push_back(*rec);
                batch_bytes += rb;
                ++consumed;
            }
            if (entries.empty()) { // only nullptr slots in this span (should never happen)
                i += consumed;
                written = i;
                continue;
            }

            const std::int64_t ts_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                           std::chrono::system_clock::now().time_since_epoch())
                                           .count();
            const std::string value = serialize_journal_batch(ts_ms, entries);
            const std::string key = journal_batch_key(boot_nonce_, batch_seq_);

            // Write-side ceiling (review UP-1): retention (prune) is the only shrink path and it
            // can fail indefinitely (chronic SQLITE_BUSY / a corrupt page). Without a write-side
            // cap, a failing prune lets the journal grow without bound and exhaust the SHARED
            // kv_store.db - taking down UNRELATED plugins' KV. This hard ceiling (default 2x the
            // retention caps) sits ABOVE the soft retention caps prune trims to - so normal
            // between-tick overshoot is never rejected - and is deliberately DECOUPLED from the
            // retention caps (a test may shrink retention to force eviction without also blocking
            // the writes that set that up). The cached size (set exactly by each prune scan,
            // incremented below on a durable write) drives it: reject + count + circuit-break,
            // leaving the records in the bounded RAM staging.
            const std::int64_t raw_count = journal_batch_count_.load(std::memory_order_relaxed);
            const std::int64_t raw_bytes = journal_bytes_.load(std::memory_order_relaxed);
            // #2303 UP-2 (Sol review): a NEGATIVE gauge means the cached size is UNTRUSTED (an
            // over-subtraction bug). clamp_nonneg would floor it to 0 and ADMIT the write -
            // fail-OPEN, growing the shared kv_store.db on the strength of a wrong size. Fail
            // CLOSED instead: refuse + count, and let a later prune rebase restore a trusted size
            // (writes then resume). This cannot occur in correct operation - every lc: row is
            // counted - so it never blocks a healthy agent; it is a defense-in-depth tripwire
            // against a future accounting regression, not a live code path.
            if (raw_count < 0 || raw_bytes < 0) {
                gauge_underflow_.fetch_add(1, std::memory_order_relaxed);
                return written; // untrusted size: defer to RAM staging until a prune rebases
            }
            if (clamp_nonneg(raw_count) + 1 > hard_max_batches_ ||
                clamp_nonneg(raw_bytes) + value.size() > hard_max_bytes_) {
                write_capacity_rejected_.fetch_add(1, std::memory_order_relaxed);
                return written; // the rest stay pending; a later prune shrinks, then the tick retries
            }

            KvInsert result;
            if (inject_skip_writes_.load(std::memory_order_relaxed) > 0) {
                inject_skip_writes_.fetch_sub(1, std::memory_order_relaxed); // test-only: let this one write
                result = kv_->insert_if_absent(kJournalNamespace, key, value);
            } else if (inject_fail_writes_.load(std::memory_order_relaxed) > 0) {
                inject_fail_writes_.fetch_sub(1, std::memory_order_relaxed); // test-only fault
                result = KvInsert::Error;
            } else {
                result = kv_->insert_if_absent(kJournalNamespace, key, value);
            }
            switch (result) {
            case KvInsert::Inserted:
                ++batch_seq_;
                batches_written_.fetch_add(1, std::memory_order_relaxed);
                // Track the live-size gauges so the write-side ceiling above and the operator
                // size signal stay honest between prune scans (review UP-1 / sre). fetch_add
                // (not an absolute store) so a concurrent prune rebase never loses this
                // increment (#2303 gauge-race fix).
                //
                // ORDERING IS LOAD-BEARING (#2303 UP-4): this fetch_add MUST stay AFTER the
                // durable insert_if_absent above. That ordering is what makes a prune rebase
                // racing this persist an OVER-count (the row is on disk, seen by the scan, and
                // also fetch_add'd -> ceiling tightens, safe) rather than an UNDER-count (gauge
                // bumped for a row not yet on disk -> ceiling loosens -> fail-open). Do NOT
                // reorder to "reserve then write".
                journal_batch_count_.fetch_add(1, std::memory_order_relaxed);
                journal_bytes_.fetch_add(static_cast<std::int64_t>(value.size()),
                                         std::memory_order_relaxed);
                i += consumed;
                written = i; // count the durably-committed slots BEFORE building the best-effort
                             // provenance record, so a throw there loses only the sent-label
                             // back-fill (best-effort), not by re-persisting a duplicate batch
                             // under a new key next retry (review round 2 MINOR-3).
                if (out_batches) { // provenance back-fill source (review M3)
                    PersistedBatch pb{key, {}};
                    pb.event_ids.reserve(entries.size());
                    for (const auto& e : entries)
                        pb.event_ids.push_back(e.event_id);
                    out_batches->push_back(std::move(pb));
                }
                break;
            case KvInsert::Exists:
                // ~2^-64 boot-nonce+seq collision: DON'T overwrite. Count it, advance the seq
                // past the occupied key, and circuit-break (the tick retries the rest).
                key_collisions_.fetch_add(1, std::memory_order_relaxed);
                ++batch_seq_;
                write_failures_.fetch_add(1, std::memory_order_relaxed);
                return written;
            case KvInsert::Error:
                // Per-push circuit breaker: stop at the first write failure so one bad write
                // can't stall apply_rules for 500 x the 5 s busy timeout. Keep the seq (nothing
                // was written to this key), leave the rest pending.
                write_failures_.fetch_add(1, std::memory_order_relaxed);
                return written;
            }
        } catch (...) {
            // A build/serialize allocation threw: batches before this one are durably written,
            // so count a write failure and return `written`; the caller erases exactly that
            // prefix and the rest (incl. this batch) stay pending for the tick retry (B4).
            write_failures_.fetch_add(1, std::memory_order_relaxed);
            return written;
        }
    }
    return written;
}

JournalPruneStats GuardianLifecycleJournal::prune(std::int64_t now_ms) {
    // Serialise retention against paging (review round 2 MINOR-1): the maintenance tick calls
    // prune() bare while a concurrent reconnect-hook page_into_window may be renaming/deleting
    // the same keys under paging_mutex_. Without this, the loser of a race falsely counts
    // quarantine_failures / prune_failures on operator-facing integrity counters.
    std::lock_guard<std::mutex> pg{paging_mutex_};
    return prune_locked_(now_ms);
}

JournalPruneStats GuardianLifecycleJournal::prune_locked_(std::int64_t now_ms) {
    JournalPruneStats stats;
    if (!kv_)
        return stats;

    // Shutdown began: a prune pass is a full-journal scan plus one KvStore read per evicted key,
    // each able to block on the 5 s busy timeout. Bail BEFORE starting so the drain-worker join
    // in GuardianEngine::stop() is not held up by retention work nobody will observe (C0 #2298).
    // read_ok stays false, so the page-side boot barrier does NOT latch on a stop-aborted pass.
    if (stopping_.load(std::memory_order_acquire))
        return stats;

    if (inject_fail_reads_.load(std::memory_order_relaxed) > 0) { // test-only injected read fault
        inject_fail_reads_.fetch_sub(1, std::memory_order_relaxed);
        prune_failures_.fetch_add(1, std::memory_order_relaxed);
        return stats; // read_ok stays false, same as a real list_entries failure
    }
    // #2303 gauge-race fix (rebase-as-delta). Snapshot the gauge count IMMEDIATELY before the
    // scan; after the scan we fetch_add the SIGNED difference (scanned-actual minus this
    // snapshot) rather than storing an absolute. A concurrent persist() fetch_add landing
    // between this load and the rebase is preserved (both are RMW on the same atomic), where
    // an absolute store would silently clobber it and under-count the write ceiling. This is
    // also the sole path that walks a fail-closed boot seed back down to reality.
    const std::int64_t pre_count = journal_batch_count_.load(std::memory_order_relaxed);
    const std::int64_t pre_bytes = journal_bytes_.load(std::memory_order_relaxed);

    // TEST-ONLY interleaving seam (#2303 UP-3): fire a simulated concurrent persist AFTER the
    // pre_count snapshot but BEFORE the scan - the window where the inserted row is BOTH seen by
    // list_entries and carries its own fetch_add (the transient double-count). Null in production.
    if (pre_scan_hook_)
        pre_scan_hook_();

    auto rows = kv_->list_entries(kJournalNamespace, kBatchKeyPrefix);
    if (!rows) {
        prune_failures_.fetch_add(1, std::memory_order_relaxed); // read error: fail-safe, retry next pass
        return stats; // read_ok stays false: the boot barrier will NOT latch on a failed scan (M5)
    }
    stats.read_ok = true;

    // Rebase to what the scan actually observed on disk (all lc: rows, parseable or not); the
    // quarantine + eviction below then fetch_sub exactly what they REMOVE, so the gauge lands
    // at the true post-prune size without ever taking an absolute snapshot.
    std::int64_t scanned_bytes = 0;
    for (const auto& row : *rows)
        scanned_bytes += static_cast<std::int64_t>(row.value.size());
    journal_batch_count_.fetch_add(static_cast<std::int64_t>(rows->size()) - pre_count,
                                   std::memory_order_relaxed);
    journal_bytes_.fetch_add(scanned_bytes - pre_bytes, std::memory_order_relaxed);

    // TEST-ONLY interleaving seam: fire a simulated concurrent persist() in the exact window
    // between the rebase and the removal accounting (null in production).
    if (post_scan_hook_)
        post_scan_hook_();

    struct Live {
        std::string key;
        std::int64_t ts_ms;
        std::size_t bytes;
    };
    std::vector<Live> live;
    live.reserve(rows->size());
    for (auto& row : *rows) {
        // Shutdown mid-scan: this loop issues one rename_key per UNPARSEABLE row, so on a
        // corrupted journal it can be up to hard_max_batches_ KvStore writes, each able to
        // block on the 5 s busy timeout. Bailing here is what makes the post-request_stop()
        // exit bounded (#2298 governance sec-M2): GuardianEngine::stop() holds mtx_ across
        // the drain-worker join, so every second spent here blocks dispatch(), journal_stats()
        // and the heartbeat too. Nothing is lost - the gauges were rebased to the scanned
        // reality above, each completed rename already paired with its own fetch_sub, and the
        // next boot re-scans.
        if (stopping_.load(std::memory_order_acquire))
            return stats;
        auto parsed = parse_journal_batch(row.value);
        if (!parsed) {
            // Unparseable → move aside atomically so replay never re-parses it.
            if (kv_->rename_key(kJournalNamespace, row.key, journal_quarantine_key(row.key)) ==
                KvRename::Renamed) {
                quarantined_.fetch_add(1, std::memory_order_relaxed);
                ++stats.quarantined;
                // Left the lc: namespace: subtract it from the rebased gauge (RMW, #2303).
                journal_batch_count_.fetch_sub(1, std::memory_order_relaxed);
                journal_bytes_.fetch_sub(static_cast<std::int64_t>(row.value.size()),
                                         std::memory_order_relaxed);
            } else {
                quarantine_failures_.fetch_add(1, std::memory_order_relaxed);
            }
            continue;
        }
        live.push_back(Live{row.key, parsed->ts_ms, row.value.size()});
    }

    // Oldest-first by (ts_ms, key) - NOT lexical key (the boot-nonce is random) - with batches
    // stamped implausibly far in the FUTURE ordered FIRST, so the count and byte ceilings shed
    // them before they shed real evidence.
    //
    // Without that they are immortal: such a batch can never be "too old", and oldest-first
    // count eviction never reaches it either - so once enough exist (a bad RTC, a VM clone, a
    // hand-edited kv_store.db) every genuine record written afterwards is the one evicted in
    // its place, permanently (#2345 Gate 2 security).
    //
    // Deliberately an ORDERING rule, not an expiry rule. Treating "future" as expired would
    // delete on the strength of the local clock being right, and the failure that actually
    // happens in the field is a clock reading in the PAST (a dead CMOS battery reports 1970),
    // which would make every real batch look future-dated and wipe the journal wholesale - the
    // very outcome the anomaly guard above exists to prevent. Reordering cannot delete anything
    // the count and byte ceilings were not already going to delete; if the clock is wrong
    // enough that every row looks future, they all compare equal here and the ceilings simply
    // trim in key order.
    const std::int64_t future_cutoff = now_ms + kJournalFutureSlackMs;
    const auto order_key = [future_cutoff](const Live& l) {
        return l.ts_ms > future_cutoff ? std::numeric_limits<std::int64_t>::min() : l.ts_ms;
    };
    std::sort(live.begin(), live.end(), [&order_key](const Live& a, const Live& b) {
        const auto ka = order_key(a), kb = order_key(b);
        return ka != kb ? ka < kb : a.key < b.key;
    });

    // now_ms is used directly. An earlier round clamped it upward with the previous pass's
    // reading, on the theory that a BACKWARD clock step stops age eviction, lets the journal
    // climb to its hard write ceiling, and makes it start REFUSING new records. Gate 8b showed
    // that premise is wrong: the count and byte ceilings below are computed with no clock at
    // all, so they hold the journal at max_batches_ regardless of what the clock does, and the
    // rejection ceiling is never reached. What the clamp actually bought was one extra pass of
    // eviction against a reading already known to be bad, on the pass AFTER a correction - so
    // it destroyed in-retention evidence to solve a problem that does not exist. Removed.
    //
    // A backward clock therefore just pauses AGE eviction until it is fixed, which is the safe
    // direction for an audit trail, and a correction takes effect on the very next pass.
    const std::int64_t window_ms = static_cast<std::int64_t>(retention_days_) * 86400 * 1000;
    const std::int64_t min_ts = now_ms - window_ms;

    // "Would this pass age out everything?" - counting only batches that are not stamped in the
    // FUTURE. A plain all_of over every row let a single future-dated batch veto the signal
    // permanently (#2345 Gate 8b UP6-1): one row written with a wrong RTC, or carried in by a
    // VM clone, is never itself expired, and because the count ceiling trims oldest-first it is
    // also immortal - so the guard would be silently disarmed for the life of the endpoint by
    // one bad row. Future-dated rows are excluded from the question rather than allowed to
    // answer it.
    std::size_t datable = 0, expired = 0;
    for (const auto& l : live) {
        if (l.ts_ms > now_ms)
            continue; // future-dated: cannot be "too old", and must not veto the signal
        ++datable;
        if (l.ts_ms < min_ts)
            ++expired;
    }
    const bool would_wipe = datable > 0 && expired == datable;
    const bool big_step = last_prune_now_ms_ != 0 && now_ms - last_prune_now_ms_ > window_ms;
    // Declined ONCE per anomaly. Latching matters: declining every time a pass would wipe the
    // journal means a genuinely long-idle agent never ages anything out at all.
    const bool skip_age = (would_wipe || big_step) && !age_wipe_declined_;
    if (skip_age) {
        clock_jump_skips_.fetch_add(1, std::memory_order_relaxed);
        // The delta is meaningless on the FIRST pass of a process - last_prune_now_ms_ is still
        // zero, so it would print the whole Unix epoch as "the clock moved", in exactly the
        // restarted-VM scenario this detection was redesigned to catch (Gate 8 advisor).
        if (last_prune_now_ms_ == 0)
            spdlog::warn("Guardian journal: the first retention pass after start would age out "
                         "the ENTIRE journal ({} batches); skipping AGE eviction once so a clock "
                         "anomaly cannot delete the audit trail wholesale",
                         live.size());
        else
            spdlog::warn("Guardian journal: this retention pass would age out the ENTIRE journal "
                         "({} batches; clock moved {} ms since the last pass); skipping AGE "
                         "eviction once so a clock anomaly cannot delete the audit trail "
                         "wholesale",
                         live.size(), now_ms - last_prune_now_ms_);
    }
    last_prune_now_ms_ = now_ms;
    std::size_t total_bytes = 0;
    for (const auto& l : live)
        total_bytes += l.bytes;

    std::vector<std::string> evict;
    std::int64_t evicted_bytes = 0; // #2303: bytes to fetch_sub once the delete SUCCEEDS
    std::size_t surviving = live.size();
    // Cap AGE evictions per pass (#2345 Gate 5 CH-5). The count and byte caps are self-limiting
    // - they only ever trim the excess over a fixed ceiling - but age is absolute, so a single
    // clock reading can mark the entire journal expired at once. Bounding the pass turns that
    // into a paced ageing-out. Not applied to the count/byte caps: those must be free to bring
    // an over-ceiling journal back under its ceiling in one pass, which is a hard storage bound.
    std::size_t age_evictions = 0;
    std::size_t age_candidates = 0;
    for (const auto& l : live) { // oldest first: age is absolute, count/bytes trim from this end
        const bool too_many = surviving > max_batches_;
        const bool too_big = total_bytes > max_bytes_;
        if (!skip_age && l.ts_ms < min_ts)
            ++age_candidates;
        const bool too_old =
            !skip_age && l.ts_ms < min_ts && age_evictions < kMaxAgeEvictionsPerPass;
        if (too_old)
            ++age_evictions;
        if (too_old || too_many || too_big) {
            evict.push_back(l.key);
            evicted_bytes += static_cast<std::int64_t>(l.bytes);
            --surviving;
            total_bytes -= l.bytes;
        }
    }

    // The cutoff replay shares (#2345 Gate 5) is INT64_MIN - "nothing is too old to replay" -
    // for as long as this pass is working off a backlog of expired batches, whether because it
    // declined the wipe or because the per-pass cap left some behind. That is what makes the
    // paced deletion buy anything at all: without it, replay skips exactly the batches retention
    // is about to delete and the pacing would only slow the deletion, shipping nothing
    // (#2345 Gate 8 S3/UP5-3). It does not make delivery likely - deletion still outruns replay
    // about five to one at the current cap and refill rate (#2364) - it makes it possible. It
    // costs a bounded burst of redelivery, since sent-but-expired batches become candidates too
    // - bounded by the per-pass batch cap and the paging rate limiter, and the server de-dupes
    // on event_id.
    const bool pacing = skip_age || age_candidates > age_evictions;
    // Publish the CONSERVATIVE cutoff first and tighten it only once the delete below has
    // actually happened (#2345 round 7, Sol). Committing min_ts here and then failing the
    // delete stranded the rows it named: still present on disk, but classified expired by
    // replay, so neither shipped nor removed until some later pass succeeded. Repeated
    // failures alternated stranded and replayable passes while inflating a counter documented
    // to mean the endpoint's clock moved. INT64_MIN means "nothing is too old to replay",
    // which errs toward redelivery - free, since the server de-dupes on event_id.
    last_age_cutoff_ = std::numeric_limits<std::int64_t>::min();
    pruned_cutoff_valid_ = true;
    // Hold the "already declined" latch for as long as this anomaly is still being worked off,
    // not merely for the pass after the decline. Clearing it on the first accepting pass made a
    // large backlog re-trip the guard on alternate passes: it still converged, but at half rate
    // and while incrementing a counter documented to mean "this endpoint's clock moved", which
    // would have an operator chasing a second anomaly that never happened.
    //
    // Hold the latch only while an anomaly BACKLOG is still being worked off - which is what
    // `pacing` already means. Setting it from `age_candidates > 0` disarmed the guard after any
    // pass that aged out even one batch, and a live agent past its retention horizon has such a
    // pass constantly; a real jump arriving next would then evict unguarded, with no warn line
    // and no clock_jump_skips increment. Four Gate 8b reviewers found this independently, and
    // the correct expression was already computed one line above.
    age_wipe_declined_ = pacing;

    // Shutdown immediately before the pass's heaviest write: del_keys is one transaction over
    // the whole evict set and is the single longest KvStore call prune makes (#2298 governance
    // cs-2 - the stopping_ gates must PRECEDE the heavy calls, not merely straddle them).
    // Skipping it retains the batches, which is the safe direction for an audit journal; the
    // gauges already reflect on-disk reality via the rebase, so nothing is left inconsistent.
    if (stopping_.load(std::memory_order_acquire))
        return stats;

    if (!evict.empty()) {
        // del_keys is one all-or-nothing transaction: a 0 return with a non-empty evict list is
        // a delete FAILURE (review M4). Only AFTER a successful delete do we count the eviction,
        // classify each by its (still-present) sent-label, and let the label-GC run against the
        // now-correct survivor set. On failure the batches + labels are left intact and retried.
        int n;
        if (inject_fail_deletes_.load(std::memory_order_relaxed) > 0) { // test-only injected del fault
            inject_fail_deletes_.fetch_sub(1, std::memory_order_relaxed);
            n = 0;
        } else {
            n = kv_->del_keys(kJournalNamespace, evict);
        }
        if (n <= 0) {
            prune_failures_.fetch_add(1, std::memory_order_relaxed);
            // Nothing was evicted. Under rebase-as-delta the gauge already reflects the scanned
            // on-disk reality and we subtracted only what we actually removed, so a failed
            // delete correctly requires NO gauge change (#2303 - the old absolute store here
            // was itself a lost-update site).
            return stats; // do NOT touch survivors' sent-labels this pass
        }
        batches_pruned_.fetch_add(static_cast<std::uint64_t>(n), std::memory_order_relaxed);
        stats.evicted = static_cast<std::size_t>(n);
        // The delete happened, so the rows this cutoff would exclude from replay are genuinely
        // gone. Only a pass with no expired backlog left may tighten it; while one is being
        // worked off, replay must keep considering everything (see `pacing` above).
        if (!pacing)
            last_age_cutoff_ = min_ts;
        // Evicted keys left the lc: namespace: subtract them from the rebased gauge (RMW).
        // Count uses `n` (RETURNING rows), bytes uses evicted_bytes (the whole evict set): the
        // two bases match ONLY because n == evict.size() here. del_keys rolls back on any
        // failure (n==0), and under paging_mutex_ the sole concurrent writer (persist) only
        // INSERTS - no other path deletes an lc: key - so every evicted key is still present at
        // delete time and n can never be a partial 0<n<size. If a future out-of-lock lc:
        // deleter is added, switch bytes to sum only the actually-deleted keys (a rebase heals
        // the skew next scan regardless).
        journal_batch_count_.fetch_sub(static_cast<std::int64_t>(n), std::memory_order_relaxed);
        journal_bytes_.fetch_sub(evicted_bytes, std::memory_order_relaxed);
        for (const auto& key : evict) {
            // Shutdown mid-classification: the eviction itself is already committed and counted;
            // only the best-effort sent/unsent split of the REMAINING keys is skipped, one KvStore
            // read each (C0 #2298 - keeps the drain-worker join prompt on a large evict set).
            // The remainder is left unclassified, so evicted_sent_unacked_ +
            // evicted_without_send_evidence_ can under-count batches_pruned_ after a
            // shutdown. In-memory counters only - no durable evidence is lost - but an
            // operator comparing them across a restart should expect the gap.
            if (stopping_.load(std::memory_order_acquire))
                break;
            // Best-effort classification: a live entry may age out before its batch key exists,
            // so absence of a sent-label != "never sent".
            if (kv_->exists(kJournalNamespace, journal_sent_key_from_batch_key(key)))
                evicted_sent_unacked_.fetch_add(1, std::memory_order_relaxed);
            else
                evicted_without_send_evidence_.fetch_add(1, std::memory_order_relaxed);
        }
    }

    // Surviving batch keys (parseable, not evicted): the reference set for sent-label GC. The
    // size gauges are NOT stored here any more - the rebase above plus the quarantine/eviction
    // fetch_subs already left them at the true on-disk size via RMW only, so a concurrent
    // persist increment is never lost (#2303 gauge-race fix).
    const std::set<std::string> evicted_set(evict.begin(), evict.end());
    std::set<std::string> survivors;
    for (const auto& l : live)
        if (!evicted_set.count(l.key))
            survivors.insert(l.key);

    // Shutdown: skip the two remaining housekeeping scans (label GC + quarantine bounding). Both
    // are best-effort and idempotent - the next boot's prune redoes them - and each is another
    // full list_entries + del_keys against a possibly-contended KvStore (C0 #2298).
    if (stopping_.load(std::memory_order_acquire))
        return stats;

    // Sent-label GC: drop any sent:<...> whose batch no longer survives - an evicted batch's
    // label, or an orphan from a crash between the pop-after-send label write and eviction.
    if (auto sent = kv_->list_entries(kJournalNamespace, kSentKeyPrefix)) {
        // The gate above covered ENTERING this block; a stop can still land during the list
        // itself, and each remaining step is another KvStore round trip (#2298 Sol review).
        if (stopping_.load(std::memory_order_acquire))
            return stats;
        std::vector<std::string> stale;
        for (const auto& s : *sent)
            if (!survivors.count(journal_batch_key_from_sent_key(s.key)))
                stale.push_back(s.key);
        if (!stale.empty() && !stopping_.load(std::memory_order_acquire))
            stats.sent_labels_gc =
                static_cast<std::size_t>(kv_->del_keys(kJournalNamespace, stale));
    }

    if (stopping_.load(std::memory_order_acquire))
        return stats; // do not START the quarantine scan

    // Bound the quarantine set (drop oldest-by-key; corrupt batches have no trusted ts_ms).
    if (auto q = kv_->list_entries(kJournalNamespace, kQuarantineKeyPrefix)) {
        if (q->size() > max_quarantine_ && !stopping_.load(std::memory_order_acquire)) {
            std::vector<std::string> drop;
            const std::size_t excess = q->size() - max_quarantine_;
            for (std::size_t i = 0; i < excess; ++i)
                drop.push_back((*q)[i].key); // list_entries is key-sorted
            // Count + warn the shed (review UP-7 / sre): a fleet quietly discarding over-cap
            // corrupt batches was previously invisible - an operator needs to see quarantine churn.
            if (stopping_.load(std::memory_order_acquire))
                return stats; // last gate before the final delete
            const int dropped = kv_->del_keys(kJournalNamespace, drop);
            if (dropped > 0) {
                quarantine_capacity_evicted_.fetch_add(static_cast<std::uint64_t>(dropped),
                                                       std::memory_order_relaxed);
                spdlog::warn("Guardian journal: shed {} over-cap quarantined batch(es) (cap {})",
                             dropped, max_quarantine_);
            }
        }
    }

    return stats;
}

JournalPageStats GuardianLifecycleJournal::page_into_window(GuardianSparkRuntime& rt,
                                                           std::int64_t now_ms) {
    JournalPageStats stats;
    if (!kv_)
        return stats;
    // Shutdown began: page nothing at all. The mid-loop gate below already stops the window
    // mutation; checking here (and BEFORE paging_mutex_, so we never queue behind an in-flight
    // prune) also skips the boot-prune barrier's full scan and the candidate-build rename pass,
    // so a stop during maintenance does not delay the drain-worker join (C0 #2298).
    if (stopping_.load(std::memory_order_acquire))
        return stats;
    std::lock_guard<std::mutex> pg{paging_mutex_};

    // N1 / UP-11 (fleet-cost + run-loop stall): a pass with no token can do no net-new work, so
    // short-circuit BEFORE any O(journal) scan - including the boot-prune barrier below. Otherwise
    // a flapping link re-runs the full boot scan on the run-loop thread every reconnect until it
    // latches (up to the 5 s KvStore busy timeout each). The tick's periodic prune + the first
    // token-bearing page both still bound an over-cap journal; nothing is skipped, only deferred.
    // (The process's first page has the startup burst, so the boot prune still runs before the
    // very first replay.) rev-4.1 #6 warned a slow KvStore delays heartbeats; this respects it.
    if (!page_bucket_.ready(now_ms)) {
        stats.deferred_no_token = true;
        return stats;
    }

    // Prune-before-page barrier (rev-4.1 #6): the FIRST paging attempt prunes before it can
    // return any replay candidate, so a stale over-cap journal is bounded before replay. Latch
    // the barrier only on a SUCCESSFUL prune scan (review M5) so a transient read error does not
    // permanently mark the boot prune done and let over-cap data page unpruned.
    //
    // KNOWN LIMIT (#2303 Sol, pre-existing, inert): "bounded before replay" holds for the SCAN
    // (C4 pages nothing on a failed scan). It does NOT hold if the scan succeeds but the
    // retention DELETE fails - prune returns read_ok=true, the barrier latches, and readable
    // over-cap rows page anyway. That is bounded (the page rate-limiter caps the fleet cost) and
    // the rows are valid audit records, just not retention-trimmed first. Gating the barrier on
    // complete retention success (or documenting the intentional replay) is deferred to the
    // cutover resilience work (#2300); it does not gate this inert path.
    if (!boot_pruned_) {
        // Call prune_locked_ directly: we already hold paging_mutex_ (prune() would re-lock it).
        if (!prune_locked_(now_ms).read_ok)
            return stats; // #2303 C4: the barrier means "prune BEFORE any candidate can page".
                          // Latching only on read_ok (M5) is necessary but not sufficient - on a
                          // failed scan we must also PAGE NOTHING this pass, or we hand the
                          // runtime candidates a successful prune would have evicted, defeating
                          // the barrier on exactly the passes it exists for. Bounded and
                          // self-correcting: the tick's periodic prune and the next token-bearing
                          // pass retry, and expired rows are skipped below regardless.
        boot_pruned_ = true;
    }

    // Re-check after the boot-prune barrier above: that barrier runs a FULL prune pass, so a
    // stop can arrive while it is in flight, and this list_entries is page's own heaviest read
    // (#2298 governance cs-2).
    if (stopping_.load(std::memory_order_acquire))
        return stats;

    if (inject_fail_page_reads_.load(std::memory_order_relaxed) > 0) { // test-only read fault
        inject_fail_page_reads_.fetch_sub(1, std::memory_order_relaxed);
        page_read_failures_.fetch_add(1, std::memory_order_relaxed);
        return stats; // same observable as a real list_entries failure below
    }
    auto rows = kv_->list_entries(kJournalNamespace, kBatchKeyPrefix);
    if (!rows) {
        // Read error: fail-safe, page nothing this pass. Counted separately from prune's own
        // scan failures - a page-side read that fails every pass stops ALL replay while prune
        // keeps succeeding, so the two are different operator situations (#2345 Gate 6 SRE).
        page_read_failures_.fetch_add(1, std::memory_order_relaxed);
        return stats;
    }

    // Order candidates by (ts_ms, key) - NOT lexical key (the boot-nonce is random). Skip
    // expired batches (prune removes them; don't re-send an aged-out event).
    struct Cand {
        std::string key;
        std::int64_t ts_ms;
        JournalBatch batch;
    };
    std::vector<Cand> cands;
    cands.reserve(rows->size());
    // Use the cutoff RETENTION last decided, not a freshly computed one (#2345 Gate 5 CH-5).
    // Computing it here independently reintroduced the very loss the clock-jump guard exists to
    // prevent, one layer along: prune declined to age-evict on the anomalous reading, so the
    // batches survived on disk - and then page, computing its own cutoff from the same bad
    // clock, classified all of them "expired, prune will remove them" and replayed none. The
    // trail was retained and never sent, which is the worst of both. One decision, one place.
    const std::int64_t min_ts =
        pruned_cutoff_valid_ ? last_age_cutoff_
                             : now_ms - static_cast<std::int64_t>(retention_days_) * 86400 * 1000;
    for (auto& row : *rows) {
        // Shutdown mid-scan: this loop can issue one rename_key per corrupt row, so bail rather
        // than finish quarantining a large journal (C0 #2298). Nothing has been paged yet, so
        // returning here mutates no window and counts no pass; the next boot re-scans.
        if (stopping_.load(std::memory_order_acquire))
            return stats;
        auto b = parse_journal_batch(row.value);
        if (!b)
            continue; // unparseable: prune quarantines it (runs before page via the barrier + tick)
        if (b->ts_ms < min_ts)
            continue; // valid but expired: prune evicts it; do not re-send, do not quarantine
        // Re-validate every record before replay (review M6): a corrupt/tampered v4 row on disk
        // (enqueued_ns<=0, an oversized/non-UTF-8 field, or a kind other than armed/disarmed)
        // would poison the server compare into a false Conflict every reconnect -- the exact
        // failure the M6 MINT gate prevents. QUARANTINE the whole batch (the quarantine unit per
        // section 2/9) so it is never replayed and the removal is COUNTED, not silently skipped.
        bool replayable = true;
        for (const auto& r : b->entries) {
            if (validate_record(r) != JournalReject::None ||
                (r.kind != "armed" && r.kind != "disarmed")) {
                replayable = false;
                break;
            }
        }
        if (!replayable) {
            if (kv_->rename_key(kJournalNamespace, row.key, journal_quarantine_key(row.key)) ==
                KvRename::Renamed) {
                quarantined_.fetch_add(1, std::memory_order_relaxed);
                // The row left the lc: namespace here too - keep the running-counter gauges
                // exact (#2303), matching prune's quarantine fetch_sub. Page does not rebase,
                // so without this the gauge over-counts the renamed-away row until the next
                // prune scan (safe direction, but the "RMW exactly what leaves lc:" invariant
                // must hold on every remover, not just prune).
                journal_batch_count_.fetch_sub(1, std::memory_order_relaxed);
                journal_bytes_.fetch_sub(static_cast<std::int64_t>(row.value.size()),
                                         std::memory_order_relaxed);
            } else {
                quarantine_failures_.fetch_add(1, std::memory_order_relaxed);
            }
            continue;
        }
        cands.push_back(Cand{row.key, b->ts_ms, std::move(*b)});
    }
    std::sort(cands.begin(), cands.end(), [](const Cand& a, const Cand& b) {
        return a.ts_ms != b.ts_ms ? a.ts_ms < b.ts_ms : a.key < b.key;
    });

    // Fair rotation (review B2): resume at the first candidate strictly greater than the
    // last-considered (ts_ms, key) and WRAP, so the never-sent tail is reached instead of the
    // oldest sent-and-popped batches re-charging the bucket every pass and starving it. Bound
    // the pass to min(cands, cap) so a wrap cannot re-page a batch twice in one pass.
    const auto after_cursor = [&](const Cand& c) -> bool {
        if (!page_cursor_)
            return true;
        return c.ts_ms != page_cursor_->first ? c.ts_ms > page_cursor_->first
                                              : c.key > page_cursor_->second;
    };
    std::size_t start = 0;
    while (start < cands.size() && !after_cursor(cands[start]))
        ++start;
    if (start == cands.size())
        start = 0; // cursor at/after the end: wrap to the oldest

    // NOTE ON A REMOVED MECHANISM. Four attempts were made here to stop a LARGE batch being
    // skipped every pass while small ones are placed, and then deleted by retention unsent -
    // a loss channel biased towards the biggest batches, which are mass arm/disarm bursts and
    // so the most audit-significant records. All four scheduled the send window; all four
    // failed, and the reason is structural rather than a bug in any of them: a batch is
    // blocked precisely when the window has less room than it needs, so making it fit means
    // pausing competing replay until the drain creates room. Where the drain cannot create
    // room, such a scheme must either release (restoring the original loss) or hold (stalling
    // every other batch). No amount of counter or branch fixing removes that fork.
    //
    // The channel is therefore DOCUMENTED, not scheduled around: see #2364 and the retention
    // section of docs/guardian-c0-thread-reloc-design.md. It is narrow - a maximum batch is
    // 256 entries against a 4096 window, so it needs sustained occupancy above ~94%, which is
    // itself a delivery failure with its own signals - and the right next step is a signal for
    // that regime (the age of the oldest headroom-blocked batch), not a fifth scheduler.

    // One membership snapshot for the whole pass. Sizing a candidate by its NET-NEW records
    // rather than its raw entry count is what stops a batch that is ALREADY fully windowed
    // from being read as blocked on a phantom shortage - the same accounting error
    // try_page_batch fixes under the lock, which lived on here at the pre-check one layer up
    // (#2345 Gate 8 QE).
    const auto windowed = rt.lifecycle_event_ids();
    // De-duplicated, mirroring try_page_batch's `want` set. Counting per entry let a row that
    // repeats an event_id overstate its requirement by up to a whole batch, so a batch needing
    // one slot could be deferred as though it needed many (#2345 Gate 8b security).
    std::unordered_set<std::string> seen; // reused across candidates to avoid re-allocating
    const auto net_new_of = [&windowed, &seen](const JournalBatch& b) {
        seen.clear();
        for (const auto& r : b.entries)
            if (!windowed.count(r.event_id))
                seen.insert(r.event_id);
        return seen.size();
    };

    const std::size_t limit = std::min<std::size_t>(cands.size(), kJournalPageMaxBatchesPerPass);
    for (std::size_t n = 0; n < limit; ++n) {
        if (stopping_.load(std::memory_order_acquire))
            break; // shutdown began: stop mutating the window (stop-race gate, rev-4.1 #7)
        Cand& c = cands[(start + n) % cands.size()];
        // Check headroom BEFORE building anything. Two reasons (#2298 Gate 4 UP-2 + f-2):
        // try_page_batch's own headroom gate is all-or-nothing per batch, so a full window
        // means every OutboxEntry constructed below - up to 256 per batch, each carrying
        // several strings - is built and immediately discarded; and the caller cannot
        // otherwise distinguish "window full" from "already a member", which are opposite
        // situations. Recording it here makes the distinction explicit and skips the waste.
        // This pre-check is a pure OPTIMISATION - it avoids building up to 256 OutboxEntry
        // objects for a batch that cannot fit. It is deliberately NOT the source of truth: a
        // concurrent arm can consume the room between here and try_page_batch, so the
        // authoritative blocked/member distinction comes back from under outbox_mu_ below
        // (#2345 Gate 3). It is read per candidate rather than hoisted because a single stale
        // read would misclassify every later candidate in the pass.
        const std::size_t headroom = rt.lifecycle_headroom();
        const auto id = std::pair{c.ts_ms, c.key};
        const std::size_t need = net_new_of(c.batch);
        if (need == 0) {
            // Already fully windowed: no work, and emphatically NOT a blockage.
            page_cursor_ = id;
            continue;
        }
        if (headroom < need) {
            // Paging a newer batch ahead of an older blocked one can invert armed/disarmed
            // wire order across batches. That is tolerated by the server today: dedup compares
            // immutable fields only on an event_id collision, lifecycle events do not update
            // the compliance census, and event queries order by event timestamp rather than
            // arrival. Strict replay order is in any case already best-effort (fair-rotation
            // resume, second-truncated ingest timestamps).
            stats.headroom_blocked = true;
            // Record the SMALLEST blocked requirement so the caller can re-arm only once that
            // much room actually exists - "any headroom > 0" re-armed on every cycle and put
            // UP-2's scan amplification back in the recovery regime.
            if (stats.min_blocked_headroom == 0 || need < stats.min_blocked_headroom)
                stats.min_blocked_headroom = need;
            page_cursor_ = id; // advance: never pin the rotation on a blocked batch
            if (headroom == 0) {
                // Nothing fits at all, so stop scanning - but first record the SMALLEST batch
                // still pending, not this one. Reporting the head's requirement made the
                // worker's re-arm wait for room it never needed (Gate 4 S3). The loop rewrite
                // that later replaced it dropped this scan; restored (#2345 Gate 8b security).
                // Fold in only candidates that actually NEED room. A fully-windowed candidate
                // reports 0 net-new, and taking that into the minimum zeroed it - whereupon the
                // "> 0" guard discarded the whole scan and min_blocked_headroom silently kept
                // the HEAD batch's requirement, which is the exact defect this scan exists to
                // prevent. Not a corner case: live arm/disarm records are both windowed and
                // journal candidates, so a recent batch is routinely fully windowed
                // (#2345 Gate 3 - found independently by three reviewers).
                std::size_t smallest = need; // seeded from a candidate that does need room
                for (std::size_t m = n + 1; m < limit; ++m) {
                    const std::size_t nn = net_new_of(cands[(start + m) % cands.size()].batch);
                    if (nn > 0)
                        smallest = std::min(smallest, nn);
                    if (smallest == 1)
                        break; // cannot get smaller; stop hashing the rest of the slice
                }
                if (stats.min_blocked_headroom == 0 || smallest < stats.min_blocked_headroom)
                    stats.min_blocked_headroom = smallest;
                break;
            }
            continue;
        }
        const bool have_token = page_bucket_.ready(now_ms); // refills for elapsed time

        std::vector<OutboxEntry> entries;
        entries.reserve(c.batch.entries.size());
        for (std::size_t i = 0; i < c.batch.entries.size(); ++i) {
            const auto& r = c.batch.entries[i];
            OutboxEntry e = OutboxEntry::lifecycle(r.rule_id, r.generation, r.event_id,
                                                   r.enqueued_ns, r.kind, r.guard_type, r.rule_name);
            e.journal_batch_key = c.key; // replay provenance for the sent-label (wire-ignored)
            e.journal_last_in_batch = (i + 1 == c.batch.entries.size());
            entries.push_back(std::move(e));
        }
        const auto outcome = rt.try_page_batch(std::move(entries));
        // Advance the cursor for EVERY considered batch (paged or a free member / headroom-defer
        // skip), so an already-windowed head cannot pin the rotation.
        page_cursor_ = std::pair{c.ts_ms, c.key};
        if (outcome.blocked_for_headroom) {
            // The window shrank between the pre-check and the locked attempt. Without this the
            // pass would report "nothing to do" and the caller's refill re-arm would never
            // fire, stalling replay for a full cadence interval (#2345 Gate 3).
            stats.headroom_blocked = true;
            if (stats.min_blocked_headroom == 0 || outcome.required < stats.min_blocked_headroom)
                stats.min_blocked_headroom = outcome.required;
        }
        if (outcome.added > 0) {
            // Charge BEFORE the break, deliberately. This pass is allowed to place one batch
            // over an empty bucket, and charging for it takes the balance negative, which is
            // simply the debt for work already done: two batches placed cost two tokens, so
            // the next pass waits proportionally longer. Charging only when a token was in
            // hand would hand out one free batch per pass and roughly double the steady-state
            // replay rate the bucket exists to bound (#2345 round 7 - proposed as a fix, and
            // rejected on that arithmetic).
            page_bucket_.take();
            ++stats.batches_paged;
            stats.records_paged += outcome.added;
            if (!have_token)
                break; // paged one net-new over an empty bucket; the rest wait for a refill
        }
        // added == 0 and not blocked: every entry was already a member; keep rotating.
    }

    pages_.fetch_add(1, std::memory_order_relaxed);
    records_paged_.fetch_add(stats.records_paged, std::memory_order_relaxed);
    return stats;
}

void GuardianLifecycleJournal::mark_batch_sent(const std::string& batch_key) {
    if (!kv_ || batch_key.empty())
        return;
    // Best-effort presence marker; the value is unused. set() is an upsert, so a repeated
    // send is idempotent. Never gates re-paging or deletion (design §2/§8).
    if (kv_->set(kJournalNamespace, journal_sent_key_from_batch_key(batch_key), ""))
        sent_labels_written_.fetch_add(1, std::memory_order_relaxed);
}

} // namespace yuzu::agent
