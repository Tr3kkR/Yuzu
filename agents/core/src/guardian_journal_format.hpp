#pragma once

/**
 * guardian_journal_format.hpp -- pure on-disk format for the Guardian durable
 * lifecycle-audit journal (item 7, PR-Ag; design rev 4.1:
 * docs/spark-item7-lifecycle-journal-design.md).
 *
 * This TU is the SUBSTRATE ONLY: the record shape, the kv_store key/namespace
 * scheme, the caps, mint-time field validation, and batch (de)serialization.
 * It has NO wiring, NO KvStore access, NO threads - it is deterministic and
 * unit-testable in isolation. Staging, persistence, retention, and replay layer
 * on top of this in later commits.
 *
 * A JournalRecord is FROZEN AT MINT: every field it carries is exactly what was
 * (or will be) sent on the wire, so a replay reconstructs a byte-identical
 * GuaranteedStateEvent and the server's redelivery compare (PR-Sv) sees a match,
 * not a false Conflict. Nothing here is ever re-stamped or re-measured.
 */

#include <yuzu/plugin.h> // YUZU_EXPORT

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::agent {

// ── Namespace, format version, caps (design §3, §6; rev-4.1) ──────────────────

/// Distinct kv_store "plugin" namespace - survives full_sync's clear("__guardian__").
inline constexpr std::string_view kJournalNamespace = "__guardian_journal__";

/// Value envelope version. An unknown version on read → quarantine (never trust).
inline constexpr int kJournalFormatVersion = 4;

/// Batch size caps: a push larger than this is chunked into multiple batches.
inline constexpr std::size_t kMaxJournalEntriesPerBatch = 256;
inline constexpr std::size_t kMaxJournalBatchBytes = 256 * 1024; // 256 KiB

/// Bounded staging reserve (RAM). Overflow → drop-oldest + journal_stage_dropped.
inline constexpr std::size_t kMaxPendingJournalRecords = 4096;

/// Per-field byte cap. An oversized field keeps the whole record out (counted).
inline constexpr std::size_t kMaxJournalFieldBytes = 4096;

/// Retention bounds (evict oldest by (ts_ms, key)).
inline constexpr int kJournalRetentionDays = 7;
inline constexpr std::size_t kMaxJournalBatches = 1000;
inline constexpr std::size_t kMaxJournalBytes = 32ull * 1024 * 1024; // 32 MiB

/// Corrupt batches moved aside are ALSO bounded (counted + pruned) so they cannot
/// accumulate outside the caps above.
inline constexpr std::size_t kMaxQuarantineBatches = 100;

/// Replay paging rate limiter (rev-4.1 #8): a process-lifetime token bucket bounds the
/// STEADY-STATE redelivery bandwidth - re-send-all re-pages a sent+popped entry on every
/// tick until retention, so the refill rate IS the per-agent redelivery rate. At this rate
/// a fleet of N agents redelivers <= N * kJournalPageRefillPerSec batches/sec server-wide,
/// each a cheap redelivered-quiet ingest; the DEFERRED server ack removes re-send-all
/// entirely. Tunable.
inline constexpr double kJournalPageRefillPerSec = 0.1; // 1 batch / 10 s / agent
inline constexpr double kJournalPageBurst = 5.0;        // small startup burst
/// Bound per-pass paging work (reconstruct + membership scan) regardless of journal size.
inline constexpr std::size_t kJournalPageMaxBatchesPerPass = 128;

/// How far in the future a batch's ts_ms may plausibly sit before retention stops trusting it.
///
/// A batch stamped beyond this sorts FIRST for the count and byte ceilings - an ORDERING rule,
/// NOT an expiry rule. The distinction is load-bearing and was arrived at the hard way: making
/// such a batch "immediately expired" hands the whole journal to any clock reading in the past
/// (an RTC that comes up at 1970 makes every real row look future-dated), which is the
/// wholesale wipe the age guard exists to prevent - it failed 21 tests. Do not "simplify" this
/// back to an expiry test. Without the ordering rule such a row is IMMORTAL - it can never be
/// too old, and count eviction is oldest-first so it is never count-evicted either - and worse,
/// it DISPLACES real evidence: once enough of them exist
/// (a bad RTC for a week, a VM clone, a hand-edited kv_store.db), every genuine record written
/// afterwards is the one evicted at the next prune, permanently. Precedent for the shape is
/// server-side in app_perf_daily_store.cpp's kFutureSlackDays (#2345 Gate 2 security).
///
/// One day is generous for clock skew between an endpoint and its own next prune pass, while
/// still bounding the damage a badly-set clock can do to the audit trail.
inline constexpr std::int64_t kJournalFutureSlackMs = 24LL * 3600 * 1000;

/// Batches a single retention pass may evict for AGE. Age is the one retention rule driven by
/// an absolute reading of the wall clock, so one bad reading (a VM restored from snapshot, an
/// NTP overshoot) marks every batch expired simultaneously and would delete the whole durable
/// audit trail in one transaction. Capping the pass converts that into a paced ageing-out that
/// an operator can notice and act on, rather than an instantaneous one.
///
/// It does NOT guarantee the paced batches are shipped first: at 64 per ~120 s pass this sheds
/// roughly 32 batches/minute while replay refills at 0.1 batch/s (~6/minute), so deletion
/// outruns delivery about five to one (#2345 Gate 2 performance). Lowering the cap to match the
/// replay rate, or lifting the paging bucket while pacing, is tracked on #2364; what the cap
/// buys today is time and a signal, not delivery.
///
/// It caps AGE eviction ONLY, and deliberately does not bound how fast a journal shrinks: the
/// count and byte ceilings are uncapped and trim an over-ceiling journal back in a single pass
/// regardless of this constant, so an over-cap journal converges as fast as it ever did. The
/// pacing therefore applies to the case it was built for - a journal that is within its
/// ceilings but suddenly entirely expired - and NOT, as an earlier version of this comment
/// claimed, to "a full 2000-batch journal ageing out in about an hour": at 2000 batches the
/// count ceiling is what evicts, and it evicts ~1000 in one pass (#2345 Gate 8 UP5-2).
inline constexpr std::size_t kMaxAgeEvictionsPerPass = 64;

/// Key prefixes within kJournalNamespace. A batch key is "lc:<nonce>:<seq12>";
/// its sent-label is "sent:<nonce>:<seq12>"; a quarantined batch is
/// "quarantine:" + the original batch key. The three prefixes are disjoint so a
/// prefix scan of one never sees another.
inline constexpr std::string_view kBatchKeyPrefix = "lc:";
inline constexpr std::string_view kSentKeyPrefix = "sent:";
inline constexpr std::string_view kQuarantineKeyPrefix = "quarantine:";

// ── Record (7 fields, frozen at mint; design §3) ─────────────────────────────

struct JournalRecord {
    std::string rule_id;
    std::uint64_t generation{0};
    std::string event_id; // wire idempotency key; boot-nonce'd; PRESERVED verbatim on replay
    std::int64_t enqueued_ns{0}; // wall ns at enqueue; the frozen wire timestamp source
    std::string kind;            // "armed" | "disarmed"
    std::string guard_type;
    std::string rule_name;
};

struct JournalBatch {
    std::int64_t ts_ms{0}; // batch wall-clock ms - the ordering key across batches
    std::vector<JournalRecord> entries;
};

// ── Key helpers ──────────────────────────────────────────────────────────────

/// "lc:<boot_nonce>:<seq12>" - seq is a per-process counter from 0, zero-padded
/// to 12 digits (side-steps list()'s fail-open max+1 overwrite). Ordering across
/// batches is by (ts_ms, key), NOT lexical key: the boot-nonce is random.
YUZU_EXPORT std::string journal_batch_key(std::string_view boot_nonce, std::uint64_t seq);

/// "sent:<boot_nonce>:<seq12>" - the (best-effort) sent-label for a batch.
YUZU_EXPORT std::string journal_sent_key(std::string_view boot_nonce, std::uint64_t seq);

/// "quarantine:" + batch_key - where a corrupt/unparseable batch is moved.
YUZU_EXPORT std::string journal_quarantine_key(std::string_view batch_key);

/// Derive the batch key a sent-label refers to: "sent:X:Y" → "lc:X:Y". Used by
/// sent-label GC to find labels whose batch no longer exists. Returns the input
/// unchanged if it is not a sent-label key (it then matches no batch).
YUZU_EXPORT std::string journal_batch_key_from_sent_key(std::string_view sent_key);

/// Derive a batch's sent-label key: "lc:X:Y" → "sent:X:Y". Used when a paged batch's last
/// entry sends, and to classify an eviction. Returns the input unchanged if not a batch key.
YUZU_EXPORT std::string journal_sent_key_from_batch_key(std::string_view batch_key);

// ── Mint-time validation (design §2 loss table; rev-4.1 #2) ───────────────────

/// Why a record was refused entry to the journal. The caller maps each reason to
/// its integrity counter: field faults → journal_field_rejected; a skewed clock →
/// journal_clock_rejected (rev-4.1 #2).
enum class JournalReject {
    None,
    EmbeddedNul,  // a string field contains a NUL - journal values are NUL-free
    Oversized,    // a string field exceeds kMaxJournalFieldBytes
    InvalidUtf8,  // a string field is not valid UTF-8 (JSON cannot carry it byte-exact;
                  // silently replacing bytes would flip the server compare to a false Conflict)
    SkewedClock,  // enqueued_ns floors to epoch seconds <= 0 - the server would stamp
                  // receipt-now instead, making every replay mismatch on timestamp
};

/// Validate a record at mint. Returns the FIRST reason it must be refused, or
/// None if it is journalable. Pure - no I/O.
YUZU_EXPORT JournalReject validate_record(const JournalRecord& r);

// ── Batch (de)serialization ──────────────────────────────────────────────────

/// Serialize a batch to the v:4 JSON envelope. Never throws: entries are assumed
/// already validated (validate_record), and the dump replaces any stray invalid
/// byte rather than throwing (a belt-and-suspenders over validation).
YUZU_EXPORT std::string serialize_journal_batch(std::int64_t ts_ms,
                                                std::span<const JournalRecord> entries);

/// Why a stored batch value could not be parsed back. Either reason → quarantine.
enum class JournalParseError {
    Malformed,      // not JSON, or missing/typewrong required fields
    UnknownVersion, // "v" is present but != kJournalFormatVersion
};

/// Parse a stored batch value. `unexpected` → the caller quarantines the key.
YUZU_EXPORT std::expected<JournalBatch, JournalParseError>
parse_journal_batch(std::string_view json);

} // namespace yuzu::agent
