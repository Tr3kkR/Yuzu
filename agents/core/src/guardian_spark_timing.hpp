#pragma once

/**
 * guardian_spark_timing.hpp - #4606 criterion-10: plain-data timing record types +
 * their pure log-line formatters for the Spark detect->delivery latency benchmark
 * (T_ready -> T_mutation -> T_mechanism -> T_detect -> T_fire -> T_server ->
 * T_visible). Deliberately NOT part of GuardianSparkRuntime's class interface:
 *   - so the two format_*_line() functions are directly unit-testable (pure, no
 *     I/O, no clock reads) without touching the runtime;
 *   - so a later commit's agent-side send-site logging (agent.cpp, T_wire) can
 *     reuse SendTimingRecord/format_send_timing_line without depending on
 *     guardian_spark_runtime.hpp (agent.cpp lives in this same directory and
 *     already avoids pulling that header in for an unrelated reason).
 *
 * Placed in agents/core/src/ (not agents/core/include/yuzu/agent/) so its
 * `#include "guardian_outbox.hpp"` (for OutboxDomain) resolves via ordinary
 * same-directory quoted-include lookup, matching guardian_spark_runtime.hpp's own
 * include of it - agents/core/src is not on yuzu_agent_core_lib's -I list, only
 * reachable via same-directory resolution, and neither is guardian_outbox.hpp
 * reachable from agents/core/include/yuzu/agent/ any other way.
 *
 * Field order/naming in both format_*_line() functions is the parseable-log-line
 * contract the benchmark tooling regexes against (same class of tooling as R5.7's
 * T0/T2 / the #3990 diagnostic) - keep it stable.
 *
 * CORRELATION CONTRACT (read before writing a correlator):
 *   - Join on `event_id` and the embedded *_wall_ns fields, NEVER on log-file line order.
 *     A T_wire line can precede its own T_detect line in the file: evaluate_key wakes the
 *     outbox drain worker BEFORE it emits the deferred T_detect line (the waker deliberately
 *     does not wait on the log sink - a stalled sink must never delay delivery), and two
 *     keys' deferred emissions can interleave. A streaming correlator should buffer a T_wire
 *     for a grace window rather than pair it with the next T_detect it sees. In program order
 *     detect_wall_ns precedes wire_wall_ns for one event_id, but both are system_clock reads,
 *     so an NTP step can invert them; T_wire carries no *_mono_ns field.
 *   - event_id is `<agent>-<boot_nonce>-<rule>-<wall_ms>-<seq>`. A new agent process gets a
 *     new boot_nonce, so an id minted before a restart is never re-minted after it.
 *   - Reading a T_detect line that has no later lines:
 *       accepted=0 (fire_*_ns=-1)  the outbox rejected the batch; nothing was enqueued. The
 *                                  next eval pass mints a NEW event_id (and logs another
 *                                  accepted=0 line for as long as the outbox stays full).
 *       accepted=1, no T_wire      enqueued but never sent: coalesced away (a later
 *                                  observation for the same rule+domain replaced it under a
 *                                  newer event_id, same boot_nonce), purged (generation
 *                                  superseded, or the rule was dropped), still queued, held
 *                                  back by a down stream (the Spark path logs no T_wire for
 *                                  that), or the agent stopped first. The Compliance/Health
 *                                  outbox is an in-memory buffer, NOT durable
 *                                  (guardian_outbox.hpp): after a restart the boot
 *                                  re-evaluation mints a fresh id under a new boot_nonce.
 *   - Reading a T_wire line:
 *       Spark path (domain=compliance|health|lifecycle):
 *         sent=0  Write() returned false. The entry is retained and re-sent under the SAME
 *                 event_id unless it is coalesced or dropped in the meantime, in which case
 *                 that id never gets a sent=1. A DOWN stream logs no T_wire line at all.
 *         sent=1  the local write succeeded, which is NOT receipt. A retried send produces
 *                 several T_wire lines for one event_id.
 *       domain=legacy (the non-Spark drift-sink path: no outbox, no T_detect):
 *         sent=0  the event was DROPPED (link down or Write() failed). There is no retry.
 *   - A T_wire line with no T_detect is normal, not an orphan: domain=lifecycle (armed,
 *     disarmed and errored events, and journal replays from this or an earlier process),
 *     domain=health raised by a subscription fault or loss rather than an evaluation pass,
 *     domain=legacy, or an agent stopped between the waker and the deferred T_detect line.
 *   - T_wire sent=1 with no T_server: lost in flight, or the server classified the event
 *     Redelivered (for example a Lifecycle journal replay), Conflict or Error. The server
 *     emits T_server for Inserted only, and logs Redelivered at debug (Conflict and Error at
 *     warn), so at the default info level a replay and a loss look alike in the server log.
 */

#include <yuzu/plugin.h> // YUZU_EXPORT (agent-core shared-lib symbol visibility, -fvisibility=hidden)

#include "guardian_outbox.hpp" // OutboxDomain

#include <cstdint>
#include <optional>
#include <string>

namespace yuzu::agent {

/// #4606 criterion-10: the mechanism/handler context an evaluate_key() pass was triggered by,
/// when it was triggered by a real Spark event (SparkEventKind::Fired). Absent (std::nullopt)
/// for a Convergence-reason pass, which has no event to attribute — an absent trigger must
/// stay absent in every derived timing record, never defaulted to a fabricated zero that a
/// benchmark parser could mistake for "observed but zero-latency".
struct EvalTrigger {
    std::int64_t mechanism_wall_ns{0}; ///< T_mechanism: SparkEvent::at, ns since Unix epoch
    std::int64_t handler_wall_ns{0};   ///< T_handler (diagnostic only): on_event() entry, wall ns
    std::int64_t handler_mono_ns{0};   ///< same instant, steady ns (for LOCAL interval math only)
    std::uint64_t seq{0};              ///< SparkEvent::seq — correlates to the mechanism's own line
};

/// One outbox entry's timing, staged during evaluate_key()'s registry_mu_-held commit section
/// and emitted as a log line AFTER both registry_mu_ and pk->eval_mu are released.
struct EvalTimingRecord {
    std::string event_id;
    OutboxDomain domain{OutboxDomain::Compliance};
    std::int64_t detect_wall_ns{0};  ///< T_detect: immediately after eval_rule() returns, wall ns
    std::int64_t detect_mono_ns{0};  ///< same instant, steady ns (local interval math only)
    bool accepted{false};            ///< outbox_.enqueue_all() outcome for this entry's batch
    std::int64_t fire_wall_ns{-1};   ///< T_fire: enqueue_all() returned true; -1 if !accepted
    std::int64_t fire_mono_ns{-1};   ///< same instant, steady ns; -1 if !accepted (never a
                                     ///< fabricated 0 a parser could read as "fired at the epoch")
    std::optional<EvalTrigger> trigger; ///< absent for a Convergence-reason pass
};

/// Formats one line, stable field order/naming for the benchmark's log-line-parsed
/// methodology (same class of tooling as R5.7's T0/T2 / the #3990 diagnostic). Pure formatter —
/// no I/O, no clock reads — so it's directly unit-testable. A leading `trigger_present=0/1`
/// flag disambiguates an absent trigger from a real one; the sentinel `-1` on every
/// mechanism_wall_ns/handler_wall_ns/handler_mono_ns/seq field when absent is belt-and-braces
/// on top of that flag — never a fabricated `0`, which a benchmark parser could misread as
/// "observed, zero-latency".
YUZU_EXPORT std::string format_eval_timing_line(const EvalTimingRecord& r);

/// #4606 criterion-10 T_wire: one send attempt's timing, logged by the agent-side send sites
/// in agent.cpp (send_guardian_outbox_entry for the Spark outbox path, and the legacy
/// drift-sink lambda). Declared here so both agent-side timing lines share one header/contract.
struct SendTimingRecord {
    std::string event_id;
    /// The outbox domain of the entry being sent, so a Lifecycle journal replay (legitimately
    /// no T_server: the server answers Redelivered) is distinguishable from a lost
    /// Compliance/Health event (also no T_server, for a bad reason). Absent (std::nullopt) on
    /// the legacy drift-sink path, which has no outbox - rendered as `domain=legacy`.
    std::optional<OutboxDomain> domain;
    bool sent{false};            ///< local Write() succeeded — NOT server receipt (see T_server)
    std::int64_t wire_wall_ns{0};
};
YUZU_EXPORT std::string format_send_timing_line(const SendTimingRecord& r);

/// Builds the T_wire record for one Spark-outbox send attempt: the entry's event_id and
/// domain, the local Write() outcome, and the wire timestamp. A free function rather than
/// inline in agent.cpp (whose AgentImpl is file-local and unreachable from a unit test) so
/// that carrying `domain` through - the point of the field - is covered by a test.
YUZU_EXPORT SendTimingRecord make_outbox_send_timing(const OutboxEntry& e, bool sent,
                                                     std::int64_t wire_wall_ns);

} // namespace yuzu::agent
