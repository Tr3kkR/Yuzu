#pragma once

// tar_capture_status.hpp -- pure predicate for whether a bounded-subprocess
// capture is complete enough to trust as an authoritative TAR snapshot.
//
// Background: run_bounded_subprocess (agents/core/include/yuzu/agent/
// subprocess_runner.hpp) distinguishes "the child ran to completion" from
// "the deadline/output cap cut it off" via SubprocessResult::{tool_ran,
// timed_out, output_truncated, exit_code}. Several TAR collectors migrated
// from popen to that runner but kept the old popen-era check (only
// `tool_ran`), so a command that hit the deadline or the output cap still
// had its (partial) lines/output parsed and diffed against the previous
// COMPLETE snapshot -- fabricating durable "stopped"/"removed" forensic
// events for every row the partial run happened not to reach, followed by
// compensating false "started"/"appeared" events once a complete run
// replaces the partial one as the new baseline. This header is the single
// place that decision is made, so it is unit-testable without spawning a
// process (tests/unit/test_tar_service.cpp, tests/unit/test_tar_mapdrive.cpp)
// and every collector site applies the identical policy.
//
// zero_exit_required defaults to true because every command this repo wraps
// through the runner today (systemctl list-units, launchctl list, smbstatus
// -b, wevtutil qe, journalctl -u ... -n) is verified or documented to exit 0
// on a normal empty-result run -- see the call sites in
// tar_service_collector.cpp / tar_mapdrive_collector.cpp for what was
// verified on a live host versus assumed from documented behaviour. A future
// command whose *documented* success path is legitimately non-zero (this
// repo has been bitten by exactly that with `dnf check-update` exiting 100)
// must pass zero_exit_required=false at its own call site rather than
// weakening this default for everyone.

#include <cstddef>
#include <optional>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

namespace yuzu::tar {

/// The single exception type every TAR collector throws to report an
/// incomplete capture (a failed read, a kernel/parser-reported truncation,
/// or an entry-cap reached before the whole table was consumed) --
/// service/mapdrive's subprocess legs, and every ARP/mapdrive native leg.
/// collect_or_retain() below catches ONLY this type (round 3, B3-003): an
/// earlier cut caught bare `std::exception`, which would also swallow a
/// genuine std::bad_alloc or other programming/allocation failure thrown out
/// of a collector and misreport it as ordinary capture incompleteness --
/// masking, not just retrying, a real bug. A dedicated type also makes the
/// contract self-documenting: catching `IncompleteCaptureError` by name says
/// exactly what is being tolerated, where `std::exception` said nothing.
struct IncompleteCaptureError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

/// Why a capture was (or was not) judged complete -- `complete` is the
/// verdict a caller acts on; `reason` is populated only when `!complete`,
/// for logging (never a fabricated verdict, never silent).
struct CaptureCompleteness {
    bool complete{false};
    std::string reason;
};

/// Whether appending one more row to a size-`size_before_push` collection
/// would exceed `cap` -- the single decision every capped collector loop
/// must apply BEFORE appending the candidate row, never after. Extracted
/// (round 3, B3-004/B3-005) because the Windows ARP and Windows mapdrive
/// (WNet outbound + NetSessionEnum inbound) loops each re-implemented this
/// check inline, AFTER the push, which misclassifies an exact-cap table as
/// truncated: the cap-th row is appended, size becomes == cap, and the
/// post-push check then (wrongly) declares the table truncated even though
/// no row was actually omitted. Every platform's capped loop must call this
/// BEFORE push_back so only a genuine (cap+1)-th candidate establishes
/// truncation. Pure and compiled on every platform (unlike the #ifdef-gated
/// collector loops themselves), so this exact decision is unit-tested
/// directly (tests/unit/test_tar_capture_status.cpp) independent of which
/// OS's loop calls it -- the gap B3-005 identifies: the off-by-one survived
/// two review rounds because nothing exercised the real per-platform cap
/// decision, only a stand-in throw.
inline bool would_exceed_cap(std::size_t size_before_push, std::size_t cap) {
    return size_before_push >= cap;
}

/// Pure completeness check over a bounded-subprocess result's status fields
/// (passed individually rather than as a SubprocessResult so this header
/// stays free of any dependency on agents/core, and so a test can construct
/// every combination directly). A capture is authoritative only when the
/// child actually ran, was not killed at the deadline, was not cut off by
/// the output cap, and -- unless the caller says this command's success is
/// legitimately non-zero -- exited 0.
inline CaptureCompleteness classify_subprocess_capture(bool tool_ran, bool timed_out,
                                                        bool output_truncated, int exit_code,
                                                        bool zero_exit_required = true) {
    if (!tool_ran)
        return CaptureCompleteness{.complete = false, .reason = "spawn failed"};
    if (timed_out)
        return CaptureCompleteness{.complete = false, .reason = "deadline exceeded"};
    if (output_truncated)
        return CaptureCompleteness{.complete = false, .reason = "output capped"};
    if (zero_exit_required && exit_code != 0)
        return CaptureCompleteness{.complete = false,
                                   .reason = "exit code " + std::to_string(exit_code)};
    return CaptureCompleteness{.complete = true, .reason = {}};
}

/// Outcome of an incomplete-capture-aware snapshot collection: either the
/// collector ran to completion (`current` holds the snapshot) or it threw
/// (an incomplete/failed/truncated/capped capture, however the specific
/// collector detected that -- subprocess status via
/// classify_subprocess_capture above, or a platform syscall's own error
/// contract for the native ARP/mapdrive legs), in which case `current` is
/// empty and `skip_reason` carries the thrown what() for logging.
template <typename T>
struct CollectOrRetain {
    std::optional<T> current;
    std::string skip_reason;
};

/// The single collect-or-retain seam every TAR snapshot-diff source applies
/// (service, mapdrive, arp): call `collect`, and on a thrown
/// IncompleteCaptureError -- the shared, dedicated signal a collector uses
/// to report "this capture did not complete" -- return an empty result
/// instead of propagating, so the caller's existing "skip this tick's diff
/// and state advance, retain the previous baseline" branch (`if (current) {
/// ... }` at every tar_plugin.cpp call site) is the ONLY place that decision
/// is made. A free function taking the collector as a parameter (rather
/// than each call site's own inline try/catch) means a test can inject a
/// fixture collector that throws/returns on demand and assert the exact
/// skip/retain/recover behaviour without a live syscall or subprocess
/// (tests/unit/test_tar_capture_status.cpp).
///
/// Catches ONLY IncompleteCaptureError (round 3, B3-003) -- previously this
/// caught bare `std::exception`, so a genuine std::bad_alloc or other
/// allocation/programming failure thrown out of a collector was silently
/// reinterpreted as ordinary capture incompleteness (retained baseline,
/// logged, tick continues) instead of surfacing as the real bug it is. Any
/// other std::exception now propagates out of collect_or_retain, out of
/// collect_fast_impl/collect_slow_impl, and up to agent.cpp's own
/// defence-in-depth catch around plugin execute() (agents/core/src/agent.cpp
/// -- frozen for this branch, read not edited), which is the actual safety
/// net for a plugin's unexpected exception; it is not this seam's job.
template <typename CollectFn>
auto collect_or_retain(CollectFn&& collect) {
    using T = std::invoke_result_t<CollectFn>;
    CollectOrRetain<T> result;
    try {
        result.current = std::forward<CollectFn>(collect)();
    } catch (const IncompleteCaptureError& e) {
        result.skip_reason = e.what();
    }
    return result;
}

/// The `snapshot` action's (do_snapshot, tar_plugin.cpp) single honesty
/// decision (round 3, B3-002): given the names of every enabled source that
/// collect_or_retain skipped this pass (arp/service/mapdrive -- whichever
/// legs threw IncompleteCaptureError), produce the exact response line the
/// action writes. Previously `snapshot` unconditionally reported
/// "tar|snapshot|complete" even when a source was classified incomplete and
/// silently skipped, leaving operator/agentic consumers unable to tell a
/// complete forced snapshot from one that quietly retained stale state.
/// Extracted to a pure function (rather than inlined at the do_snapshot call
/// site) so the exact wording is unit-tested directly
/// (tests/unit/test_tar_capture_status.cpp) without standing up a live
/// TarPlugin/CommandContext/database.
inline std::string snapshot_result_line(const std::vector<std::string>& skipped_sources) {
    if (skipped_sources.empty())
        return "tar|snapshot|complete";
    std::string joined;
    for (std::size_t i = 0; i < skipped_sources.size(); ++i) {
        if (i)
            joined += ',';
        joined += skipped_sources[i];
    }
    return "tar|snapshot|partial|" + joined;
}

} // namespace yuzu::tar
