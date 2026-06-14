#include "dex_linux_journal.hpp"

#include <nlohmann/json.hpp>

#include <charconv>
#include <string>

namespace yuzu::agent::lnx {

namespace {

using nlohmann::json;

// `journalctl -o json` renders most fields as strings, but a field can be an array
// (a key that repeated in the entry) or an object (binary → a byte array). Take it
// only when it is a plain string; anything else reads as "" so the caller drops it
// rather than shipping binary/structured content.
std::string jstr(const json& j, const char* key) {
    if (!j.is_object())
        return {};
    const auto it = j.find(key);
    if (it != j.end() && it->is_string())
        return it->get<std::string>();
    return {};
}

// Parse a whole string_view as a signed int. nullopt on anything malformed —
// from_chars never throws (a bad COREDUMP_SIGNAL must not unwind the poll thread).
std::optional<int> to_int(std::string_view s) {
    int v = 0;
    const char* const end = s.data() + s.size();
    const auto [p, ec] = std::from_chars(s.data(), end, v);
    if (ec != std::errc{} || p != end)
        return std::nullopt;
    return v;
}

// Kernel OOM-killer line: "Out of memory: Killed process 1234 (comm) total-vm:…".
// Returns the killed process comm from the parentheses, or "" if `msg` is not an
// OOM-kill line. Only the comm is taken — the rest of the kernel message (memory
// figures) is never shipped.
std::string oom_victim_comm(std::string_view msg) {
    constexpr std::string_view kMark = "Out of memory: Killed process ";
    const auto p = msg.find(kMark);
    if (p == std::string_view::npos)
        return {};
    const auto lp = msg.find('(', p);
    if (lp == std::string_view::npos)
        return {};
    const auto rp = msg.find(')', lp);
    if (rp == std::string_view::npos || rp <= lp + 1)
        return {};
    return std::string(msg.substr(lp + 1, rp - lp - 1));
}

} // namespace

std::string crash_signal_name(int signo) {
    switch (signo) {
    case 3:  return "SIGQUIT";
    case 4:  return "SIGILL";
    case 5:  return "SIGTRAP";
    case 6:  return "SIGABRT";
    case 7:  return "SIGBUS";
    case 8:  return "SIGFPE";
    case 11: return "SIGSEGV";
    case 24: return "SIGXCPU";
    case 25: return "SIGXFSZ";
    case 31: return "SIGSYS";
    default: return "signal " + std::to_string(signo);
    }
}

JournalLine parse_journal_line(std::string_view line) {
    JournalLine out;
    const json j = json::parse(line, nullptr, /*allow_exceptions=*/false);
    if (j.is_discarded() || !j.is_object())
        return out; // cursor "", obs nullopt
    out.cursor = jstr(j, "__CURSOR");

    const std::string mid = jstr(j, "MESSAGE_ID");

    // ── systemd-coredump entry → process.crashed ─────────────────────────────
    // Every coredump is a crash by definition (systemd-coredump only fires on a
    // core-generating signal), so no intentional-stop filtering is needed. Subject
    // is the comm only — COREDUMP_EXE (a full path) is never shipped.
    if (mid == kMsgIdCoredump) {
        const std::string comm = jstr(j, "COREDUMP_COMM");
        if (comm.empty())
            return out; // no safe subject
        SignalObservation o;
        o.obs_type = "process.crashed";
        o.subject = comm;
        o.kind = "signal";
        if (const auto sig = to_int(jstr(j, "COREDUMP_SIGNAL")))
            o.reason = crash_signal_name(*sig);
        o.sentence = comm + " crashed" + (o.reason.empty() ? std::string{} : " (" + o.reason + ")");
        out.obs = std::move(o);
        return out;
    }

    // ── systemd unit entered failed state → service.crashed ──────────────────
    // Covers both a running service dying and a start that failed (both end in the
    // failed state, one canonical UNIT_FAILED entry each). UNIT_RESULT (exit-code /
    // signal / core-dump / timeout / oom-kill) is the reason when present; absent →
    // empty reason (still a valid observation).
    if (mid == kMsgIdUnitFailed || mid == kMsgIdUnitResult) {
        const std::string unit = jstr(j, "UNIT");
        if (unit.empty())
            return out;
        SignalObservation o;
        o.obs_type = "service.crashed";
        o.subject = unit;
        o.kind = "unit";
        o.reason = jstr(j, "UNIT_RESULT");
        o.sentence =
            unit + " failed" + (o.reason.empty() ? std::string{} : " (result: " + o.reason + ")");
        out.obs = std::move(o);
        return out;
    }

    // ── kernel OOM-killer → memory.exhausted ─────────────────────────────────
    // No stable MESSAGE_ID (it is a kernel ring-buffer message), so identify by the
    // kernel transport + the OOM text; only the killed comm is taken.
    if (jstr(j, "_TRANSPORT") == "kernel") {
        const std::string victim = oom_victim_comm(jstr(j, "MESSAGE"));
        if (!victim.empty()) {
            SignalObservation o;
            o.obs_type = "memory.exhausted";
            o.subject = victim;
            o.reason = "oom-kill";
            o.sentence = "Out of memory: kernel killed " + victim;
            out.obs = std::move(o);
        }
        return out; // a non-OOM kernel line: cursor advances, no observation
    }

    return out;
}

} // namespace yuzu::agent::lnx
