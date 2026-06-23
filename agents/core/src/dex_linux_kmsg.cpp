#include "dex_linux_kmsg.hpp"

#include <array>
#include <string>
#include <string_view>
#include <utility>

namespace yuzu::agent::lnx {

namespace {

bool contains(std::string_view hay, std::string_view needle) {
    return hay.find(needle) != std::string_view::npos;
}

// The block-layer error line names the failure type before ", dev " — map it to a
// short, infra-safe reason code (never the raw line). The captured form on a real
// failing SCSI disk is "critical medium error, dev sdb, sector N op …"; the I/O
// fallback covers "… I/O error, dev …" and the rarer critical-* variants.
std::string disk_error_reason(std::string_view msg) {
    if (contains(msg, "critical medium error"))
        return "medium-error";
    if (contains(msg, "critical target error"))
        return "target-error";
    if (contains(msg, "critical nexus error"))
        return "nexus-error";
    if (contains(msg, "critical space allocation error"))
        return "space-error";
    return "io-error";
}

// "INFO: task <comm>:<pid> blocked for more than N seconds." → comm. The comm sits
// between "task " and " blocked"; the pid is the trailing ":<n>" (rsplit on ':' so a
// comm is taken whole even though a comm cannot normally contain ':'). "" if the
// shape does not match.
std::string hung_task_comm(std::string_view msg) {
    constexpr std::string_view kTask = "task ";
    const auto tp = msg.find(kTask);
    if (tp == std::string_view::npos)
        return {};
    const auto start = tp + kTask.size();
    const auto bp = msg.find(" blocked", start);
    if (bp == std::string_view::npos || bp <= start)
        return {};
    std::string_view ident = msg.substr(start, bp - start); // "<comm>:<pid>"
    const auto colon = ident.rfind(':');
    if (colon != std::string_view::npos)
        ident = ident.substr(0, colon);
    return std::string(ident);
}

SignalObservation make_obs(const char* obs_type, std::string subject, std::string reason,
                           std::string kind, std::string sentence) {
    SignalObservation o;
    o.obs_type = obs_type;
    o.subject = std::move(subject);
    o.reason = std::move(reason);
    o.kind = std::move(kind);
    o.sentence = std::move(sentence);
    return o;
}

} // namespace

std::string kmsg_device_after(std::string_view msg, std::string_view marker) {
    const auto p = msg.find(marker);
    if (p == std::string_view::npos)
        return {};
    const auto start = p + marker.size();
    auto end = start;
    while (end < msg.size()) {
        const char c = msg[end];
        if (c == ')' || c == ',' || c == ' ' || c == ':')
            break;
        ++end;
    }
    return std::string(msg.substr(start, end - start));
}

std::string oom_victim_comm(std::string_view msg) {
    // Both real forms share this case-sensitive marker (cgroup-v2 lower-cases the
    // leading "Out" mid-sentence; on modern systemd the cgroup form is the common
    // case). Only the parenthesized comm is taken — the comm's closer is the LAST ')'
    // in the line (the un-parenthesised memory stats tail carries none), so a comm
    // like "(ba)sh" is not truncated.
    constexpr std::string_view kMark = "of memory: Killed process ";
    const auto p = msg.find(kMark);
    if (p == std::string_view::npos)
        return {};
    const auto lp = msg.find('(', p);
    if (lp == std::string_view::npos)
        return {};
    const auto rp = msg.rfind(')');
    if (rp == std::string_view::npos || rp <= lp + 1)
        return {};
    return std::string(msg.substr(lp + 1, rp - lp - 1));
}

std::optional<SignalObservation> classify_kernel_message(std::string_view msg) {
    // Most-severe / most-specific first; first match wins, so the rare co-fire (an
    // fs error that also logs a disk error) is claimed by the more specific marker.

    // ── os.bugcheck — fatal kernel panic ONLY ────────────────────────────────────
    // A survivable Oops / soft-lockup / taint is deliberately NOT mapped here: it
    // would inflate the BSOD-equivalent rate (the panic line is the only honest
    // "the kernel died" carrier). Note a real panic is often NOT flushed to the
    // persistent journal post-reboot — os.dirty_shutdown (below) is the reliable
    // "did it die" companion.
    if (contains(msg, "Kernel panic - not syncing"))
        return make_obs("os.bugcheck", "kernel", "panic", "panic", "Kernel panic");

    // ── memory.exhausted — kernel OOM-killer ─────────────────────────────────────
    if (const std::string victim = oom_victim_comm(msg); !victim.empty())
        return make_obs("memory.exhausted", victim, "oom-kill", "",
                        "Out of memory: kernel killed " + victim);

    // ── hw.error — machine-check / hardware error ────────────────────────────────
    // GHES / mcelog print "[Hardware Error]"; the throttled MCE summary prints
    // "Machine check events logged"; a fatal MCE prints "Machine Check Exception".
    // (Bare "mce:" is avoided — boot prints benign "mce: CPU supports N MCE banks".)
    if (contains(msg, "[Hardware Error]") || contains(msg, "Machine check events logged") ||
        contains(msg, "Machine Check Exception"))
        return make_obs("hw.error", "cpu", "machine-check", "", "Hardware/machine-check error");

    // ── fs.corruption — ext4 / xfs / btrfs metadata error ────────────────────────
    // Match the canonical error line (not the consequent "remounting read-only"),
    // so one corruption event yields one observation. Subject = backing device.
    for (const std::string_view marker : {std::string_view{"EXT4-fs error (device "},
                                          std::string_view{"BTRFS error (device "}}) {
        if (const std::string dev = kmsg_device_after(msg, marker); !dev.empty())
            return make_obs("fs.corruption", dev, "fs-error", "", "Filesystem error on " + dev);
    }
    if (contains(msg, "XFS (") &&
        (contains(msg, "orruption") || contains(msg, "Internal error") ||
         contains(msg, "metadata I/O error"))) {
        if (const std::string dev = kmsg_device_after(msg, "XFS ("); !dev.empty())
            return make_obs("fs.corruption", dev, "fs-error", "", "Filesystem error on " + dev);
    }

    // ── os.dirty_shutdown — journal recovery at mount (unclean prior shutdown) ────
    // ext4 logs "recovery complete", xfs logs "Starting recovery" only when the
    // journal/log needs replay = the box did not unmount cleanly. The reliable
    // "did it die" evidence, since a panic line rarely survives the reboot.
    if (contains(msg, "recovery complete")) {
        std::string dev = kmsg_device_after(msg, "EXT4-fs (");
        if (dev.empty())
            dev = kmsg_device_after(msg, "(device ");
        if (!dev.empty())
            return make_obs("os.dirty_shutdown", dev, "journal-recovery", "",
                            "Filesystem journal recovered after unclean shutdown on " + dev);
    }
    if (contains(msg, "Starting recovery") && contains(msg, "XFS (")) {
        if (const std::string dev = kmsg_device_after(msg, "XFS ("); !dev.empty())
            return make_obs("os.dirty_shutdown", dev, "journal-recovery", "",
                            "Filesystem journal recovered after unclean shutdown on " + dev);
    }

    // ── disk.error — block-layer / buffer I/O error ──────────────────────────────
    // Two real forms (live-captured): "Buffer I/O error on dev sdb, …" and the
    // block-layer "<type> error, dev sdb, sector N op …" (the "blk_update_request:"
    // prefix is stripped on modern kernels). Subject = backing device, the storm key.
    if (const std::string dev = kmsg_device_after(msg, "Buffer I/O error on dev "); !dev.empty())
        return make_obs("disk.error", dev, "io-error", "", "Disk I/O error on " + dev);
    if (contains(msg, ", dev ") && contains(msg, ", sector ")) {
        if (const std::string dev = kmsg_device_after(msg, ", dev "); !dev.empty())
            return make_obs("disk.error", dev, disk_error_reason(msg), "",
                            "Disk I/O error on " + dev);
    }

    // ── process.hung — kernel hung-task watchdog (D-state stall) ─────────────────
    if (contains(msg, "blocked for more than") && contains(msg, "task ")) {
        if (const std::string comm = hung_task_comm(msg); !comm.empty())
            return make_obs("process.hung", comm, "blocked", "hang",
                            comm + " blocked (kernel hung-task)");
    }

    return std::nullopt; // not a catalogued kernel reliability signal
}

} // namespace yuzu::agent::lnx
