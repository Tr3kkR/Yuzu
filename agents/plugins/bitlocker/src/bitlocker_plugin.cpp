/**
 * bitlocker_plugin.cpp — Disk encryption status plugin for Yuzu
 *
 * Actions:
 *   "state" — BitLocker / LUKS / FileVault status per volume.
 *
 * Output is pipe-delimited via write_output().
 */

#include <yuzu/plugin.hpp>
#include <yuzu/string_utils.hpp> // yuzu::util::safe_output_field (plg-L1)

#include <array>
#include <cstdio>
#include <format>
#include <sstream>
#include <string>
#include <string_view>

#ifndef _WIN32
#include <chrono>
#include <spdlog/spdlog.h>
#include <yuzu/agent/subprocess_runner.hpp> // yuzu::agent::run_bounded_subprocess (K-7/CDX-07)
#endif

#ifdef __APPLE__
#include "bitlocker_macos_apfs.hpp"
#endif

namespace {

#ifndef _WIN32
// A generous per-call wall-clock bound for the local disk-encryption tools
// (fdesetup/diskutil/lsblk/cryptsetup). Long enough never to fire in practice,
// short enough that a wedged tool cannot pin the instruction worker forever.
constexpr std::chrono::seconds kBitlockerCmdDeadline{20};
#endif

std::string run_command(const char* cmd) {
#ifdef _WIN32
    std::string result;
    std::array<char, 256> buf{};
    FILE* pipe = _popen(cmd, "r");
    if (!pipe)
        return result;
    while (fgets(buf.data(), static_cast<int>(buf.size()), pipe)) {
        result += buf.data();
    }
    _pclose(pipe);
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r'))
        result.pop_back();
    return result;
#else
    // Route through the bounded, fork-lock-covered runner instead of a raw,
    // deadline-less popen (K-7/CDX-07). `/bin/sh -c` preserves the exact shell
    // semantics popen used (the commands rely on `2>/dev/null` redirects), so
    // the returned stdout blob is byte-identical to the old path — only now it
    // carries a hard deadline, an output cap, and the global fork-lock. stderr
    // already goes to /dev/null (merge_stderr=false), matching the commands.
    auto res = yuzu::agent::run_bounded_subprocess(
        {"/bin/sh", "-c", cmd},
        yuzu::agent::SubprocessOptions{.deadline = kBitlockerCmdDeadline});
    // A deadline-killed or exec-failed tool returns empty/partial output that
    // would otherwise parse as a legitimate "FileVault absent / no volumes" —
    // a silent false-negative. Warn so an operator can tell a cut-short scan
    // from a genuinely empty result (sre-M1; mirrors the event_logs pattern).
    if (res.timed_out || !res.tool_ran || res.output_truncated) {
        spdlog::warn("bitlocker: degraded shell-out (timed_out={}, tool_ran={}, truncated={}): {}",
                     res.timed_out, res.tool_ran, res.output_truncated, cmd);
    }
    std::string result = res.output;
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r'))
        result.pop_back();
    return result;
#endif
}

#ifdef _WIN32

void parse_bitlocker_status(yuzu::CommandContext& ctx, const std::string& output) {
    std::istringstream iss(output);
    std::string line;
    std::string drive, conversion, pct_encrypted, method, protection;

    auto emit_volume = [&]() {
        if (!drive.empty()) {
            ctx.write_output(std::format("volume|{}|{}|{}|{}|{}", drive, conversion, pct_encrypted,
                                         method, protection));
        }
        drive.clear();
        conversion.clear();
        pct_encrypted.clear();
        method.clear();
        protection.clear();
    };

    while (std::getline(iss, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
            line.pop_back();
        if (line.empty())
            continue;

        // Volume lines look like: "Volume C: [OS]"
        if (line.find("Volume") == 0 && line.find(':') != std::string::npos) {
            emit_volume();
            // Extract drive letter
            auto colon = line.find(':');
            if (colon > 0) {
                drive = line.substr(colon - 1, 2); // e.g. "C:"
            }
            continue;
        }

        auto colon = line.find(':');
        if (colon == std::string::npos)
            continue;

        auto key = line.substr(0, colon);
        auto val = line.substr(colon + 1);
        // Trim
        while (!key.empty() && (key.front() == ' ' || key.front() == '\t'))
            key.erase(key.begin());
        while (!key.empty() && key.back() == ' ')
            key.pop_back();
        while (!val.empty() && val.front() == ' ')
            val.erase(val.begin());
        while (!val.empty() && val.back() == ' ')
            val.pop_back();

        if (key == "Conversion Status") {
            conversion = val;
        } else if (key == "Percentage Encrypted") {
            pct_encrypted = val;
        } else if (key == "Encryption Method") {
            method = val;
        } else if (key == "Protection Status") {
            protection = val;
        }
    }
    emit_volume();
}

#elif defined(__linux__)

void list_luks_volumes(yuzu::CommandContext& ctx) {
    // List block devices and check for LUKS
    auto lsblk = run_command("lsblk -o NAME,TYPE,FSTYPE -n -l 2>/dev/null");
    if (lsblk.empty()) {
        ctx.write_output("volume|none|no_block_devices");
        return;
    }

    std::istringstream iss(lsblk);
    std::string line;
    bool found = false;
    while (std::getline(iss, line)) {
        std::istringstream ls(line);
        std::string name, type, fstype;
        ls >> name >> type >> fstype;

        if (fstype == "crypto_LUKS" || type == "crypt") {
            // Try to get status
            auto status_cmd = std::format("cryptsetup status {} 2>/dev/null", name);
            auto status = run_command(status_cmd.c_str());
            std::string state = "unknown";
            if (status.find("is active") != std::string::npos) {
                state = "active";
            } else if (status.find("is inactive") != std::string::npos) {
                state = "inactive";
            } else if (!status.empty()) {
                state = "present";
            }
            ctx.write_output(std::format("volume|{}|{}|{}", name, type, state));
            found = true;
        }
    }
    if (!found) {
        ctx.write_output("volume|none|no_encrypted_volumes");
    }
}

#elif defined(__APPLE__)

// Emits the honest per-volume FileVault/encryption status. Two signals:
//  - `fdesetup status` — a global on/off read, retained unconditionally as a
//    corroborating signal AND as the fallback when diskutil parsing below
//    yields no volumes (e.g. diskutil unavailable, unexpected output shape).
//  - `diskutil apfs list` — enumerated per APFS volume, parsed by the pure
//    header so it stays fixture-testable. Encryption is binary
//    (encrypted/not_encrypted/unknown) — APFS has no meaningful
//    percentage-encrypted to report, unlike BitLocker's conversion-in-
//    progress state, so none is fabricated here.
void report_filevault_status(yuzu::CommandContext& ctx) {
    auto fdesetup_output = run_command("fdesetup status 2>/dev/null");
    if (fdesetup_output.find("On") != std::string::npos ||
        fdesetup_output.find("FileVault is On") != std::string::npos) {
        ctx.write_output("filevault|enabled");
    } else if (fdesetup_output.find("Off") != std::string::npos ||
               fdesetup_output.find("FileVault is Off") != std::string::npos) {
        ctx.write_output("filevault|disabled");
    } else {
        // Route the raw fdesetup text through safe_output_field (plg-L1): even
        // though bitlocker is a key|value plugin (a literal '|' stays in the
        // value), a multi-line fdesetup diagnostic would otherwise inject a row
        // past write_output's newline framing.
        ctx.write_output(
            std::format("filevault|unknown|{}", yuzu::util::safe_output_field(fdesetup_output)));
    }

    auto diskutil_output = run_command("diskutil apfs list 2>/dev/null");
    auto volumes = yuzu::bitlocker::macos::parse_diskutil_apfs_list(diskutil_output);
    for (const auto& vol : volumes) {
        // plg-L1 (round-4 review): escape every dynamic field before the positional
        // `volume|...` protocol — an APFS volume label/type/state with a '|' or
        // newline would otherwise shift columns or inject a row (same fix already
        // applied to the fdesetup diagnostic row above).
        ctx.write_output(
            std::format("volume|{}|{}|{}", yuzu::util::safe_output_field(yuzu::bitlocker::macos::volume_label(vol)),
                        yuzu::util::safe_output_field(yuzu::bitlocker::macos::volume_type(vol)),
                        yuzu::util::safe_output_field(vol.encrypted_state)));
    }
    // If diskutil yielded nothing parseable, the fdesetup row above already
    // served as the fallback signal — no synthetic "no volumes" row needed.
}

#endif

} // namespace

class BitlockerPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "bitlocker"; }
    std::string_view version() const noexcept override { return "0.1.0"; }
    std::string_view description() const noexcept override {
        return "Disk encryption status — BitLocker, LUKS, FileVault";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"state", nullptr};
        return acts;
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }
    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action,
                yuzu::Params /*params*/) override {

        if (action == "state") {
#ifdef _WIN32
            auto output = run_command("manage-bde -status");
            if (output.empty()) {
                ctx.write_output("error|manage-bde not available or access denied");
                return 1;
            }
            parse_bitlocker_status(ctx, output);
#elif defined(__linux__)
            list_luks_volumes(ctx);
#elif defined(__APPLE__)
            report_filevault_status(ctx);
#endif
            return 0;
        }

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(BitlockerPlugin)
