/**
 * bitlocker_plugin.cpp — Disk encryption status plugin for Yuzu
 *
 * Actions:
 *   "state" — BitLocker / LUKS / FileVault status per volume.
 *
 * Output is pipe-delimited via write_output().
 */

#include <yuzu/plugin.hpp>

#include <array>
#include <cstdio>
#include <format>
#include <sstream>
#include <string>
#include <string_view>

namespace {

std::string run_command(const char* cmd) {
    std::string result;
    std::array<char, 256> buf{};
#ifdef _WIN32
    FILE* pipe = _popen(cmd, "r");
#else
    FILE* pipe = popen(cmd, "r");
#endif
    if (!pipe)
        return result;
    while (fgets(buf.data(), static_cast<int>(buf.size()), pipe)) {
        result += buf.data();
    }
#ifdef _WIN32
    _pclose(pipe);
#else
    pclose(pipe);
#endif
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r'))
        result.pop_back();
    return result;
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
            auto output = run_command("fdesetup status 2>/dev/null");
            if (output.find("On") != std::string::npos ||
                output.find("FileVault is On") != std::string::npos) {
                ctx.write_output("filevault|enabled");
            } else if (output.find("Off") != std::string::npos ||
                       output.find("FileVault is Off") != std::string::npos) {
                ctx.write_output("filevault|disabled");
            } else {
                ctx.write_output(std::format("filevault|unknown|{}", output));
            }
#endif
            return 0;
        }

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(BitlockerPlugin)
