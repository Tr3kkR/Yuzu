/**
 * msi_packages_plugin.cpp — MSI / pkgutil package inventory plugin for Yuzu
 *
 * Actions:
 *   "list"          — Lists all installed packages.
 *   "product_codes" — Returns compact list of package identifiers.
 *
 * Windows: enumerates MSI products via MsiEnumProductsA; the code slot is a
 *   real {GUID} product code.
 * macOS: enumerates `pkgutil --pkgs` receipts; the code slot is the honest
 *   reverse-domain package identifier (e.g. "com.apple.pkg.Core") — never a
 *   fabricated GUID.
 * Other platforms: returns "platform not supported".
 *
 * Output is pipe-delimited via write_output():
 *   msi|code|name|version|install_location
 *   product_code|code|name
 */

#include <yuzu/plugin.hpp>

#include <format>
#include <string>
#include <string_view>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <msi.h>
#pragma comment(lib, "msi.lib")

// String property names for MsiGetProductInfoA
static constexpr const char* kInstalledProductName = "InstalledProductName";
static constexpr const char* kVersionString = "VersionString";
static constexpr const char* kInstallLocation = "InstallLocation";
#elif defined(__APPLE__)
#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <memory>
#include <vector>

#include <spdlog/spdlog.h>
#include <yuzu/agent/subprocess_runner.hpp> // yuzu::agent::run_bounded_subprocess / probe_tool_path (Wave 4 PR4.3a, ADR-3002 rung 2)

#include "msi_packages_macos.hpp"
#endif

namespace {

// Replace invalid UTF-8 bytes with '?' (MSI/pkgutil data can contain
// non-UTF-8 chars). Platform-agnostic, reused by both the Windows and macOS
// branches below. (Pipe/newline escaping of dynamic macOS fields happens in the
// pure format_msi_row/format_product_code_row helpers in msi_packages_macos.hpp.)
std::string sanitize_utf8(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    size_t i = 0;
    while (i < s.size()) {
        auto c = static_cast<unsigned char>(s[i]);
        if (c < 0x80) {
            out += s[i];
            ++i;
        } else if ((c >> 5) == 0x06 && i + 1 < s.size() &&
                   (static_cast<unsigned char>(s[i + 1]) >> 6) == 0x02) {
            out += s[i];
            out += s[i + 1];
            i += 2;
        } else if ((c >> 4) == 0x0E && i + 2 < s.size() &&
                   (static_cast<unsigned char>(s[i + 1]) >> 6) == 0x02 &&
                   (static_cast<unsigned char>(s[i + 2]) >> 6) == 0x02) {
            out += s[i];
            out += s[i + 1];
            out += s[i + 2];
            i += 3;
        } else if ((c >> 3) == 0x1E && i + 3 < s.size() &&
                   (static_cast<unsigned char>(s[i + 1]) >> 6) == 0x02 &&
                   (static_cast<unsigned char>(s[i + 2]) >> 6) == 0x02 &&
                   (static_cast<unsigned char>(s[i + 3]) >> 6) == 0x02) {
            out += s[i];
            out += s[i + 1];
            out += s[i + 2];
            out += s[i + 3];
            i += 4;
        } else {
            out += '?';
            ++i;
        }
    }
    return out;
}

#ifdef _WIN32
// Get an MSI product property as a std::string.
std::string get_product_info(const char* product_code, const char* property) {
    char buf[512]{};
    DWORD size = sizeof(buf);
    if (MsiGetProductInfoA(product_code, property, buf, &size) == ERROR_SUCCESS) {
        return std::string(buf, size);
    }
    return {};
}
#elif defined(__APPLE__)
// Direct-argv, shell-free replacement for the old `/bin/sh -c` hop (Wave 4
// PR4.3a, ADR-3002 rung 2): argv[0] (always the probed absolute pkgutil
// path) is exec'd directly through the bounded runner — no shell in
// between, so no shell-quoting/injection surface, and shell_quote() is gone
// entirely (each argv element, including a package identifier, is passed
// verbatim — execve never re-parses it). Route through the bounded,
// fork-lock-covered runner instead of a raw, deadline-less popen (K-7/
// CDX-07). This matters most here: `list` issues up to 500 sequential
// `pkgutil --pkg-info` calls, so a single wedged receipt read could
// otherwise pin the instruction worker for the whole loop — each call
// carries a hard per-call deadline. Internal newlines in the captured
// output are preserved for the pure per-line parsers in
// msi_packages_macos.hpp.
std::string run_command(const std::vector<std::string>& argv) {
    if (argv.empty() || argv.front().empty())
        return {};
    auto res = yuzu::agent::run_bounded_subprocess(
        argv, yuzu::agent::SubprocessOptions{.deadline = std::chrono::seconds{15}});
    // A cut-short pkgutil returns empty/partial output that parses as "no
    // packages" — a silent false-negative. Warn so an operator can tell a
    // degraded scan from a genuinely empty receipt DB (sre-M1).
    if (res.timed_out || !res.tool_ran || res.output_truncated) {
        spdlog::warn("msi_packages: degraded run (timed_out={}, tool_ran={}, truncated={}): {}",
                     res.timed_out, res.tool_ran, res.output_truncated, argv.front());
    }
    std::string result = res.output;
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r'))
        result.pop_back();
    return result;
}

// pkgutil --pkg-info loops are sequential and per-package; a receipt DB can
// legitimately hold hundreds of entries, so bound the number of --pkg-info
// calls a single `list` gather issues.
constexpr std::size_t kMaxPackages = 500;
#endif

int do_list(yuzu::CommandContext& ctx) {
#ifdef _WIN32
    char product_code[39]{}; // {GUID} = 38 chars + null
    int count = 0;
    for (DWORD idx = 0; MsiEnumProductsA(idx, product_code) == ERROR_SUCCESS; ++idx) {
        std::string_view code{product_code};
        auto name = get_product_info(product_code, kInstalledProductName);
        auto version = get_product_info(product_code, kVersionString);
        auto location = get_product_info(product_code, kInstallLocation);

        ctx.write_output(sanitize_utf8(
            std::format("msi|{}|{}|{}|{}", code, name.empty() ? "-" : name,
                        version.empty() ? "-" : version, location.empty() ? "-" : location)));
        ++count;
    }
    if (count == 0) {
        ctx.write_output("msi|No MSI packages found|-|-|-");
    }
#elif defined(__APPLE__)
    using yuzu::msi_packages::macos::derive_display_name;
    using yuzu::msi_packages::macos::parse_pkg_ids;
    using yuzu::msi_packages::macos::parse_pkg_info;

    // msi_packages/do_list#1 (docs/agent-spawn-sink-manifest.md)
    auto pkgutil_path = yuzu::agent::probe_tool_path({"/usr/sbin/pkgutil"});
    auto ids = parse_pkg_ids(run_command({pkgutil_path, "--pkgs"}));
    const std::size_t total_seen = ids.size();
    const bool truncated = total_seen > kMaxPackages;
    if (truncated)
        ids.resize(kMaxPackages);

    int count = 0;
    for (const auto& id : ids) {
        // A receipt id is a reverse-domain name; one starting with '-' would be
        // eaten by pkgutil's OWN option parser as a flag. No shell is involved
        // -- this is argv[2] reaching getopt -- so quoting cannot help, and the
        // call's meaning would be unpredictable. Skip it instead.
        if (!id.empty() && id.front() == '-') {
            spdlog::warn("msi_packages: skipping option-like pkgutil receipt id '{}'", id);
            continue;
        }
        // msi_packages/do_list#2 -- one call per receipt, id passed as its
        // own argv element (no shell, so no quoting is needed at all).
        auto info = parse_pkg_info(run_command({pkgutil_path, "--pkg-info", id}), id);
        ctx.write_output(sanitize_utf8(yuzu::msi_packages::macos::format_msi_row(info)));
        ++count;
    }
    if (truncated) {
        // Honest truncation sentinel: the receipt DB held more packages than
        // kMaxPackages, so the inventory above is incomplete. The "__truncated__"
        // code slot cannot collide with a real reverse-domain package id, so a
        // positional downstream parser can distinguish this from a real row.
        ctx.write_output(std::format("msi|__truncated__|{}|-|-", total_seen));
    }
    if (count == 0) {
        ctx.write_output("msi|No packages found|-|-|-");
    }
#else
    ctx.write_output("error|platform not supported");
    return 1;
#endif
    return 0;
}

int do_product_codes(yuzu::CommandContext& ctx) {
#ifdef _WIN32
    char product_code[39]{};
    int count = 0;
    for (DWORD idx = 0; MsiEnumProductsA(idx, product_code) == ERROR_SUCCESS; ++idx) {
        std::string_view code{product_code};
        auto name = get_product_info(product_code, kInstalledProductName);
        ctx.write_output(
            sanitize_utf8(std::format("product_code|{}|{}", code, name.empty() ? "-" : name)));
        ++count;
    }
    if (count == 0) {
        ctx.write_output("product_code|none|-");
    }
#elif defined(__APPLE__)
    using yuzu::msi_packages::macos::derive_display_name;
    using yuzu::msi_packages::macos::parse_pkg_ids;

    // Names are derived purely from the identifier (pkgutil's --pkg-info
    // receipt carries no separate display-name field either — see
    // msi_packages_macos.hpp), so this action never needs the per-package
    // --pkg-info round trip that `list` does.
    // msi_packages/do_product_codes#1 (docs/agent-spawn-sink-manifest.md)
    auto ids =
        parse_pkg_ids(run_command({yuzu::agent::probe_tool_path({"/usr/sbin/pkgutil"}), "--pkgs"}));
    int count = 0;
    for (const auto& id : ids) {
        ctx.write_output(sanitize_utf8(yuzu::msi_packages::macos::format_product_code_row(id)));
        ++count;
    }
    if (count == 0) {
        ctx.write_output("product_code|none|-");
    }
#else
    ctx.write_output("error|platform not supported");
    return 1;
#endif
    return 0;
}

// ── ABI4 capability declarations (#2204) ────────────────────────────────────
//
// windows: MsiEnumProductsA/MsiGetProductInfoA -- native MSI API, rung 1.
// macos: pkgutil --pkgs / --pkg-info via the bounded argv runner (Wave 4
// PR4.3a, ADR-3002 rung 2) -- direct argv, no shell hop; ships via
// msi_packages_macos.hpp's pure parsers, unchanged.
// linux: no MSI/pkgutil equivalent -- the code returns "platform not
// supported" outright.
const YuzuActionDescriptor kActionDescriptors[] = {
    {"list",
     /* linux   = */ {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, nullptr},
     /* macos   = */ {YUZU_SUPPORT_SUPPORTED, 2, "pkgutil via bounded argv runner", nullptr},
     /* windows = */ {YUZU_SUPPORT_SUPPORTED, 1, "msi_api", nullptr}},
    {"product_codes",
     /* linux   = */ {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, nullptr},
     /* macos   = */ {YUZU_SUPPORT_SUPPORTED, 2, "pkgutil via bounded argv runner", nullptr},
     /* windows = */ {YUZU_SUPPORT_SUPPORTED, 1, "msi_api", nullptr}},
};

} // namespace

class MsiPackagesPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "msi_packages"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Enumerates installed packages and product codes (Windows MSI / macOS pkgutil)";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"list", "product_codes", nullptr};
        return acts;
    }

    const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }
    size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action,
                yuzu::Params /*params*/) override {
        if (action == "list")
            return do_list(ctx);
        if (action == "product_codes")
            return do_product_codes(ctx);

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(MsiPackagesPlugin)
