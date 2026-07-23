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

#include <spdlog/spdlog.h>
#include <yuzu/agent/subprocess_runner.hpp> // yuzu::agent::run_bounded_subprocess (K-7/CDX-07)

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
// Run a shell command, capturing stdout with trailing newline(s) stripped.
// Internal newlines are preserved — callers that need per-line data (pkgutil
// output) parse those via the pure helpers in msi_packages_macos.hpp.
std::string run_command(const std::string& cmd) {
    // Route through the bounded, fork-lock-covered runner instead of a raw,
    // deadline-less popen (K-7/CDX-07). This matters most here: `list` issues up
    // to 500 sequential `pkgutil --pkg-info` calls, so a single wedged receipt
    // read could otherwise pin the instruction worker for the whole loop. Each
    // call now carries a hard per-call deadline. `/bin/sh -c` preserves the
    // shell semantics popen used (the commands rely on `2>/dev/null`), so the
    // returned stdout blob is byte-identical; internal newlines are preserved
    // for the pure per-line parsers in msi_packages_macos.hpp.
    auto res = yuzu::agent::run_bounded_subprocess(
        {"/bin/sh", "-c", cmd},
        yuzu::agent::SubprocessOptions{.deadline = std::chrono::seconds{15}});
    // A cut-short pkgutil returns empty/partial output that parses as "no
    // packages" — a silent false-negative. Warn so an operator can tell a
    // degraded scan from a genuinely empty receipt DB (sre-M1).
    if (res.timed_out || !res.tool_ran || res.output_truncated) {
        spdlog::warn("msi_packages: degraded shell-out (timed_out={}, tool_ran={}, truncated={}): {}",
                     res.timed_out, res.tool_ran, res.output_truncated, cmd);
    }
    std::string result = res.output;
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r'))
        result.pop_back();
    return result;
}

// Single-quote a package identifier for safe interpolation into a shell
// command line (identifiers come from a prior `pkgutil --pkgs` call, but are
// still untrusted free text as far as this process is concerned).
std::string shell_quote(std::string_view s) {
    std::string out = "'";
    for (char c : s) {
        if (c == '\'')
            out += "'\\''";
        else
            out += c;
    }
    out += "'";
    return out;
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

    auto ids = parse_pkg_ids(run_command("pkgutil --pkgs 2>/dev/null"));
    const std::size_t total_seen = ids.size();
    const bool truncated = total_seen > kMaxPackages;
    if (truncated)
        ids.resize(kMaxPackages);

    int count = 0;
    for (const auto& id : ids) {
        auto info = parse_pkg_info(
            run_command(std::format("pkgutil --pkg-info {} 2>/dev/null", shell_quote(id))), id);
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
    auto ids = parse_pkg_ids(run_command("pkgutil --pkgs 2>/dev/null"));
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
