/**
 * msi_packages_plugin.cpp — MSI package inventory plugin for Yuzu
 *
 * Actions:
 *   "list"          — Lists all installed MSI packages.
 *   "product_codes" — Returns compact list of product code GUIDs.
 *
 * Windows-only. On other platforms, returns "platform not supported".
 *
 * Output is pipe-delimited via write_output():
 *   msi|product_code|name|version|install_location
 *   product_code|{GUID}|name
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
static constexpr const char* kVersionString        = "VersionString";
static constexpr const char* kInstallLocation      = "InstallLocation";
#endif

namespace {

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

// Replace invalid UTF-8 bytes with '?' (MSI data can contain non-UTF-8 chars).
std::string sanitize_utf8(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    size_t i = 0;
    while (i < s.size()) {
        auto c = static_cast<unsigned char>(s[i]);
        if (c < 0x80) {
            out += s[i]; ++i;
        } else if ((c >> 5) == 0x06 && i + 1 < s.size() &&
                   (static_cast<unsigned char>(s[i+1]) >> 6) == 0x02) {
            out += s[i]; out += s[i+1]; i += 2;
        } else if ((c >> 4) == 0x0E && i + 2 < s.size() &&
                   (static_cast<unsigned char>(s[i+1]) >> 6) == 0x02 &&
                   (static_cast<unsigned char>(s[i+2]) >> 6) == 0x02) {
            out += s[i]; out += s[i+1]; out += s[i+2]; i += 3;
        } else if ((c >> 3) == 0x1E && i + 3 < s.size() &&
                   (static_cast<unsigned char>(s[i+1]) >> 6) == 0x02 &&
                   (static_cast<unsigned char>(s[i+2]) >> 6) == 0x02 &&
                   (static_cast<unsigned char>(s[i+3]) >> 6) == 0x02) {
            out += s[i]; out += s[i+1]; out += s[i+2]; out += s[i+3]; i += 4;
        } else {
            out += '?'; ++i;
        }
    }
    return out;
}
#endif

int do_list(yuzu::CommandContext& ctx) {
#ifdef _WIN32
    char product_code[39]{}; // {GUID} = 38 chars + null
    int count = 0;
    for (DWORD idx = 0;
         MsiEnumProductsA(idx, product_code) == ERROR_SUCCESS;
         ++idx) {
        std::string_view code{product_code};
        auto name     = get_product_info(product_code, kInstalledProductName);
        auto version  = get_product_info(product_code, kVersionString);
        auto location = get_product_info(product_code, kInstallLocation);

        ctx.write_output(sanitize_utf8(std::format("msi|{}|{}|{}|{}",
            code,
            name.empty() ? "-" : name,
            version.empty() ? "-" : version,
            location.empty() ? "-" : location)));
        ++count;
    }
    if (count == 0) {
        ctx.write_output("msi|No MSI packages found|-|-|-");
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
    for (DWORD idx = 0;
         MsiEnumProductsA(idx, product_code) == ERROR_SUCCESS;
         ++idx) {
        std::string_view code{product_code};
        auto name = get_product_info(product_code, kInstalledProductName);
        ctx.write_output(sanitize_utf8(std::format("product_code|{}|{}",
            code,
            name.empty() ? "-" : name)));
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

}  // namespace

class MsiPackagesPlugin final : public yuzu::Plugin {
public:
    std::string_view name()        const noexcept override { return "msi_packages"; }
    std::string_view version()     const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Enumerates installed MSI packages and product codes (Windows only)";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {
            "list", "product_codes", nullptr
        };
        return acts;
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override {
        return {};
    }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx,
                std::string_view action,
                yuzu::Params /*params*/) override {
        if (action == "list")          return do_list(ctx);
        if (action == "product_codes") return do_product_codes(ctx);

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(MsiPackagesPlugin)
