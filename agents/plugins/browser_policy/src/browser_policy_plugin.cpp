/**
 * browser_policy_plugin.cpp — enterprise-managed browser policy inventory.
 *
 * Action:
 *   "policies" — one `policy|...` row per configured Chrome/Chromium/Edge
 *                policy: browser, mandatory|recommended level, machine|user
 *                scope, name, typed value, and the file it came from (row
 *                schema: browser_policy_parsers.hpp).
 *
 * Sources (all rung 1, file/registry truth, no process spawn):
 *   Windows  HKLM\SOFTWARE\Policies\{Google\Chrome,Microsoft\Edge} (+ the
 *            Recommended subkeys)                       [P2b-2, win.cpp]
 *   Linux    /etc/opt/{chrome,edge} and /etc/chromium policies/{managed,
 *            recommended} JSON files                    [linux.cpp]
 *   macOS    /Library/Managed Preferences/{,<user>/}{com.google.Chrome,
 *            com.microsoft.Edge}.plist                  [macos.cpp]
 *
 * This is operator/IT-authored configuration, not personal data, so it is an
 * ordinary `Inventory` read with no default-off kill switch (that gate is
 * for plugins that read user-identifying data, which this one does not).
 *
 * Portable except for the single dispatch #if selecting the host leg; all
 * three descriptor legs are declared unconditionally so the capability-matrix
 * generator (#2204) sees a stable shape whichever OS built the plugin.
 */

#include <yuzu/plugin.hpp>

#include "browser_policy_legs.hpp"

#include <yuzu/string_utils.hpp>

#include <string>
#include <string_view>

namespace {

const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "policies",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "/etc/opt/{chrome,edge} and /etc/chromium policies/{managed,recommended}/*.json "
         "(nlohmann)",
         nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 1,
         "/Library/Managed Preferences/{,<user>/}{com.google.Chrome,com.microsoft.Edge}.plist "
         "(CFPropertyListCreateWithData)",
         "managed (mandatory) policy only: Managed Preferences carries no recommended level; "
         "verified against a synthetic plist tree only, no live managed Mac in this run"},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "HKLM\\SOFTWARE\\Policies\\{Google\\Chrome,Microsoft\\Edge} registry reads "
         "(RegKey enumerate_value_names)",
         nullptr},
    },
};

} // namespace

class BrowserPolicyPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "browser_policy"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Enterprise-managed Chrome and Edge browser policy inventory";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"policies", nullptr};
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
        if (action != "policies") {
            // `action` is request-supplied and lands in a pipe-delimited stream, so it
            // goes through the shared escaper. Deliberately NOT a `policy|` row.
            ctx.write_output(std::string{"unknown action: "} +
                             yuzu::util::safe_output_field(action));
            return 1;
        }

        // No exception may cross the plugin ABI on any leg.
        try {
#if defined(_WIN32)
            return yuzu::browser_policy::run_windows(ctx);
#elif defined(__linux__)
            return yuzu::browser_policy::run_linux(ctx);
#elif defined(__APPLE__)
            return yuzu::browser_policy::run_macos(ctx);
#endif
        } catch (...) {
            ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  yuzu::browser_policy::kExceptionToken);
            return 1;
        }
        return 1; // unreachable on a supported build (Windows/Linux/macOS only).
    }
};

YUZU_PLUGIN_EXPORT(BrowserPolicyPlugin)
