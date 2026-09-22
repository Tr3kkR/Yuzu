/**
 * browser_inventory_plugin.cpp — Chromium-family browser, profile and
 * extension inventory for Yuzu agents.
 *
 * Actions:
 *   "browsers"   — which Chromium-family browsers (Chrome, Edge, ...) are
 *                  installed on this host.
 *   "profiles"   — per-browser profile directories, read from each
 *                  browser's "Local State" file. Never emits an account
 *                  identifier -- see browser_inventory_parsers.hpp's
 *                  PRIVACY CONTRACT.
 *   "extensions" — per-profile extension install/enable state, read from
 *                  "Default/Secure Preferences" (preferred) or
 *                  "Default/Preferences" (fallback) -- see that header for
 *                  which file actually carries extensions.settings.
 *
 * Securable: Forensics, default-off via the server-side kill switch
 * (PluginConfigStore::seed_kill_switch_default_off, execution_artifacts'
 * precedent) -- the seed call itself is wired by P2a-3, not this package.
 *
 * PRIVACY CONTRACT (binding for every leg, every OS): never emit
 * user_name, gaia_id, e-mail addresses, browsing history, cookies or
 * bookmarks in any row. Enforced structurally in
 * browser_inventory_parsers.hpp -- BrowserProfileRow and ExtensionStateRow
 * simply have no such fields. The Secure Preferences HMAC/`protection`
 * tree is never read, let alone validated.
 *
 * WAVE 1 (this package, P2a-1): plugin scaffold + descriptor (3 actions x
 * 3 OS legs, all declared unconditionally per the capability-matrix
 * generator's contract), the pure JSON parsers, and a COMPILING STUB for
 * the Linux leg. macOS and Windows legs are FINAL ~20-line placeholders
 * this wave -- their real implementation follows as its own PR (see the
 * descriptor's PLANNED mechanism strings below). No CFPropertyList copy,
 * no subprocess, no Firefox/Safari code in this package.
 * WAVE 2 (P2a-2) replaces the Linux leg's stub body with the real
 * ~/.config/{google-chrome,microsoft-edge} walk.
 * WAVE 3 (P2a-3) wires registration/README/YAML/server kill-switch seed.
 *
 * This TU is portable except for its single dispatch #if, which selects
 * the one host leg to call -- the same shape peripherals_plugin.cpp uses,
 * so a single-OS build never needs to link the other two legs' symbols.
 *
 * Read-only: no action here mutates host state.
 */

#include <yuzu/plugin.hpp>

#include "browser_inventory_legs.hpp"

#include <yuzu/string_utils.hpp>

#include <string>
#include <string_view>

namespace {

// The nine per-action per-OS legs (three actions x three OSes) are FIXED
// and never wrapped in a preprocessor conditional -- a single-OS build
// still declares the full per-OS shape, per the capability-matrix
// generator's contract (peripherals_plugin.cpp's precedent comment).
//
// Linux: "browsers" is CONSTRAINED (presence-only detection, no
// version/channel probe in this package); "profiles"/"extensions" are
// SUPPORTED -- both backed by a real JSON read once P2a-2 lands the leg
// body (this package ships only the pure parsers + a compiling stub, see
// the file banner). macOS and Windows: PLANNED on all three actions this
// wave, mechanism strings name the follow-up PR's plan.
const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "browsers",
        /* .linux_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 1,
         "~/.config/{google-chrome,microsoft-edge} directory presence",
         "presence-only; no version/channel detection in this package"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_PLANNED, 1,
         "/Applications/{Google Chrome,Microsoft Edge}.app Info.plist + ~/Library/Application "
         "Support/{Google/Chrome,Microsoft Edge} walk; Safari bundle + .appex containers",
         "follows as its own PR"},
        /* .windows_leg = */
        {YUZU_SUPPORT_PLANNED, 1,
         "ProfileList walk + %LOCALAPPDATA% User Data; Program Files Application\\<semver> dirs",
         "follows as its own PR"},
    },
    {
        /* .action      = */ "profiles",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "~/.config/{google-chrome,microsoft-edge}/Local State JSON read", nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_PLANNED, 1,
         "/Applications/{Google Chrome,Microsoft Edge}.app Info.plist + ~/Library/Application "
         "Support/{Google/Chrome,Microsoft Edge} walk; Safari bundle + .appex containers",
         "follows as its own PR"},
        /* .windows_leg = */
        {YUZU_SUPPORT_PLANNED, 1,
         "ProfileList walk + %LOCALAPPDATA% User Data; Program Files Application\\<semver> dirs",
         "follows as its own PR"},
    },
    {
        /* .action      = */ "extensions",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "Default/Secure Preferences (fallback Default/Preferences) extensions.settings JSON "
         "read",
         nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_PLANNED, 1,
         "/Applications/{Google Chrome,Microsoft Edge}.app Info.plist + ~/Library/Application "
         "Support/{Google/Chrome,Microsoft Edge} walk; Safari bundle + .appex containers",
         "follows as its own PR"},
        /* .windows_leg = */
        {YUZU_SUPPORT_PLANNED, 1,
         "ProfileList walk + %LOCALAPPDATA% User Data; Program Files Application\\<semver> dirs",
         "follows as its own PR"},
    },
};

} // namespace

class BrowserInventoryPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "browser_inventory"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Chromium-family browser, profile and extension inventory";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"browsers", "profiles", "extensions", nullptr};
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
        const auto act = yuzu::browser_inventory::parse_action(action);
        if (!act) {
            // `action` is request-supplied and lands in a pipe-delimited stream, so
            // it goes through the shared escaper like any other untrusted field.
            // This is deliberately NOT a row (no leading kind token), which is why
            // it does not use the legs.hpp formatters.
            ctx.write_output(std::string{"unknown action: "} +
                             yuzu::util::safe_output_field(action));
            return 1;
        }

        // Every failure-token literal this plugin dir emits matches
        // ^(windows|macos|linux):[a-z0-9_]+(:[a-z0-9_]+)*$ -- Yuzu targets
        // exactly these three OSes (CLAUDE.md "Target architecture"), so
        // there is deliberately no fourth branch here.
#if defined(_WIN32)
        return yuzu::browser_inventory::run_windows(ctx, *act);
#elif defined(__linux__)
        return yuzu::browser_inventory::run_linux(ctx, *act);
#elif defined(__APPLE__)
        return yuzu::browser_inventory::run_macos(ctx, *act);
#endif
        return 1; // unreachable on a supported build (see the comment above); avoids
                  // falling off the end of a non-void function if one ever isn't.
    }
};

YUZU_PLUGIN_EXPORT(BrowserInventoryPlugin)
