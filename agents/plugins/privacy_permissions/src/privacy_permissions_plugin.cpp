/**
 * privacy_permissions_plugin.cpp -- per-app sensitive-permission grant visibility
 * (camera/microphone/location/full-disk-access equivalents), read-only. One action,
 * `permissions`, emitting `permissions|<os>|<app_id>|<category>|<state>|<raw>
 * |<last_used_start>|<last_used_stop>` rows (states in privacy_permissions_parsers.hpp):
 *   Linux:   xdg-desktop-portal PermissionStore.Lookup over the session bus (rung 1)
 *   macOS:   TCC.db read-only, in-process sqlite3 (rung 1) -- SIP-protected; an unentitled
 *            agent is expected to read `denied`, recorded honestly, never claimed working
 *            without real-hardware evidence
 *   Windows: HKCU/HKLM ...\CapabilityAccessManager\ConsentStore registry walk (rung 1)
 *
 * Default-off (Forensics class, same posture as execution_artifacts) -- the server-side
 * kill-switch seed (server.cpp) gates whether this plugin's dispatch is even reachable; this
 * plugin performs no authz itself.
 *
 * WHY (state plainly, do not inflate): the roadmap's own research found zero documented
 * business/compliance driver anywhere in the four planning docs for this row -- the weakest
 * justification in the whole wave. Built anyway as fleet-visibility completeness: every
 * competitor EDR/MDM already reports this. See README "Caveats and known gaps" for the full
 * disclosure.
 *
 * All three legs are genuinely first-of-kind in this codebase (confirmed by repo-wide grep:
 * zero TCC.db, zero ConsentStore/CapabilityAccessManager, zero sd_bus_open_user anywhere
 * before this plugin) -- lower confidence than a typical Wave 8 row, several real unknowns
 * are named in each leg's own file banner and resolved only by a real-host probe, not by
 * assumption. Portable except the dispatch #if; all three descriptor legs are declared
 * unconditionally so the capability-matrix generator sees one shape everywhere.
 */

#include <yuzu/plugin.hpp>

#include "privacy_permissions_legs.hpp"

#include <yuzu/string_utils.hpp>

#include <string>
#include <string_view>

namespace {

const YuzuActionDescriptor kActionDescriptors[] = {
    {"permissions",
     /* linux_leg   = */
     {YUZU_SUPPORT_CONSTRAINED, 1,
      "xdg-desktop-portal org.freedesktop.impl.portal.PermissionStore.Lookup over the session "
      "bus; unavailable (no daemon/no session) on most non-sandboxed desktops", nullptr},
     /* macos_leg   = */
     {YUZU_SUPPORT_CONSTRAINED, 1,
      "TCC.db read-only, in-process sqlite3; SIP-protected, an unentitled agent is expected "
      "to read denied", nullptr},
     /* windows_leg = */
     {YUZU_SUPPORT_SUPPORTED, 1,
      "HKCU/HKLM SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\"
      "ConsentStore registry walk", nullptr}},
};

} // namespace

class PrivacyPermissionsPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "privacy_permissions"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Per-app sensitive-permission grants -- camera, microphone, location, "
               "full-disk-access equivalents (read-only)";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"permissions", nullptr};
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
        namespace pp = yuzu::privacy_permissions;
        // Frozen seam: nothing may escape the plugin ABI (the SDK trampoline does not catch),
        // so the whole body, the unknown-action row included, sits inside the one try.
        try {
            if (action != pp::kPermissionsAction) {
                ctx.write_output("unknown action: " + yuzu::util::safe_output_field(action));
                return 1;
            }
#if defined(_WIN32)
            return pp::collect_windows_permissions(ctx);
#elif defined(__linux__)
            return pp::collect_linux_permissions(ctx);
#elif defined(__APPLE__)
            return pp::collect_macos_permissions(ctx);
#endif
            return 1;
        } catch (...) {
            ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  "internal_error");
            ctx.write_output("constrained|internal_error");
            return 1;
        }
    }
};

YUZU_PLUGIN_EXPORT(PrivacyPermissionsPlugin)
