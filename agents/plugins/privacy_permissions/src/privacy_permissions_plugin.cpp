/**
 * privacy_permissions_plugin.cpp -- per-app sensitive-permission grant visibility
 * (camera/microphone/location/full-disk-access equivalents), read-only. One action,
 * `permissions`, emitting `permissions|<os>|<app_id>|<category>|<state>|<raw>|<last_used_start>
 * |<last_used_stop>` rows (the leading field is the YAML's `row_kind` column; states and the
 * row contract in privacy_permissions_parsers.hpp):
 *   Linux:   xdg-desktop-portal PermissionStore.Lookup over the agent's OWN session bus (rung 1)
 *   macOS:   the system TCC.db + every /Users home's per-user TCC.db, read-only, in-process
 *            sqlite3 (rung 1) -- TCC-protected; an agent without Full Disk Access reads `denied`,
 *            recorded honestly, never claimed working without real-hardware evidence
 *   Windows: HKLM ProfileList -> each real profile's ConsentStore (live HKU hive or offline
 *            NTUSER.DAT mount) + the HKLM ...\CapabilityAccessManager\ConsentStore mirror (rung 1)
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

#include <string>
#include <string_view>

#include <yuzu/plugin.hpp>
#include <yuzu/string_utils.hpp>

#include "privacy_permissions_legs.hpp"

namespace {

#if defined(_WIN32)
constexpr std::string_view kOsName = "windows";
#elif defined(__APPLE__)
constexpr std::string_view kOsName = "macos";
#else
constexpr std::string_view kOsName = "linux";
#endif

const YuzuActionDescriptor kActionDescriptors[] = {
    {"permissions",
     /* linux_leg   = */
     {YUZU_SUPPORT_CONSTRAINED, 1,
      "xdg-desktop-portal org.freedesktop.impl.portal.PermissionStore.Lookup over the agent "
      "process's own session bus (sd_bus_open_user)",
      "never another user's session: a system-service agent normally has no session bus and "
      "reports unavailable, which says nothing about interactive users' grants; "
      "full_disk_access is unsupported (no portal equivalent)"},
     /* macos_leg   = */
     {YUZU_SUPPORT_CONSTRAINED, 1,
      "TCC.db read-only, in-process sqlite3: the system /Library/Application Support/"
      "com.apple.TCC/TCC.db plus each /Users/<home> (uid >= 500) per-user "
      "Library/Application Support/com.apple.TCC/TCC.db",
      "every TCC.db is TCC-protected: without Full Disk Access each read is denied; camera and "
      "microphone grants live only in the per-user dbs; location is unsupported (locationd, "
      "outside TCC)"},
     /* windows_leg = */
     {YUZU_SUPPORT_SUPPORTED, 1,
      "HKLM ProfileList enumeration, then each real profile's "
      "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore via its "
      "loaded HKU\\<SID> hive or an offline NTUSER.DAT mount (RegLoadKeyW, SeBackup/SeRestore), "
      "plus the same HKLM ConsentStore path",
      "measured on the-rig (Windows 11, LocalSystem) 2026-09-23; LocalSystem's own HKCU is not "
      "read; only a successfully read HKLM Deny (the device toggle) overrides a profile"}},
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
            // Same 8-field shape as a data row (row_kind `constrained`), so the YAML columns
            // still line up on the one row a consumer is most likely to be puzzled by.
            ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  "internal_error");
            ctx.write_output(pp::format_internal_error_row(kOsName));
            return 1;
        }
    }
};

YUZU_PLUGIN_EXPORT(PrivacyPermissionsPlugin)
