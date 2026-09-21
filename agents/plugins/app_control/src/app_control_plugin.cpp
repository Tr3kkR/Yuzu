/**
 * app_control_plugin.cpp -- read-only application-control (WDAC / AppLocker) posture.
 *
 *   "wdac_policy"      -- Code Integrity policy state (registry + active .cip presence).
 *   "applocker_policy" -- AppLocker rule-collection enforcement mode and rule count.
 *
 * Refs #282 (PARTIAL): read-only posture only; add_rule / remove_rule /
 * get_blocked_events and a Linux fapolicyd leg are NOT implemented. This is not
 * EDR-class telemetry (docs/roadmap.md Phase 18 "Out of scope"): it reads the state
 * of an OS-native control, it does not replicate endpoint detection.
 *
 * Application control is a Windows-only concept here, so Linux/macOS report the fixed
 * `<action>|unsupported|windows_only_concept` row with an UNAVAILABLE status. This TU
 * is portable: all three descriptor legs are declared on every build and execute()
 * branches on _WIN32 only to choose the real leg (app_control_win.cpp).
 */

#include <yuzu/plugin.hpp>

#include "app_control_parsers.hpp"

#include <yuzu/string_utils.hpp>

#include <exception>
#include <string>
#include <string_view>

#ifdef _WIN32
namespace yuzu::app_control {
// Defined in app_control_win.cpp (Windows-only source, meson.build).
int collect_wdac(yuzu::CommandContext& ctx);
int collect_applocker(yuzu::CommandContext& ctx);
} // namespace yuzu::app_control
#endif

namespace {

// Descriptor legs are FIXED, never preprocessor-conditional. The Windows notes' probe
// outcomes are PENDING the integration rig session and are pasted verbatim from
// app_control_win.cpp's banner before merge -- nothing below is a claimed probe result.
const YuzuOsLeg kLinuxLeg{YUZU_SUPPORT_UNSUPPORTED, 0, nullptr,
                          "Windows-only concept; Linux fapolicyd is a separate, unimplemented "
                          "leg of #282"};
const YuzuOsLeg kMacosLeg{YUZU_SUPPORT_UNSUPPORTED, 0, nullptr,
                          "Windows-only concept; macOS app-trust (Gatekeeper/SIP) is covered by "
                          "platform_security"};

const YuzuActionDescriptor kActionDescriptors[] = {
    {"wdac_policy", kLinuxLeg, kMacosLeg,
     {YUZU_SUPPORT_SUPPORTED, 1,
      "RegEnumValueW HKLM\\SYSTEM\\CurrentControlSet\\Control\\CI\\Policy + std::filesystem "
      "listing of %SystemRoot%\\System32\\CodeIntegrity\\CiPolicies\\Active\\*.cip",
      "RIG PROBE PENDING (CI\\Policy values under LocalSystem; VerifiedAndReputablePolicyState "
      "value meanings): quoted verbatim from the integration rig session before merge. An "
      "unmodelled value is reported 'unmodelled'; an unreadable key is constrained or "
      "permission_denied, never absent"}},
    {"applocker_policy", kLinuxLeg, kMacosLeg,
     {YUZU_SUPPORT_SUPPORTED, 1,
      "wmi_bounded run_bounded_wmi_query root\\StandardCimv2\\Security\\ApplicationControl "
      "MSFT_ApplockerPolicy; registry walk of "
      "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\SrpV2\\<collection> when the class is "
      "absent or empty",
      "RIG PROBE PENDING (MSFT_ApplockerPolicy class presence + property names, SrpV2 walk): "
      "quoted verbatim from the integration rig session before merge. The CIM namespace is "
      "caller-side allowlisted"}},
};

} // namespace

class AppControlPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "app_control"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Read-only effective WDAC and AppLocker application-control policy posture "
               "(Windows-only)";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"wdac_policy", "applocker_policy", nullptr};
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

    // No exception may escape: the plugin-ABI trampoline and LocalDispatcher have no
    // catch of their own (autoruns / windows_optional_features precedent).
    int execute(yuzu::CommandContext& ctx, std::string_view action,
                yuzu::Params /*params*/) override {
        try {
            if (action == "wdac_policy" || action == "applocker_policy") {
#ifdef _WIN32
                return action == "wdac_policy" ? yuzu::app_control::collect_wdac(ctx)
                           : yuzu::app_control::collect_applocker(ctx);
#else
                ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE,
                                      YUZU_RESULT_COMPLETENESS_PARTIAL,
                                      yuzu::app_control::kUnsupportedWindowsOnly);
                // `action` string-equals one of the two literals just checked, never free text.
                ctx.write_output(yuzu::app_control::format_unsupported_row(action));
                return 1;
#endif
            }

            // `action` is request-supplied and lands in a pipe-delimited stream.
            ctx.write_output(std::string{"unknown action: "} +
                             yuzu::util::safe_output_field(action));
            return 1;
        } catch (const std::exception& e) {
            ctx.write_output(yuzu::app_control::format_constrained_row("unhandled_exception"));
            ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  std::string{"unhandled exception: "} +
                                      yuzu::util::safe_output_field(e.what()));
            return 1;
        } catch (...) {
            ctx.write_output(yuzu::app_control::format_constrained_row("unhandled_exception"));
            ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  "unhandled exception of unknown type inside execute()");
            return 1;
        }
    }
};

YUZU_PLUGIN_EXPORT(AppControlPlugin)
