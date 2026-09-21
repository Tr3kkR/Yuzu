/**
 * system_hardening_plugin.cpp -- exploit-mitigation / kernel-hardening
 * posture for Yuzu (read-only).
 *
 * Action:
 *   "posture" -- one row per allowlisted key:
 *                  posture|<os>|<key>|<raw>|<state>
 *                state is enabled | disabled | partial | unmodelled | absent |
 *                unreadable (see system_hardening_parsers.hpp). Every key
 *                reads as a value, `absent` or `unreadable` -- one token never
 *                stands for two causes.
 *
 * Mechanisms (all rung 1, no spawn):
 *   Linux   -- allowlisted /proc/sys reads (open/read, errno-classified)
 *   macOS   -- allowlisted sysctlbyname reads
 *   Windows -- Session Manager\kernel mitigation registry + GetProcessMitigationPolicy
 *              (system_hardening_win.cpp)
 *
 * WHY (state plainly, do not inflate): there is no documented business
 * driver for this plugin. No capability-map, enterprise-parity, SOC 2 or
 * roadmap entry names it; the nearest idea (docs/roadmap.md Issue 18.2,
 * CIS-shaped compliance reporting) is a reporting layer over rules that would
 * have to exist elsewhere and is itself only Proposed. This is capability-gap
 * reasoning, not evidenced demand.
 *
 * This TU is portable except for its single dispatch #if; all three
 * descriptor legs are declared unconditionally so the capability-matrix
 * generator (#2204) sees a stable shape on every host.
 */

#include <yuzu/plugin.hpp>

#include "system_hardening_legs.hpp"

#include <yuzu/string_utils.hpp>

#include <string>
#include <string_view>

namespace {

const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "posture",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "allowlisted /proc/sys reads (open/read, errno-classified absent/unreadable)", nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "allowlisted sysctlbyname reads (kern.securelevel/coredump/sugid_coredump/bootargs)",
         nullptr},
        /* .windows_leg = */
        // INTEGRATOR: the 4th (notes) field is filled from P81b-2's rig-probe
        // banner in system_hardening_win.cpp; nullptr until then.
        {YUZU_SUPPORT_SUPPORTED, 1,
         "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel mitigation "
         "registry + GetProcessMitigationPolicy (agent process)",
         nullptr},
    },
};

} // namespace

class SystemHardeningPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "system_hardening"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Exploit-mitigation and kernel-hardening posture (read-only)";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"posture", nullptr};
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
        if (action != "posture") {
            // `action` is request-supplied and lands in a pipe-delimited stream.
            ctx.write_output(std::string{"unknown action: "} +
                             yuzu::util::safe_output_field(action));
            return 1;
        }
        // Yuzu targets exactly these three OSes, so there is no fourth branch.
#if defined(_WIN32)
        return yuzu::system_hardening::collect_posture_win(ctx);
#elif defined(__linux__)
        return yuzu::system_hardening::collect_posture_linux(ctx);
#elif defined(__APPLE__)
        return yuzu::system_hardening::collect_posture_macos(ctx);
#endif
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(SystemHardeningPlugin)
