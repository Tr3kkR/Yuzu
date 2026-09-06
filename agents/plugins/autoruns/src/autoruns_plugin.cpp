/**
 * autoruns_plugin.cpp — persistence-source enumeration ("what starts
 * automatically") across Windows, Linux and macOS.
 *
 * Actions:
 *   "catalog" — lists every SourceId this plugin knows about (the full
 *               34-source catalog, every OS), with the DECLARED support level
 *               this BUILD carries for it. No OS call: a pure reflection of
 *               autoruns_catalog.hpp.
 *   "list"    — runs every per-OS leg (collect_windows / collect_linux /
 *               collect_macos, autoruns_legs.hpp) and emits a `source|`
 *               status line per source plus zero or more `autorun|` rows for
 *               each source that produced data. `sources=` filters to a
 *               comma-separated SourceId allow-list; leg-internal.
 *
 * This TU is fully portable -- no target-OS #if of any kind. All three legs
 * are declared unconditionally so a single-OS build always links (see
 * autoruns_legs.hpp's foreign-OS stub) and the capability matrix generator
 * (#2204) sees a complete, stable three-OS shape regardless of which OS
 * built this plugin.
 *
 * Read-only: no action here mutates host state, spawns a process, or writes
 * to the registry/filesystem/launchd.
 */

#include <yuzu/plugin.hpp>

#include "autoruns_catalog.hpp"
#include "autoruns_legs.hpp"
#include "autoruns_parsers.hpp"

#include <yuzu/string_utils.hpp>

#include <exception>
#include <optional>
#include <string>
#include <string_view>

namespace {

// Both actions declare the SAME three mechanism strings: `catalog` and
// `list` describe the identical underlying acquisition capability at
// different fidelities (declared-only vs actually-executed), so there is no
// separate "how catalog works" mechanism to name -- it is a pure read of
// this TU's own static data, on every OS.
//
// WAVE7_NOTES_PENDING: the `fallback` text below is a placeholder. PR11.5
// (P15) replaces it with the reviewed, spike-verified note text this
// mechanism deserves -- see the wave's own decision record.
const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "list",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "file reads of cron/anacron/at/systemd unit dirs/XDG autostart; systemctl list-timers "
         "argv fallback only when no unit dir is readable",
         "WAVE7_NOTES_PENDING"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "CFPropertyListCreateWithData over launchd plists; file reads of /etc/periodic, "
         "/etc/emond.d",
         "WAVE7_NOTES_PENDING"},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "Reg*W over HKLM + every HKU via win_profiles with_user_hive; ITaskService COM; WMI "
         "root\\subscription bounded query",
         "WAVE7_NOTES_PENDING"},
    },
    {
        /* .action      = */ "catalog",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "file reads of cron/anacron/at/systemd unit dirs/XDG autostart; systemctl list-timers "
         "argv fallback only when no unit dir is readable",
         "WAVE7_NOTES_PENDING"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "CFPropertyListCreateWithData over launchd plists; file reads of /etc/periodic, "
         "/etc/emond.d",
         "WAVE7_NOTES_PENDING"},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "Reg*W over HKLM + every HKU via win_profiles with_user_hive; ITaskService COM; WMI "
         "root\\subscription bounded query",
         "WAVE7_NOTES_PENDING"},
    },
};

} // namespace

class AutorunsPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "autoruns"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Enumerates persistence sources (what starts automatically) across Windows, "
               "Linux and macOS";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"list", "catalog", nullptr};
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

    int execute(yuzu::CommandContext& ctx, std::string_view action, yuzu::Params params) override {
        // No exception may escape this function: every leg below eventually
        // calls into untrusted-input parsers and third-party OS APIs, and an
        // uncaught exception crossing the extern "C" plugin-ABI boundary is
        // undefined behaviour, not a clean failure. Every branch inside the
        // try also agrees its int return with whatever it told
        // set_result_status, so a caller reading either signal gets the same
        // answer.
        try {
            if (action == "catalog") {
                do_catalog(ctx);
                return 0;
            }
            if (action == "list") {
                return do_list(ctx, params.get("sources"));
            }

            ctx.write_output(std::string{"unknown action: "} +
                             yuzu::util::safe_output_field(action));
            return 1;
        } catch (const std::exception& e) {
            ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  "autoruns:exception");
            ctx.write_output(std::string{"error: "} + yuzu::util::safe_output_field(e.what()));
            return 1;
        } catch (...) {
            ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  "autoruns:exception");
            ctx.write_output("error: unknown exception");
            return 1;
        }
    }

private:
    static void do_catalog(yuzu::CommandContext& ctx) {
        ctx.write_output(std::string{"catalog|"} +
                         std::to_string(yuzu::autoruns::kAutorunSourceCatalogVersion));
        for (const auto& decl : yuzu::autoruns::kSourceCatalog) {
            ctx.write_output(yuzu::autoruns::format_source_status(
                decl.id, yuzu::autoruns::declared_support_for_host(decl), std::nullopt,
                "declared"));
        }
    }

    static int do_list(yuzu::CommandContext& ctx, std::string_view filter) {
        // All three run unconditionally on every build -- the two that are
        // not this build's own OS resolve to autoruns_legs.hpp's foreign-OS
        // stub, so a `list` capture always names every source in the
        // catalog, the same completeness guarantee `catalog` gives.
        yuzu::autoruns::collect_windows(ctx, filter);
        yuzu::autoruns::collect_linux(ctx, filter);
        yuzu::autoruns::collect_macos(ctx, filter);
        return 0; // a degraded per-source read is reported via set_result_status, not this rc
    }
};

YUZU_PLUGIN_EXPORT(AutorunsPlugin)
