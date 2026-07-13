/**
 * license_scan_plugin.cpp — software licence detection plugin for Yuzu
 * (SLE capability §27; ADR-0024 Decision 2; roadmap §5 PR1 file-table row 5).
 *
 * Actions:
 *   "list"     — Run every detection surface for this OS and emit the §3.1
 *                `lic|` records, then one `probe_status|` line per surface
 *                attempted. The software_licensing sync source (PR1a step 6)
 *                consumes this via LocalDispatcher: records feed the
 *                canonical blob; the probe_status lines feed the
 *                empty-vs-error structural guard (ADR-0024 D3) and NEVER
 *                enter the blob.
 *   "surfaces" — Emit ONLY the `probe_status|` diagnostics, including
 *                availability reasons (e.g. `privilege_missing` when
 *                SeBackup/SeRestore are stripped — roadmap R15). This is the
 *                live diagnostics path for the /sle/agents/{id} drill
 *                (ADR-0024 D-10); flappy surface state stays live-only.
 *
 * Output is pipe-delimited, one record per line via write_output():
 *   lic|product|vendor|version|license_type|channel|status|expires_at|source|
 *       confidence|key_hint|exe_hints|user_scope|user_ref
 *   probe_status|<surface>|ok|<rows>
 *   probe_status|<surface>|error|<message>
 *
 * Every field passes the §3.3 layer-1 sanitiser (strip `|` CR LF 0x1F 0x1E
 * NUL, clamp 1024 B) in licensing_record.hpp before emission. Vocabularies
 * are closed and unknown-preserving (§3.2) — the plugin never fabricates.
 * Licence key material is never persisted or transmitted: key_hint is an
 * OS-provided partial key or a hash prefix (ADR-0024 D2). user_ref is a
 * local profile name or empty — never a SID (ADR-0024 D11).
 *
 * `ent|` entitlement records (FlexLM seat counts, KMS activation counts) are
 * deliberately NOT emitted here — they are PR2 scope (ADR-0024 D12).
 */

#include <yuzu/plugin.hpp>

#include <format>
#include <string_view>

#include "licensing_probes.hpp"
#include "licensing_record.hpp"

namespace {

yuzu::license_scan::SurfaceRun collect_surfaces() {
#if defined(_WIN32) || defined(__linux__) || defined(__APPLE__)
    return yuzu::license_scan::run_platform_surfaces();
#else
    yuzu::license_scan::SurfaceRun run;
    run.outcomes.push_back({"platform", false, 0, "unsupported_platform"});
    return run;
#endif
}

int do_list(yuzu::CommandContext& ctx) {
    const auto run = collect_surfaces();
    // §3.1 emission order: all lic| records first, then one probe_status|
    // line per surface attempted. No sentinel row on an empty result — zero
    // records with ok statuses IS the legitimate empty state (ADR-0024 D3).
    for (const auto& record : run.records)
        ctx.write_output(yuzu::license_scan::render_lic_line(record));
    for (const auto& outcome : run.outcomes)
        ctx.write_output(yuzu::license_scan::render_probe_status_line(outcome));
    return 0;
}

int do_surfaces(yuzu::CommandContext& ctx) {
    const auto run = collect_surfaces();
    // Diagnostics only — records are deliberately suppressed (live path,
    // D-10): which surfaces are available and why not.
    for (const auto& outcome : run.outcomes)
        ctx.write_output(yuzu::license_scan::render_probe_status_line(outcome));
    return 0;
}

} // namespace

class LicenseScanPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "license_scan"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Detects software licences across OS, vendor and per-user surfaces";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"list", "surfaces", nullptr};
        return acts;
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action,
                yuzu::Params /*params*/) override {
        if (action == "list")
            return do_list(ctx);
        if (action == "surfaces")
            return do_surfaces(ctx);

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(LicenseScanPlugin)
