/**
 * execution_artifacts_plugin.cpp — Windows-only execution-evidence plugin:
 * ShimCache (AppCompatCache), Amcache InventoryApplicationFile, and
 * Prefetch.
 *
 * Actions:
 *   "shimcache" — one row per AppCompatCache entry (path, last-modified,
 *                 data size). Windows 10/11 layout only.
 *   "amcache"   — one row per Root\InventoryApplicationFile subkey (path,
 *                 SHA-1, size, link date, publisher, binary type, product
 *                 name/version).
 *   "prefetch"  — one row per .pf file under C:\Windows\Prefetch (exe name,
 *                 hash, version, run count, last-run timestamps, volume and
 *                 file-reference counts).
 *
 * FORENSICS-CLASS DATA — see content/definitions/execution_artifacts.yaml
 * and this plugin's README (agents/plugins/execution_artifacts/README.md;
 * the docs/user-manual page is a separate follow-up): gated behind the
 * Forensics securable, AdminOrApproval, single-target only, DEFAULT-OFF via the
 * server kill switch. This plugin performs no authz itself (that lives at
 * the server dispatch layer, server/core/src/dispatch_destructive_gate.hpp)
 * — it only ever emits paths and hashes, never file contents.
 *
 * All three actions are independent: a failure reading one artefact never
 * blocks the other two (each has its own `constrained|<token>` outcome and
 * exit code — see this package's spec). This TU is fully portable — no
 * target-OS #if of any kind, matching disk_actions_plugin.cpp's precedent —
 * so the three descriptor legs are always declared in full even on a
 * single-OS build, and execute() branches on _WIN32 only to choose between
 * the real Windows legs (P32's execution_artifacts_win.cpp, declared in
 * execution_artifacts_legs.hpp) and the fixed non-Windows
 * "unsupported|windows_only_artefact" outcome every action reports there.
 */

#include <yuzu/plugin.hpp>

#include "execution_artifacts_legs.hpp"

#include <yuzu/string_utils.hpp>

#include <string>
#include <string_view>

namespace {

// The three descriptor legs are FIXED and never wrapped in a preprocessor
// conditional — a single-OS build still declares the full per-OS shape
// (disk_actions_plugin.cpp precedent, #2204's capability-matrix generator).
//
// Mechanism strings and notes below quote A1's the-rig probe findings
// verbatim (tests/unit/fixtures/wave7/probes/the-rig-probe-findings.md,
// 2026-09-06) where the spec calls for it.
const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "shimcache",
        /* .linux_leg   = */
        {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, "Windows-only artefact; no equivalent exists"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, "Windows-only artefact; no equivalent exists"},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "RegQueryValueExW HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session "
         "Manager\\AppCompatCache (local bounded reader, 16 MiB)",
         "Windows 10/11 layout only ('win10' header scheme, DWORD 0x34 or 0x30); no exec-flag "
         "bit exists in this layout, so every row's insert_flag is '-'. A1's real capture "
         "(the-rig, 2026-09-06) was 7886 bytes, well under the 16 MiB bound, and parsed with "
         "the header-size DWORD reading 0x34"},
    },
    {
        /* .action      = */ "amcache",
        /* .linux_leg   = */
        {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, "Windows-only artefact; no equivalent exists"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, "Windows-only artefact; no equivalent exists"},
        /* .windows_leg = */
        {YUZU_SUPPORT_CONSTRAINED, 1,
         "copy Amcache.hve(+.LOG1/.LOG2) then RegLoadAppKeyW; whole sequence serialised by "
         "offline_hive_mutex",
         "A1's the-rig probe (2026-09-06) found the copy succeeds as a PLAIN Copy-Item in every "
         "session tested (admin and LocalSystem) — the sharing violation that would require "
         "CreateFile(FILE_SHARE_READ|WRITE|DELETE, FILE_FLAG_BACKUP_SEMANTICS) + SeBackupPrivilege "
         "was never hit, so that fallback path is unexercised on this hardware. RegLoadAppKeyW "
         "does NOT require SeBackupPrivilege: it succeeded (LSTATUS 0x00000000) with the "
         "privilege explicitly disabled via AdjustTokenPrivileges, in both the admin session and "
         "under LocalSystem, against all 8889 real InventoryApplicationFile subkeys. Reported "
         "CONSTRAINED because the plain-copy path is a best-effort acquisition method not "
         "guaranteed on every host (a locked/exclusively-held hive on another machine could still "
         "need the backup-semantics fallback), not because anything failed on the probe host"},
    },
    {
        /* .action      = */ "prefetch",
        /* .linux_leg   = */
        {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, "Windows-only artefact; no equivalent exists"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, "Windows-only artefact; no equivalent exists"},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "CreateFileW read + ntdll RtlGetCompressionWorkSpaceSize/RtlDecompressBufferEx"
         "(COMPRESSION_FORMAT_XPRESS_HUFF)",
         "A1's the-rig LocalSystem probe (2026-09-06): GetProcAddress resolved both ntdll "
         "entry points to non-null addresses in every session (admin and LocalSystem); all four "
         "decompression attempts across the three real MAM .pf captures returned NTSTATUS "
         "0x00000000 (STATUS_SUCCESS) from both RtlGetCompressionWorkSpaceSize (workspace size "
         "166495 bytes, format COMPRESSION_FORMAT_XPRESS_HUFF, engine standard) and "
         "RtlDecompressBufferEx, with every decompressed payload's bytes 4-7 reading 'SCCA'. "
         "Real captures parsed as prefetch format version 31 (Windows 10/11), not version 30 as "
         "originally planned — see execution_artifacts_parsers.hpp's file header"},
    },
};

} // namespace

class ExecutionArtifactsPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "execution_artifacts"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Windows execution-evidence sources: ShimCache, Amcache "
               "InventoryApplicationFile, and Prefetch. Forensics-gated, single-target, "
               "default-off";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"shimcache", "amcache", "prefetch", nullptr};
        return acts;
    }

    const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }
    size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext& ctx) override {
        // Copied into a std::string immediately -- ctx.get_config returns a
        // string_view over the C ABI's own buffer, not guaranteed to
        // outlive this call (tar_plugin.cpp:569's same precedent).
        data_dir_ = std::string{ctx.get_config("agent.data_dir")};
        return {};
    }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action,
                yuzu::Params /*params*/) override {
#ifdef _WIN32
        if (action == "shimcache")
            return yuzu::execution_artifacts::collect_shimcache(ctx);
        if (action == "amcache")
            return yuzu::execution_artifacts::collect_amcache(ctx, data_dir_);
        if (action == "prefetch")
            return yuzu::execution_artifacts::collect_prefetch(ctx);
#else
        if (action == "shimcache" || action == "amcache" || action == "prefetch") {
            ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  "windows_only_artefact");
            ctx.write_output(std::string{"unsupported|"} +
                             std::string{yuzu::execution_artifacts::kUnsupportedWindowsOnly});
            return 1;
        }
#endif

        // `action` is request-supplied and lands in a pipe-delimited stream, so
        // it goes through the shared escaper like any other untrusted field.
        ctx.write_output(std::string{"unknown action: "} + yuzu::util::safe_output_field(action));
        return 1;
    }

private:
    // Captured at init() (tar_plugin.cpp:565-581's precedent); only the
    // amcache leg consumes it (execution_artifacts_win.cpp's
    // amcache_dest_dir), empty when agent.data_dir is unset.
    std::string data_dir_;
};

YUZU_PLUGIN_EXPORT(ExecutionArtifactsPlugin)
