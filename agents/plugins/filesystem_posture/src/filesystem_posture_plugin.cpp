/**
 * filesystem_posture_plugin.cpp — Filesystem posture plugin for Yuzu
 *
 * Actions:
 *   "mounts"    — Lists mounted filesystems with capacity and flags.
 *   "quotas"    — Reports per-mount quota-subsystem state.
 *   "snapshots" — Reports snapshot-capable volumes / the mounted snapshot
 *                 inventory, per OS.
 *
 * This TU is fully portable (no target-OS #if of any kind): every leg is
 * declared unconditionally in kActionDescriptors, and execute() dispatches
 * to the three yuzu::filesystem_posture::emit_* entry points the per-OS leg
 * TUs (filesystem_posture_linux.cpp / _macos.cpp / _win.cpp) define. Output
 * is pipe-delimited via the shared row formatters in
 * filesystem_posture_legs.hpp.
 */

#include <yuzu/plugin.hpp>

#include "filesystem_posture_legs.hpp"

#include <string>
#include <string_view>

namespace {

// The nine descriptor legs are FIXED and never wrapped in a preprocessor
// conditional -- a single-OS build still declares the full per-OS shape so
// the capability-matrix generator (#2204) sees a complete, stable structure
// regardless of which OS built this plugin.
//
// ALEX RULING (plan gate, H6): the Windows legs ship CONSTRAINED, not
// PLANNED -- the code is implemented and MSVC-compilable, so PLANNED would
// misdescribe it. Every Windows leg's fallback prose carries the mandatory
// honesty disclaimer stating this build was compile-verified only, with no
// live Windows host available to exercise it.
const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "mounts",
        /* .linux_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 1, "/proc/self/mountinfo + statvfs(3)",
         "capacity columns are omitted for network filesystems (nfs/cifs/smb/ceph/afs and "
         "network FUSE mounts) because a statvfs against an unreachable server blocks the "
         "dispatch worker indefinitely; the mount itself is still listed"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "getmntinfo(3) MNT_NOWAIT", nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_CONSTRAINED, 1, "FindFirstVolumeW + GetVolumeInformationW + GetDiskFreeSpaceExW",
         "enumerates local volumes only; a mapped network drive is not a volume and is not "
         "listed, and no per-mount option string exists so that column reads '-'; "
         "compile-verified only -- not exercised against a live Windows host in this change"},
    },
    {
        /* .action      = */ "quotas",
        /* .linux_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 1, "quotactl(2) Q_GETFMT",
         "reports per-mount quota-subsystem state only; per-user and per-group limits are not "
         "enumerated, and a mount whose source is not a block device (overlay, tmpfs, network) "
         "reports no_block_device"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 1, "getattrlist(2) ATTR_VOL_QUOTA_SIZE/ATTR_VOL_RESERVED_SIZE",
         "volume-level quota and reserved size only; per-user and per-group quotas do not exist "
         "on APFS (quotactl returns ENOTSUP on every APFS mount while succeeding on HFS+), so no "
         "per-identity rows are reported"},
        /* .windows_leg = */
        {YUZU_SUPPORT_CONSTRAINED, 1, "IDiskQuotaControl (dskquota.h)",
         "volume quota state and default limit/threshold only, opened read-only; per-user quota "
         "entries are not enumerated; a build whose SDK lacks dskquota.h reports unavailable; "
         "compile-verified only -- not exercised against a live Windows host in this change"},
    },
    {
        /* .action      = */ "snapshots",
        /* .linux_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 1,
         "/proc/self/mountinfo btrfs subvol + device-mapper source detection",
         "reports snapshot-capable volumes and the mounted btrfs subvolume identity, not a "
         "snapshot inventory: a device-mapper source may be dm-crypt, dm-multipath or "
         "dm-integrity rather than a snapshot-capable LV, enumerating unmounted btrfs snapshots "
         "needs CAP_SYS_ADMIN via BTRFS_IOC_TREE_SEARCH, and telling an LVM snapshot LV from a "
         "linear LV needs a device-mapper DM_TABLE_STATUS ioctl -- none of which this read-only "
         "plugin performs"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "fs_snapshot_list(2)",
         "one row per (mount point, snapshot): an APFS snapshot visible under two mount points "
         "of the same volume lineage is reported under each"},
        /* .windows_leg = */
        {YUZU_SUPPORT_CONSTRAINED, 1, "FSCTL_SRV_ENUMERATE_SNAPSHOTS",
         "reports the Previous-Versions (@GMT) shadow-copy tokens the volume exposes; a "
         "DeviceIoControl failure is reported distinctly from an empty snapshot set and degrades "
         "the result status; compile-verified only -- not exercised against a live Windows host "
         "in this change"},
    },
};

} // namespace

class FilesystemPosturePlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "filesystem_posture"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Reports mounted filesystems, per-mount quota-subsystem state, and "
               "snapshot-capable volumes";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"mounts", "quotas", "snapshots", nullptr};
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
        if (action == "mounts")
            return yuzu::filesystem_posture::emit_mounts(ctx);
        if (action == "quotas")
            return yuzu::filesystem_posture::emit_quotas(ctx);
        if (action == "snapshots")
            return yuzu::filesystem_posture::emit_snapshots(ctx);

        ctx.write_output(std::string{"unknown action: "} + std::string{action});
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(FilesystemPosturePlugin)
