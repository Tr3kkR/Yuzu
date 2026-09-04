/**
 * disk_actions_macos.cpp — macOS leg entry points.
 *
 * MECHANISM, bound by spike on 2026-09-03 against this host's real hardware
 * (Apple Silicon, APPLE SSD AP0512Z): IOKit `IOBlockStorageDevice` matching,
 * reading `kIOPropertyDeviceCharacteristicsKey` for identity and the
 * `NVMe SMART Capable` property for capability. Rung 1, no subprocess, and it
 * works UNPRIVILEGED (measured at euid 501).
 *
 * WHY HEALTH IS NOT REPORTED HERE, and why that is CONSTRAINED rather than a
 * gap to be quietly filled later. The wear, available-spare and
 * critical-warning attributes live behind Apple's `IONVMeSMARTUserClient`,
 * whose selector interface is PRIVATE and undocumented. The spike confirmed
 * `IOServiceOpen` on the block device succeeds unprivileged (kr=0) and that a
 * selector exists (one returns kIOReturnNotPrivileged, others
 * kIOReturnBadArgument) -- so the door is there, but reaching the data means
 * reverse-engineering a call convention that Apple may change in any release.
 * ALEX RULING: not adopted. Building a shipped capability on an undocumented
 * interface is the same class of dependency as the dead
 * FSCTL_SRV_ENUMERATE_SNAPSHOTS this plugin's sibling had to be rescued from.
 * Health therefore reports `unknown` -- which is a true statement about what
 * this leg read -- and never `ok`, which would be a guess.
 *
 * OWNERSHIP. Every CF and IOKit object goes through ScopedCFRef / ScopedIOObject.
 * Note the documented trap those wrappers carry: ScopedIOObject must NOT wrap an
 * io_connect_t from IOServiceOpen (that needs IOServiceClose, and
 * IOObjectRelease leaves the user client instantiated in the kernel). This file
 * opens no user client at all, so the trap is not reachable here -- stated so a
 * future edit that adds one does not rediscover it.
 */

#if defined(__APPLE__)

#include "disk_actions_legs.hpp"

#include <yuzu/agent/scoped_cfref.hpp>
#include <yuzu/agent/scoped_ioobject.hpp>

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOBSD.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/storage/IOBlockStorageDevice.h>
#include <IOKit/storage/IOMedia.h>
#include <IOKit/storage/IOStorageDeviceCharacteristics.h>

#include <sys/mount.h>

#include <map>
#include <string>
#include <vector>

namespace yuzu::disk_actions {

namespace {

using yuzu::agent::ScopedCFRef;
using yuzu::agent::ScopedIOObject;

/// Bounds the provider walk. The measured chain is 7 hops; this is generous
/// headroom without trusting an unbounded registry to terminate.
constexpr int kMaxProviderDepth = 16;

/// CFString -> UTF-8. Returns empty on any non-string or conversion failure;
/// the caller decides what an absent value means, since "" and "-" are
/// different facts at the row layer.
std::string cf_string(CFTypeRef v) {
    if (!v || CFGetTypeID(v) != CFStringGetTypeID()) return {};
    CFStringRef s = static_cast<CFStringRef>(v);
    // CFStringGetLength is in UTF-16 units; ask for the real UTF-8 bound.
    const CFIndex max =
        CFStringGetMaximumSizeForEncoding(CFStringGetLength(s), kCFStringEncodingUTF8) + 1;
    if (max <= 0) return {};
    std::string out(static_cast<std::size_t>(max), '\0');
    if (!CFStringGetCString(s, out.data(), max, kCFStringEncodingUTF8)) return {};
    out.resize(std::char_traits<char>::length(out.c_str()));
    return out;
}

bool cf_bool_true(CFTypeRef v) {
    return v && CFGetTypeID(v) == CFBooleanGetTypeID() && CFBooleanGetValue(static_cast<CFBooleanRef>(v));
}

/// Trim the trailing padding IOKit product strings carry (the spike observed
/// "Virtual Disk    " shapes on other platforms and Apple pads similarly).
std::string trim_right(std::string s) {
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.pop_back();
    return s;
}

/// Media type from the device-characteristics dictionary. Absent is `unknown`,
/// never a guess -- a spinning-vs-solid claim drives capacity decisions.
Media media_from_characteristics(CFDictionaryRef dc) {
    if (!dc) return Media::Unknown;
    const std::string medium =
        cf_string(CFDictionaryGetValue(dc, CFSTR(kIOPropertyMediumTypeKey)));
    if (medium == kIOPropertyMediumTypeSolidStateKey) return Media::Ssd;
    if (medium == kIOPropertyMediumTypeRotationalKey) return Media::Hdd;
    return Media::Unknown;
}

/// Transport, derived from the IOKit class name rather than parsed text. The
/// spike saw IOEmbeddedNVMeBlockDevice for the internal SSD and
/// IODiskImageBlockStorageDeviceOutKernel for a mounted disk image; the latter
/// is `virtual`, which matters because reporting a disk image as a real drive
/// would put a phantom device in a fleet health view.
Bus bus_from_class(std::string_view cls) {
    if (cls.find("NVMe") != std::string_view::npos) return Bus::Nvme;
    if (cls.find("DiskImage") != std::string_view::npos) return Bus::Virtual;
    if (cls.find("USB") != std::string_view::npos) return Bus::Usb;
    if (cls.find("SAS") != std::string_view::npos) return Bus::Sas;
    if (cls.find("ATA") != std::string_view::npos) return Bus::Sata;
    return Bus::Unknown;
}

/// Mount points reachable today, keyed by BSD device name (e.g. "disk0s2").
/// MNT_NOWAIT for the same reason filesystem_posture uses it: a synchronous
/// getmntinfo can block on an unreachable network mount, and this runs on a
/// bounded dispatch-pool worker.
std::map<std::string, std::vector<std::string>> mount_points_by_bsd_name(bool& ok) {
    std::map<std::string, std::vector<std::string>> out;
    struct statfs* mnts = nullptr;
    const int n = ::getmntinfo(&mnts, MNT_NOWAIT);
    ok = n > 0;
    if (!ok) return out;
    for (int i = 0; i < n; ++i) {
        std::string from = mnts[i].f_mntfromname;
        // "/dev/disk0s2" -> "disk0s2"; anything not under /dev/ is not a
        // block device we can join on (network mounts, synthetic roots).
        constexpr std::string_view kDev = "/dev/";
        if (from.rfind(kDev, 0) != 0) continue;
        out[from.substr(kDev.size())].push_back(mnts[i].f_mntonname);
    }
    return out;
}

/// The PHYSICAL whole disk backing an IOMedia object, resolved by walking the
/// IOKit provider chain rather than by trimming the BSD name.
///
/// The string shortcut ("disk3s1" -> "disk3") is WRONG on APFS and was caught
/// by running the leg rather than reading it: on this Mac `/` lives on
/// disk3s1s1, whose "Part of Whole" is disk3 -- but disk3 is a SYNTHESIZED
/// AppleAPFSMedia container whose physical store is disk0s2, on the real drive
/// disk0. Trimming the name therefore stops at a virtual container and never
/// reaches the physical device, which is the one thing this action exists to
/// report: a failing drive must be nameable in terms of the volumes it serves.
///
/// The provider chain resolves it exactly (measured):
///   AppleAPFSVolume disk3s1 -> AppleAPFSContainer -> AppleAPFSMedia disk3
///     -> AppleAPFSContainerScheme -> IOMedia disk0s2 -> IOGUIDPartitionScheme
///     -> IOMedia disk0 (Whole=YES)   <-- the answer
///
/// So: walk providers to the first entry that is an IOMedia AND is marked
/// whole. The class test is load-bearing -- AppleAPFSMedia also reports
/// Whole=YES, and accepting it would return the synthesized container again.
std::string physical_whole_disk_of(io_registry_entry_t media) {
    io_registry_entry_t node = media;
    ScopedIOObject owned; // owns only the nodes WE step onto, never the caller's
    for (int depth = 0; depth < kMaxProviderDepth && node; ++depth) {
        io_name_t cls{};
        IOObjectGetClass(node, cls);
        ScopedCFRef<CFTypeRef> whole{
            IORegistryEntryCreateCFProperty(node, CFSTR(kIOMediaWholeKey), kCFAllocatorDefault, 0)};
        if (std::string_view(cls) == kIOMediaClass && cf_bool_true(whole.get())) {
            ScopedCFRef<CFTypeRef> bsd{IORegistryEntryCreateCFProperty(node, CFSTR(kIOBSDNameKey),
                                                                      kCFAllocatorDefault, 0)};
            return cf_string(bsd.get());
        }
        io_registry_entry_t parent = 0;
        if (IORegistryEntryGetParentEntry(node, kIOServicePlane, &parent) != KERN_SUCCESS) break;
        owned.reset(parent); // releases the previous step, adopts this one
        node = parent;
    }
    return {};
}

} // namespace

int emit_smart(yuzu::CommandContext& ctx) {
    io_iterator_t raw_it{};
    if (IOServiceGetMatchingServices(kIOMainPortDefault,
                                     IOServiceMatching(kIOBlockStorageDeviceClass),
                                     &raw_it) != KERN_SUCCESS) {
        write_smart_row(ctx, "-", "-", Bus::Unknown, Media::Unknown, Health::Unknown, std::nullopt,
                        std::nullopt, "IOServiceGetMatchingServices failed");
        mark_result_partial(ctx, "macos:iokit", "IOServiceGetMatchingServices failed");
        return 0;
    }
    ScopedIOObject it{raw_it};

    bool any_row = false;
    for (io_object_t raw_obj; (raw_obj = IOIteratorNext(it.get()));) {
        ScopedIOObject obj{raw_obj};

        io_name_t cls{};
        IOObjectGetClass(obj.get(), cls);

        ScopedCFRef<CFTypeRef> dc{IORegistryEntryCreateCFProperty(
            obj.get(), CFSTR(kIOPropertyDeviceCharacteristicsKey), kCFAllocatorDefault, 0)};
        CFDictionaryRef dict = (dc.get() && CFGetTypeID(dc.get()) == CFDictionaryGetTypeID())
                                   ? static_cast<CFDictionaryRef>(dc.get())
                                   : nullptr;

        const std::string model =
            dict ? trim_right(cf_string(CFDictionaryGetValue(dict, CFSTR(kIOPropertyProductNameKey))))
                 : std::string{};

        // IORegistryEntrySearchCFProperty, NOT IORegistryEntryCreateCFProperty.
        // The BSD name lives on the CHILD IOMedia, not on the
        // IOBlockStorageDevice itself, so the lookup has to search the plane.
        // Create's fourth parameter is `IOOptionBits options`, documented as
        // having no options defined -- passing kIORegistryIterateRecursively
        // there is silently ignored, and the earlier revision of this line did
        // exactly that. Measured on this Mac: every smart row's device column
        // came back "-". Caught by the standards reviewer reading the API
        // contract; the runtime dump that would have shown it had only been
        // taken for the volumes action.
        ScopedCFRef<CFTypeRef> bsd{IORegistryEntrySearchCFProperty(
            obj.get(), kIOServicePlane, CFSTR(kIOBSDNameKey), kCFAllocatorDefault,
            kIORegistryIterateRecursively)};
        const std::string device = cf_string(bsd.get());

        ScopedCFRef<CFTypeRef> nvme_smart{IORegistryEntryCreateCFProperty(
            obj.get(), CFSTR("NVMe SMART Capable"), kCFAllocatorDefault, 0)};
        ScopedCFRef<CFTypeRef> ata_smart{IORegistryEntryCreateCFProperty(
            obj.get(), CFSTR("SMART Capable"), kCFAllocatorDefault, 0)};
        const bool smart_capable = cf_bool_true(nvme_smart.get()) || cf_bool_true(ata_smart.get());

        // Health is deliberately Unknown on every device: see the file banner.
        // The detail column is where the honest explanation goes, and it
        // distinguishes "the device advertises SMART but we do not read it"
        // from "the device advertises nothing".
        const char* detail =
            smart_capable
                ? "device advertises SMART; health attributes are not read on macOS (they require "
                  "Apple's private IONVMeSMARTUserClient interface)"
                : "device does not advertise SMART capability";

        write_smart_row(ctx, device.empty() ? "-" : device, model.empty() ? "-" : model,
                        bus_from_class(cls), media_from_characteristics(dict), Health::Unknown,
                        std::nullopt, std::nullopt, detail);
        any_row = true;
    }

    if (!any_row) {
        write_smart_row(ctx, "-", "-", Bus::Unknown, Media::Unknown, Health::Unknown, std::nullopt,
                        std::nullopt, "no block storage devices found");
    }
    // Reported once, after the walk, so it cannot be overwritten by a later
    // per-device mark. The whole leg is constrained by construction: it reads
    // identity and capability but never health.
    mark_result_partial(ctx, "macos:iokit",
                        "health attributes are not read on macOS; identity and capability only");
    return 0;
}

int emit_volumes(yuzu::CommandContext& ctx) {
    bool mounts_ok = false;
    const auto mounts = mount_points_by_bsd_name(mounts_ok);

    io_iterator_t raw_it{};
    if (IOServiceGetMatchingServices(kIOMainPortDefault, IOServiceMatching(kIOMediaClass),
                                     &raw_it) != KERN_SUCCESS) {
        write_volume_row(ctx, "-", "-", "-", "-", std::nullopt,
                         "IOServiceGetMatchingServices failed");
        mark_result_partial(ctx, "macos:iomedia", "IOServiceGetMatchingServices failed");
        return 0;
    }
    ScopedIOObject it{raw_it};

    bool any_row = false;
    for (io_object_t raw_obj; (raw_obj = IOIteratorNext(it.get()));) {
        ScopedIOObject obj{raw_obj};

        ScopedCFRef<CFTypeRef> bsd{
            IORegistryEntryCreateCFProperty(obj.get(), CFSTR(kIOBSDNameKey), kCFAllocatorDefault, 0)};
        const std::string name = cf_string(bsd.get());
        if (name.empty()) continue;

        ScopedCFRef<CFTypeRef> size{
            IORegistryEntryCreateCFProperty(obj.get(), CFSTR(kIOMediaSizeKey), kCFAllocatorDefault, 0)};
        std::optional<std::uint64_t> total;
        if (size.get() && CFGetTypeID(size.get()) == CFNumberGetTypeID()) {
            long long v = 0;
            if (CFNumberGetValue(static_cast<CFNumberRef>(size.get()), kCFNumberLongLongType, &v) &&
                v >= 0)
                total = static_cast<std::uint64_t>(v);
        }

        // THE JOIN this action exists for: partition -> whole disk, and
        // partition -> mount points.
        std::string joined = "-";
        if (const auto found = mounts.find(name); found != mounts.end()) {
            joined.clear();
            for (const auto& mp : found->second) {
                if (!joined.empty()) joined += ',';
                joined += mp;
            }
        }

        std::string physical = physical_whole_disk_of(obj.get());
        if (physical.empty()) physical = "-";
        write_volume_row(ctx, name, joined, physical, "-", total,
                         mounts_ok ? "-" : "mount-point enumeration failed; the mapping column is "
                                           "incomplete");
        any_row = true;
    }

    if (!any_row)
        write_volume_row(ctx, "-", "-", "-", "-", std::nullopt, "no IOMedia objects found");
    if (!mounts_ok)
        mark_result_partial(ctx, "macos:getmntinfo",
                            "getmntinfo returned no entries; volumes are listed without their "
                            "mount points");
    return 0;
}

} // namespace yuzu::disk_actions

#endif // defined(__APPLE__)
