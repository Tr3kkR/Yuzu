#pragma once

// tar_mapdrive_macos_parsers.hpp -- pure classifier for the macOS getfsstat
// mapped-drive leg (capability-map §3.8 outbound live). Header-only, no I/O:
// the impure getfsstat(2) wrapper in tar_mapdrive_collector.cpp gathers raw
// mount records and hands them here; this maps them onto the MapDriveEntry
// contract (tar_collectors.hpp) so the mapping is unit-testable off fixture
// data, the same pattern as this collector's other pure parsers
// (parse_proc_mounts / parse_fstab / parse_smbstatus / ...).
//
// remote_host_of (tar_mapdrive_collector.cpp) lives in that translation
// unit's anonymous namespace, unreachable from a header this file's unit test
// also includes directly -- so it is injected as `resolve_host` rather than
// called by name: the collector passes the real remote_host_of, tests pass
// their own fixture-equivalent stand-in. This keeps the header free of any
// dependency on the collector's internals.

#include <functional>
#include <string>
#include <vector>

#include "tar_collectors.hpp"

namespace yuzu::tar {

// One raw macOS mount record, as read by getfsstat(2). Field names mirror
// struct statfs (f_fstypename / f_mntfromname / f_mntonname) so the mapping
// in classify_macos_mounts is a direct visual match to the kernel struct the
// impure wrapper reads.
struct MacMountRec {
    std::string fstype; // f_fstypename, e.g. "nfs", "smbfs", "cifs", "afpfs", "webdav", "apfs"
    std::string from;   // f_mntfromname -- the remote spec, e.g. "//user@host/share"
    std::string on;     // f_mntonname -- the local mount point
};

/**
 * Classify raw getfsstat mount records into outbound MapDriveEntry rows.
 * Filters to the network fstypes {nfs, smbfs, cifs, afpfs, webdav}; every
 * other fstype (apfs, devfs, autofs, tmpfs, ...) is dropped. Populates every
 * MapDriveEntry field: direction="outbound" (macOS's getfsstat can only see
 * mounts this host initiated), local_mount=on, remote_path=from,
 * remote_host=resolve_host(from), username="" (unavailable via getfsstat,
 * same as the Linux /proc/mounts leg), provider mapped from fstype
 * (smbfs/cifs -> "SMB", nfs -> "NFS", afpfs -> "AFP", webdav -> "WebDAV").
 * Does NOT apply kMapDriveEntryCap -- the collector applies that (and its
 * warn-once latch) after this call, matching the Linux leg's shape.
 */
inline std::vector<MapDriveEntry>
classify_macos_mounts(const std::vector<MacMountRec>& mounts,
                      const std::function<std::string(const std::string&)>& resolve_host) {
    std::vector<MapDriveEntry> out;
    out.reserve(mounts.size());
    for (const auto& m : mounts) {
        std::string provider;
        if (m.fstype == "smbfs" || m.fstype == "cifs")
            provider = "SMB";
        else if (m.fstype == "nfs")
            provider = "NFS";
        else if (m.fstype == "afpfs")
            provider = "AFP";
        else if (m.fstype == "webdav")
            provider = "WebDAV";
        else
            continue; // not a network fstype we track -- e.g. apfs, devfs, autofs, tmpfs

        MapDriveEntry e;
        e.direction = "outbound";
        e.local_mount = m.on;
        e.remote_path = m.from;
        e.remote_host = resolve_host(m.from);
        e.username = ""; // unavailable via getfsstat, like the Linux leg
        e.provider = provider;
        out.push_back(std::move(e));
    }
    return out;
}

/**
 * Truncate `entries` to at most `cap` rows, returning true iff it truncated.
 * Split out of the collector's enumerate_mapdrive so the cap-and-warn
 * decision (kMapDriveEntryCap parity with the Linux leg at
 * tar_mapdrive_collector.cpp:1019-1026) is pure and unit-testable by feeding
 * constructed records directly, independent of the impure getfsstat call —
 * the collector calls this and only owns the warn-once logging side effect.
 */
inline bool apply_entry_cap(std::vector<MapDriveEntry>& entries, std::size_t cap) {
    if (entries.size() <= cap)
        return false;
    entries.resize(cap);
    return true;
}

} // namespace yuzu::tar
