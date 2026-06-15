#include "dex_linux_storage.hpp"

namespace yuzu::agent::lnx {

std::optional<SignalObservation> storage_low_observation(const MountPoint& mount,
                                                         const win::DiskLevel& level) {
    // subject = the backing-device basename, NEVER mount.path. device_label() owns
    // the non-PII derivation; the threshold logic is the shared cross-platform
    // builder. mount.path is the collector's statvfs target only — it is never
    // passed here, so no path component can reach the subject / wire / log.
    return win::low_disk_observation(level, device_label(mount.device));
}

} // namespace yuzu::agent::lnx
