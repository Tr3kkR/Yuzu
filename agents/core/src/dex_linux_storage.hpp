#pragma once

/**
 * dex_linux_storage.hpp — the storage.low observation chokepoint (Guardian DEX).
 *
 * ONE function binds a Linux mount to a storage.low observation, so the
 * edge-privacy invariant ("the subject is the backing-device identifier, NEVER
 * the mount path — a path carries usernames / tenant / project names";
 * docs/dex-signal-catalog.md) lives in a single, unit-testable place instead of
 * inline in the #if __linux__ poll loop. The collector calls this; the
 * [dex][privacy] test calls THIS SAME function — so the contract is a CI
 * regression guard, not a one-time live check: a future poll_disks edit cannot
 * reintroduce the mount path as the subject without failing the test.
 *
 * PURE (no syscall): it takes an already-read DiskLevel, so it compiles and is
 * tested on every host (the statvfs that fills DiskLevel is the collector's only
 * Linux mechanism). Mirrors the dex_linux_proc pure-parser split.
 */

#include <yuzu/plugin.h> // YUZU_EXPORT

#include "dex_linux_proc.hpp" // MountPoint, device_label
#include "dex_win_poll.hpp"   // DiskLevel, low_disk_observation, SignalObservation

#include <optional>

namespace yuzu::agent::lnx {

/// PURE: the storage.low observation for one mount, or nullopt when the volume is
/// healthy / its reading is invalid. The subject is device_label(mount.device) —
/// the backing-device basename, never mount.path (which is consulted ONLY for the
/// collector's statvfs()). Reuses the cross-platform threshold builder
/// (win::low_disk_observation), so the 90% / 5 GiB-free logic stays identical to
/// Windows and macOS — only the non-PII subject is Linux-specific.
YUZU_EXPORT std::optional<SignalObservation> storage_low_observation(const MountPoint& mount,
                                                                     const win::DiskLevel& level);

} // namespace yuzu::agent::lnx
