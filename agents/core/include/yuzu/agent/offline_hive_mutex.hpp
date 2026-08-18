#pragma once

/**
 * offline_hive_mutex.hpp -- process-wide serialization for the Windows
 * per-user registry-hive offline-mount path (#2771 code-review CFX-1).
 *
 * agents/shared/win_profiles.hpp's with_user_hive() enables
 * SeBackupPrivilege/SeRestorePrivilege on the PROCESS token before an offline
 * RegLoadKeyW mount and restores the token's prior attributes on the way out.
 * Four plugins load this ladder into the SAME agent process --
 * registry, installed_apps, license_scan, tar -- and tar's collectors run on
 * a background thread, so two overlapping offline-mount attempts race the
 * shared process token: A enables it, B enables it (recording A's now-enabled
 * state as "previous"), A's scope exits and restores to B's recorded
 * "previous" -- silently disabling it out from under B, mid-mount.
 *
 * A std::mutex defined as a plain `inline`/header-local static in
 * win_profiles.hpp does NOT solve this: each of the four plugin .dll/.so
 * files is a SEPARATE dynamically loaded module, and a function-local static
 * in a header is instantiated once PER TRANSLATION UNIT THAT LINKS IT IN --
 * in practice, once per plugin binary. Four plugins therefore got four
 * independent mutexes, not one process-wide lock (confirmed: each plugin DLL
 * exports exactly its one required `yuzu_plugin_descriptor` symbol and
 * nothing else -- the mutex was never shared).
 *
 * The fix is the one this codebase already uses for the identical problem --
 * see fork_lock.hpp's global_fork_lock(): define the mutex ONCE in
 * agents/core (compiled into the single yuzu_agent_core shared library every
 * plugin links against) and export it via YUZU_EXPORT, so every plugin's
 * import resolves to the SAME address in the SAME already-loaded module.
 *
 * Scope: covers the whole offline arm (privilege enable -> RegLoadKeyW -> fn
 * -> unload -> restore), not just the RegLoadKeyW call itself -- see
 * win_profiles.hpp's with_user_hive() for where it is taken. The live-hive
 * path (the common case) never takes this lock.
 */

#include <yuzu/plugin.h> // YUZU_EXPORT

#include <mutex>

namespace yuzu::agent {

/**
 * The process-global offline-hive-mount lock. Take it as a std::lock_guard
 * around the whole privilege-enable-through-restore sequence -- see the file
 * header for the full contract.
 */
YUZU_EXPORT std::mutex& offline_hive_mutex();

} // namespace yuzu::agent
