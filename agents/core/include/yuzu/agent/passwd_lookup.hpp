#pragma once

/**
 * passwd_lookup.hpp -- bounded, POSIX passwd-database resolution for the agent
 * (#3406).
 *
 * WHY THIS LIVES IN AGENT-CORE AND NOT IN THE PLUGIN THAT NEEDS IT
 * ---------------------------------------------------------------
 * The only consumer today is the macOS `certificates` plugin, which resolves
 * the console user's uid + home directory before reading their login keychain.
 * The obvious implementation -- call `yuzu::shared::bounded_call()` straight
 * from the plugin -- is UNSAFE, and the tree already says so in as many words.
 * `bounded_call` runs its callable on a DETACHED thread and abandons it at the
 * deadline; if that callable's code lives in a plugin's shared object, the
 * agent can `dlclose()` the plugin while the detached thread is still executing
 * inside it, and the process dies on unmapped text. See
 * agents/core/src/server_address_resolver.cpp, which uses the same primitive
 * and documents the constraint explicitly: safe there "specifically because
 * this whole translation unit lives in agent-core, never dlclose()'d ... the
 * risk this exact shape would carry inside a PLUGIN."
 *
 * So the bounded lookup lives here, in agent-core, for exactly the same reason
 * subprocess_runner's reaper thread does: agent-core is never unloaded, so a
 * late-arriving result from an abandoned thread is simply discarded instead of
 * racing an unload.
 *
 * WHY IT IS BOUNDED AT ALL
 * ------------------------
 * `getpwnam_r` is not a local-file read on a directory-joined Mac -- it can do
 * a blocking network Directory Services / NSS lookup with no caller-supplied
 * timeout, a hazard this repo already records at
 * agents/plugins/tar/src/tar_proc_es.cpp ("getpwuid_r -- which can do a
 * blocking network NSS lookup on a directory-joined Mac"). Before #3406 the
 * certificates plugin obtained this same information through CHILD PROCESSES
 * (`/bin/sh -c` performing `~user` tilde expansion, and `/usr/bin/id -u`), both
 * of which the bounded subprocess runner could SIGKILL at a deadline. Moving
 * the lookup in-process removed that kill boundary: an uncancellable blocking
 * call on the agent's bounded ThreadPool can pin a worker indefinitely, and
 * enough of them exhaust the pool and stall unrelated commands
 * (agents/shared/bounded_wait.hpp's own rationale). Bounding the WAIT here
 * restores the property the child process used to provide.
 */

#include <yuzu/plugin.h> // YUZU_EXPORT

#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>

namespace yuzu::agent {

/// One passwd record, reduced to the fields the agent consumes.
struct PasswdRecord {
    std::string uid;      ///< pw_uid, decimal-formatted. Always digits.
    std::string home_dir; ///< pw_dir verbatim; EMPTY if the record had none.
};

/// Why a bounded passwd resolution did not produce a record. Callers must
/// distinguish these: a TIMEOUT is a degraded-service condition and must be
/// reported honestly, whereas NOT_FOUND is a definite negative answer.
enum class PasswdLookupStatus {
    kOk,       ///< record resolved
    kNotFound, ///< the lookup completed and the account does not exist
    kError,    ///< the lookup completed and failed (nonzero rc, or ERANGE twice)
    kTimeout,  ///< the lookup did not complete within the budget, or the
               ///< bounded-call thread ceiling was already reached
};

struct PasswdLookupResult {
    PasswdLookupStatus status = PasswdLookupStatus::kError;
    PasswdRecord record{};

    bool ok() const { return status == PasswdLookupStatus::kOk; }
};

/// The raw lookup, exposed so tests can inject one that fails, returns no
/// record, or never returns at all. Returns the resolved record, or a status
/// explaining why it could not. Never kTimeout -- timing out is the bounded
/// WRAPPER's job, not the lookup's.
using PasswdLookupFn = std::function<PasswdLookupResult(const std::string& username)>;

/// Declared here; DEFINED OUT-OF-LINE in passwd_lookup.cpp so the body -- and
/// in particular bounded_call's detached thread -- compiles only into the
/// pinned agent-core image, never into a dlclose()-able plugin. Same reason
/// subprocess_runner.cpp keeps its fork/exec/reap body out of line.
///
/// The real getpwnam_r-backed lookup. Synchronous and potentially blocking --
/// call it through resolve_passwd_bounded() rather than directly.
YUZU_EXPORT PasswdLookupResult getpwnam_lookup(const std::string& username);

/**
 * Resolve `username` against the passwd database, giving up after `timeout`.
 *
 * On timeout the underlying lookup is ABANDONED, not cancelled (there is no
 * portable way to cancel it) -- it finishes on its own detached thread and its
 * result is discarded. The caller is never blocked past `timeout`. A
 * non-positive `timeout` returns kTimeout without starting a lookup at all.
 *
 * `lookup` is injectable purely for testing; production callers omit it.
 */
YUZU_EXPORT PasswdLookupResult resolve_passwd_bounded(
    const std::string& username, std::chrono::milliseconds timeout,
    const PasswdLookupFn& lookup = getpwnam_lookup);

} // namespace yuzu::agent
