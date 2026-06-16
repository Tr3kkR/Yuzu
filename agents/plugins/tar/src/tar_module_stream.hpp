#pragma once

/**
 * tar_module_stream.hpp — platform-agnostic module/image-load stream primitives.
 *
 * The image-load peer of tar_proc_stream.hpp. Where the process source answers
 * "what ran", `$Module` answers "what did it LOAD" — DLL / dylib / .so loads plus
 * kernel driver / kext / kmod loads, each with a signing verdict. That is the
 * DLL-search-order-hijack, code-injection, and BYOVD (bring-your-own-vulnerable-
 * driver) surface the process source cannot see.
 *
 * This header defines the shared value type (`ModuleEvent`), the warehouse-token
 * vocabulary, the templated bounded ring (`ModuleEventRing = EventRing<ModuleEvent>`
 * — the SAME backpressure idiom the process ring uses, no fork), and the
 * `ImageStreamCollector` interface the per-platform collectors implement:
 *   - Windows ETW  — Microsoft-Windows-Kernel-Process image-load events on the
 *                    SAME session the process stream already runs (M2/M3);
 *   - macOS ES     — NOTIFY_KEXTLOAD/KEXTUNLOAD + dylib via NOTIFY_MMAP on the
 *                    SAME Endpoint Security client (M4/M5);
 *   - Linux auditd — kernel-module loads via init_module/finit_module (M6).
 *
 * M1 (this header) ships the contract only — NO concrete collector — so the
 * `$Module` warehouse tables register queryable-but-empty. See
 * docs/tar-module-loads.md for the full design and PR ladder.
 *
 * Names-only posture, with ONE deliberate, narrow divergence: `module_dir` (the
 * directory of the loaded image) IS captured, because the forensic signal for a
 * search-order hijack is the path (a `version.dll` in an app dir vs System32),
 * not a command line. No command line is ever captured.
 */

#include "tar_proc_stream.hpp" // EventRing<T>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::tar {

/// Lifecycle of a module/image-load observation. Persisted to the warehouse as
/// the lower-case token from `module_action_token()`.
enum class ModuleAction : std::uint8_t {
    kLoaded = 0,   ///< image mapped into a process / driver loaded
    kUnloaded = 1, ///< image unmapped (lower forensic value; captured where free)
    kSeed = 2,     ///< baseline: already-loaded at agent start (boot-gap seed)
    kBlocked = 3,  ///< load denied by the OS (e.g. CodeIntegrity 3033/3034)
};

/// Signing verdict for the loaded image. Persisted as the token from
/// `module_signed_token()`. `kUnknown` is the honest value where the platform
/// cannot cheaply attest signing (e.g. Linux kernel modules without IMA/EVM) —
/// never fabricated as "signed".
enum class ModuleSignedState : std::uint8_t {
    kUnknown = 0,
    kSigned = 1,
    kUnsigned = 2,
    kInvalid = 3, ///< signature present but fails verification
    kRevoked = 4,
};

/// Stable warehouse token for the `module_live.action` column. These tokens are
/// the SQL/dashboard vocabulary; they must stay in lockstep with the
/// `action = '...'` predicates in rollup_sql("module", ...) (tar_schema_registry.cpp).
constexpr std::string_view module_action_token(ModuleAction a) noexcept {
    switch (a) {
    case ModuleAction::kLoaded:   return "loaded";
    case ModuleAction::kUnloaded: return "unloaded";
    case ModuleAction::kSeed:     return "seed";
    case ModuleAction::kBlocked:  return "blocked";
    }
    return "loaded";
}

/// Stable warehouse token for the `module_live.signed_state` column.
constexpr std::string_view module_signed_token(ModuleSignedState s) noexcept {
    switch (s) {
    case ModuleSignedState::kUnknown:  return "unknown";
    case ModuleSignedState::kSigned:   return "signed";
    case ModuleSignedState::kUnsigned: return "unsigned";
    case ModuleSignedState::kInvalid:  return "invalid";
    case ModuleSignedState::kRevoked:  return "revoked";
    }
    return "unknown";
}

/// One module/image-load event decoded from a streaming source. Fields mirror the
/// TAR `module_live` schema. `process_name`/`signer` are resolved at DRAIN (off
/// the kernel-serial ETW/ES callback thread), mirroring the process ring's
/// sid→user-at-drain idiom — signing verification in particular is costly on
/// Windows and must never run on the callback thread.
struct ModuleEvent {
    std::int64_t ts_unix{0};                                     ///< event time, unix seconds
    ModuleAction action{ModuleAction::kLoaded};
    std::uint32_t pid{0};                                        ///< loading process (0 for kernel)
    std::string process_name;                                    ///< loading process basename
    std::string module_name;                                     ///< loaded image basename (names-only)
    std::string module_dir;                                      ///< directory of the loaded image
    ModuleSignedState signed_state{ModuleSignedState::kUnknown};
    std::string signer;                                          ///< publisher (Win) / team id (macOS); "" otherwise
    bool is_kernel{false};                                       ///< driver (Win) / kext (macOS) / kmod (Linux)
};

/// The module/image-load ring — `EventRing<ModuleEvent>`, the same bounded
/// push→pull backpressure bridge the process ring uses (tar_proc_stream.hpp).
using ModuleEventRing = EventRing<ModuleEvent>;

/// Common interface for a module/image-load stream — the image-load peer of
/// `ProcStreamCollector`. The TAR plugin holds ONE of these per platform and
/// drains it each fast tick, alongside the process stream (they correlate, so
/// they share cadence and snapshot_id). On a platform/SDK without a stream,
/// `start()` returns false and the `$Module` source simply produces nothing —
/// there is never silent partial loss. No concrete collector ships in M1; this
/// is the contract M2/M4/M6 implement.
class ImageStreamCollector {
public:
    virtual ~ImageStreamCollector() = default;

    // Non-copyable / non-movable: a concrete collector owns a live ETW session,
    // ES client, or auditd reader — copying or slicing it would duplicate or
    // sever that ownership. (Sibling invariant: ProcStreamCollector is identical.)
    ImageStreamCollector() = default;
    ImageStreamCollector(const ImageStreamCollector&) = delete;
    ImageStreamCollector& operator=(const ImageStreamCollector&) = delete;
    ImageStreamCollector(ImageStreamCollector&&) = delete;
    ImageStreamCollector& operator=(ImageStreamCollector&&) = delete;

    /// Begin streaming. Returns false if unavailable (wrong platform, missing
    /// entitlement/privilege, session-open failure) — caller captures nothing.
    virtual bool start() = 0;
    /// Stop streaming and release the underlying session/client. Safe if not started.
    virtual void stop() = 0;
    virtual bool running() const noexcept = 0;
    /// Move buffered events out for the batched tar.db write.
    virtual std::vector<ModuleEvent> drain() = 0;
    /// Events dropped due to ring overflow since construction.
    virtual std::uint64_t dropped() const noexcept = 0;
    /// Stable token for the `module_capture_method` status field
    /// ("etw" / "endpoint_security" / "auditd").
    virtual const char* method_name() const noexcept = 0;
};

} // namespace yuzu::tar
