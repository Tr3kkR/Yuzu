#pragma once

/**
 * local_dispatcher.hpp — agent-side in-process plugin dispatch.
 *
 * #1001 / arch-S3: PR 10 introduced an agent snapshot pump that needs
 * to invoke `tar.fleet_snapshot` locally and harvest its JSON payload
 * without touching the gRPC channel. The first implementation hand-wired
 * a `capture` pointer onto CommandContextImpl and branched
 * `flush_output_locked` on `capture != nullptr` to avoid null-deref on
 * `stream`. That smuggled two modes into a struct meant for one (the
 * gRPC streaming path) and bled into every future feature that needed
 * local-dispatch (periodic Guardian rule eval, agent-side health probes,
 * etc.) — the next adopter would copy the pattern and accrete another
 * mode-branch.
 *
 * LocalDispatcher is the single entry point for "run a plugin action
 * in-process and give me back its output". Callers shrink to a few
 * lines (cycle, log, ship to heartbeat). The capture buffer cap and
 * the truncation sentinel live here, not in CommandContextImpl.
 *
 * The cap matches the server-side `FleetTopologyStore::kPushedSnapshotMaxBytes`
 * (2 MiB). Snapshots above the cap are truncated with a sentinel suffix
 * so the server-side parser cleanly rejects the payload rather than
 * ingesting a half-finished structure; the dispatcher signals the
 * truncation through the `truncated` field on the result.
 */

#include <yuzu/plugin.h>

#include <cstddef>
#include <span>
#include <string>
#include <string_view>

namespace yuzu::agent {

class LocalDispatcher {
public:
    struct Result {
        int rc{0};             ///< plugin's return code; 0 == success
        std::string captured;  ///< concatenated output (newline-joined)
        bool truncated{false}; ///< true iff capture hit the byte cap
    };

    /// Matches the server-side `FleetTopologyStore::kPushedSnapshotMaxBytes`.
    /// Snapshots that hit the cap are truncated with a sentinel; the server
    /// parser rejects malformed JSON rather than ingesting half a struct.
    static constexpr std::size_t kCaptureMaxBytes = 2ull * 1024 * 1024;

    /// Dispatch `action` on `descriptor` synchronously, in this thread.
    /// `params` is forwarded verbatim to the plugin (may be empty).
    /// Output written via `yuzu_ctx_write_output` is appended to
    /// `result.captured`. Bounded by kCaptureMaxBytes.
    Result run(const YuzuPluginDescriptor* descriptor, std::string_view action,
               std::span<const YuzuParam> params = {});
};

} // namespace yuzu::agent
