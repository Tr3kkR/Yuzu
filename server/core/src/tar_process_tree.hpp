#pragma once

/// @file tar_process_tree.hpp
/// The TAR process-tree viewer's PURE reconstruction engine (no DB, no HTTP — so
/// it is unit-testable directly with synthetic rows). The route module
/// (tar_tree_routes.cpp) dispatches a canned, read-only `tar.sql` to ONE live host
/// (the device-page "Get live info" dispatch/poll seam), feeds the pipe-delimited
/// output through the parsers here, reconstructs a per-host process tree over a
/// chosen window, flags anomalies, and renders the HTMX fragments.
///
/// Data source is the agent's LOCAL tar.db ONLY (via `tar.sql` over `$Process_Live`
/// + `$TCP_Live`) — no live process probe, no server-side mirror, no agent seed.
/// Consequences baked into the model:
///   * Windows process rows are ETW names-only → `cmdline` is empty and there is
///     no executable path. We surface that honestly; we do NOT enrich.
///   * There are no start/exit-time columns — a process's lifetime is derived from
///     its `started`/`stopped` event timestamps in `$Process_Live`.
///   * `$Process_Live` is row-capped (100k, no seed): a long-running process whose
///     `started` event aged out can only be partially reconstructed (we synthesise
///     a "started before observation" incarnation from its `stopped` row when one
///     survives; if neither survives it cannot appear).
///   * The agent forbids recursive CTEs, so the tree is built HERE in C++ from flat
///     rows, never in SQL.

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace yuzu::server {

/// One row out of `$Process_Live` (a process start/stop event). `cmdline` is empty
/// on Windows (ETW names-only). All string fields are agent-controlled → HTML-escape
/// at render.
struct TarProcEvent {
    std::int64_t ts = 0;
    std::string action;   ///< "started" | "stopped"
    std::uint32_t pid = 0;
    std::uint32_t ppid = 0;
    std::string name;     ///< image basename
    std::string cmdline;  ///< full cmdline on Linux/macOS; "" on Windows
    std::string user;
};

/// One row out of `$TCP_Live` (a connection open/close event). Joined to a process
/// by `pid`. All string fields are agent-controlled → HTML-escape at render.
struct TarTcpConn {
    std::int64_t ts = 0;
    std::string action; ///< "connected" | "disconnected"
    std::uint32_t pid = 0;
    std::string process_name;
    std::string proto;
    int local_port = 0;
    std::string remote_addr;
    int remote_port = 0;
    std::string state;
};

/// One reconstructed process incarnation (NOT keyed by raw pid — a pid can recur,
/// so each [start,stop) lifetime is its own node, addressed by a stable `node_id`
/// = its index in `ProcTree::nodes`). Children/parent are node_ids.
struct TarProcNode {
    std::uint32_t pid = 0;
    std::uint32_t ppid = 0;
    std::string name;
    std::string cmdline;
    std::string user;
    std::int64_t started_ts = 0; ///< 0 = started before the retained window (start event aged out / pre-observation)
    std::int64_t exited_ts = 0;  ///< 0 = still running at `to_ts`
    bool running = false;        ///< alive at `to_ts`
    bool start_known = false;    ///< false → started_ts is unknown (synthesised incarnation)
    bool anomaly = false;
    std::string anomaly_evidence;
    std::size_t parent = kNoParent; ///< node_id of the parent incarnation, or kNoParent (a root)
    std::vector<std::size_t> children;

    static constexpr std::size_t kNoParent = static_cast<std::size_t>(-1);
};

/// Timescale anchors derived purely from the fetched rows (TAR has no boot-time or
/// install-time column — both are honest proxies).
struct TarTreeAnchors {
    std::int64_t observed_since = 0; ///< MIN(ts) over the rows — the start of observation
    std::int64_t install_ts = 0;     ///< == observed_since (closest TAR-only proxy for first-start)
    std::int64_t boot_ts = 0;        ///< most-recent boot inferred from root-process starts; falls back to install_ts
};

/// The reconstructed tree for one host over `[from_ts, to_ts]`.
struct TarProcTree {
    std::int64_t from_ts = 0;
    std::int64_t to_ts = 0;
    TarTreeAnchors anchors;
    std::vector<TarProcNode> nodes; ///< addressed by node_id (index)
    std::vector<std::size_t> roots; ///< node_ids of roots (ppid not present / 0 / self / orphaned)
    int running_count = 0;
    int exited_count = 0;
    int anomaly_count = 0;
    bool truncated = false; ///< hit the kMaxNodes render cap
};

/// Hard cap on reconstructed nodes — a runaway/forged event stream must not OOM or
/// produce an unrenderable tree (design §5.5).
inline constexpr std::size_t kTarTreeMaxNodes = 50000;

// ── Parsers (defensive, mirroring parse_dex_perf_output's __schema__ contract) ──
// Both expect the agent's `tar.sql` output: a `__schema__|col1|col2|…` header line
// (cell 0 is the literal marker, cells 1..N name the data columns) followed by
// pipe-delimited data rows. Columns are located BY NAME from the schema line, so a
// column reorder can't misalign fields. An `error|…` first line, a missing/wrong
// schema, torn rows, and out-of-range numbers are all skipped/rejected — a forged
// agent payload can shrink the result but never corrupt the parse.

/// Parse `$Process_Live` rows. Required columns: ts, action, pid, ppid, name, user
/// (cmdline optional — empty on Windows). Bounded to `max_rows` (default = the live
/// cap) to bound work against a response-spam payload.
std::vector<TarProcEvent> parse_tar_process_output(const std::string& output,
                                                   std::size_t max_rows = 120000);

/// Parse `$TCP_Live` rows. Required columns: pid, proto, remote_addr, remote_port,
/// local_port, state (process_name optional). Bounded to `max_rows`.
std::vector<TarTcpConn> parse_tar_tcp_output(const std::string& output,
                                             std::size_t max_rows = 20000);

// ── Reconstruction ──────────────────────────────────────────────────────────

/// Compute the timescale anchors from the (unsorted) process events.
TarTreeAnchors compute_tar_anchors(const std::vector<TarProcEvent>& events);

/// Resolve a preset token (`on_boot`/`on_install`/`1m`/`10m`/`1h`/`1d`/`custom`) +
/// optional custom from/to (epoch seconds; ≤0 = unset) into a `[from, to]` window.
/// `now` is injected for testability. Garbage preset → the `10m` default. For
/// `custom`, an unset `from` → observed_since, an unset `to` → now. `to` is clamped
/// to be ≥ `from` (a reversed range collapses to a point-in-time at `to`).
struct TarWindow {
    std::int64_t from_ts = 0;
    std::int64_t to_ts = 0;
};
TarWindow resolve_tar_window(const std::string& preset, std::int64_t custom_from,
                             std::int64_t custom_to, const TarTreeAnchors& anchors,
                             std::int64_t now);

/// Parse a `from`/`to` query value: either epoch-seconds (all digits) or a
/// datetime-local value `YYYY-MM-DDTHH:MM[:SS]` interpreted as UTC. Returns 0 for
/// empty/invalid/out-of-range input (callers treat 0 as "unset"). Overflow-guarded:
/// an oversized digit string or an absurd year yields 0, never signed-overflow UB.
/// Pure + free so it is unit-testable without the HTTP layer.
std::int64_t parse_ts_param(const std::string& s);

/// Reconstruct the per-host tree: build per-pid alive intervals from the event
/// stream, keep incarnations whose lifetime overlaps `[from, to]`, link each to the
/// parent incarnation that owned its `ppid` when it started (orphans → roots), and
/// flag suspicious parent→child name pairs. Always the FULL tree — running/exited
/// and anomalies-only filtering is a client-side display concern (each rendered row
/// carries data-state/data-anom), so the operator can toggle filters with no
/// re-dispatch. Cycle- and cap-guarded.
TarProcTree reconstruct_tar_process_tree(const std::vector<TarProcEvent>& events,
                                         std::int64_t from_ts, std::int64_t to_ts,
                                         const TarTreeAnchors& anchors);

/// True if a `parent_name → child_name` pair is a suspicious spawn (case-insensitive
/// basename match against the static LOLBin/shell denylist). On a hit, `*evidence`
/// (when non-null) is set to a short human reason. Pure + exposed for unit tests.
bool tar_is_suspicious_spawn(const std::string& parent_name, const std::string& child_name,
                             std::string* evidence = nullptr);

// ── Render (pure, server-side, dark-theme, CSP-safe — no JS in the markup) ────
// Co-located with the engine (like dex_routes' render_* helpers) so the HTML-escape
// of agent-controlled fields is unit-testable without the HTTP sink.

/// Render the tree fragment: the honesty banner + the nested `<details>/<summary>`
/// tree. Every node is rendered (no server-side filtering); each row carries
/// `data-state` (running|exited) + `data-anom` so the toolbar's client-side filters
/// (All/Running/Exited, Anomalies-only, text) can show/hide without a round-trip,
/// plus an inline network summary (remote IP:port) joined from `conns` by pid. Each
/// row hx-gets `/fragments/tar/process-tree/detail?token=…&node=…` into
/// `#tar-tree-detail`. `os` selects the Windows names-only caption; `token` keys the
/// reconstruction cache the detail route reads.
std::string render_tar_tree_fragment(const TarProcTree& tree, const std::vector<TarTcpConn>& conns,
                                     const std::string& device_id, const std::string& token,
                                     const std::string& os);

/// Render one node's detail panel — name, user, running/exited, start time, path +
/// command line (blank-with-note on Windows, populated on Linux/macOS), the node's
/// TCP connections, and anomaly evidence. `conns` is the connection set already
/// filtered to this node's pid; `os` drives the names-only note.
std::string render_tar_proc_detail(const TarProcNode& node, const std::vector<TarTcpConn>& conns,
                                   const std::string& os);

} // namespace yuzu::server
