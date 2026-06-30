#pragma once

/// @file deployment_parse.hpp
/// PURE, dependency-light parse + step model for the `/auto` DEPLOY stage — the
/// ACT half of the upgrade lifecycle that follows the pre-flight ASSESS stage. It
/// stages an installer (download + SHA-256 verify) then executes it on the devices
/// a pre-flight run cleared, tracking a per-device STATE MACHINE.
///
/// LOAD-BEARING difference from pre-flight: the steps MUTATE the endpoint (run an
/// installer), so the device step is STATEFUL — unlike pre-flight's read-only
/// checks, the grid is NOT recomputed from scratch each tick. The store models
/// guarded one-way transitions (deployment_run_store.cpp) and the engine
/// (deployment_engine.cpp) dispatches each mutating step at most once. This header
/// is only the PARSE (read content_dist's pipe output) + the step vocabulary; the
/// transition guards live in SQL.
///
/// content_dist emit contract (verified against content_dist_plugin.cpp 2026-06-30):
///   stage (action "stage")          → success: `status|ok` then `staged_path|<p>`
///                                      failure: `error|<msg>` (rc 1 → proto FAILURE)
///   execute_staged (action "execute_staged")
///                                    → run:    `status|ok|error`, `exit_code|<rc>`,
///                                              optional `output|<text>`
///                                      reject:  `error|<msg>` (validation: not staged /
///                                              no trusted hash / hash mismatch / bad args;
///                                              NO status|/exit_code| on this path)
/// Header-only so the unit test links it without the server or libpq.

#include "preflight_parse.hpp" // reuse split_pipe / find_row / parse_i64 (pure)

#include <cstdint>
#include <string>
#include <string_view>

namespace yuzu::server::deployment {

/// Per-device step. Stored as a stable token (deployment_device.step). Ordering is
/// the lifecycle: pending → staging → staged → executing → {succeeded|failed}, with
/// skipped a terminal sink for a device the operator lost scope to before it ran.
enum class Step {
    kPending,   ///< frozen into the cohort, nothing dispatched yet
    kStaging,   ///< stage dispatched (download + verify in flight)
    kStaged,    ///< stage confirmed (hash verified on the agent) — ready to execute
    kExecuting, ///< execute_staged dispatched (CLAIMED before dispatch = run-once)
    kSucceeded, ///< execute returned exit 0
    kFailed,    ///< stage error, or execute error / non-zero exit
    kSkipped,   ///< out of the operator's scope at dispatch — NEVER executed
};

inline const char* step_token(Step s) {
    switch (s) {
    case Step::kPending:
        return "pending";
    case Step::kStaging:
        return "staging";
    case Step::kStaged:
        return "staged";
    case Step::kExecuting:
        return "executing";
    case Step::kSucceeded:
        return "succeeded";
    case Step::kFailed:
        return "failed";
    default:
        return "skipped";
    }
}

inline Step step_from_token(std::string_view t) {
    if (t == "pending")
        return Step::kPending;
    if (t == "staging")
        return Step::kStaging;
    if (t == "staged")
        return Step::kStaged;
    if (t == "executing")
        return Step::kExecuting;
    if (t == "succeeded")
        return Step::kSucceeded;
    if (t == "failed")
        return Step::kFailed;
    return Step::kSkipped;
}

/// A device is settled when no further dispatch can change it.
inline bool step_is_terminal(Step s) {
    return s == Step::kSucceeded || s == Step::kFailed || s == Step::kSkipped;
}

/// Operator-entered artifact spec (the /auto deploy config). The cohort is NOT
/// here — it is the pre-flight run's go-cohort, frozen at create.
struct DeploymentConfig {
    std::string url;      ///< content_dist/stage `url`
    std::string filename; ///< content_dist/stage `filename` (+ execute_staged)
    std::string sha256;   ///< content_dist/stage `sha256` (+ execute_staged expected_hash)
    std::string args;     ///< content_dist/execute_staged `args` (optional)
};

// ── Server-side input validation (before ANY dispatch) ───────────────────────

/// Mirrors content_dist's `is_safe_filename`: non-empty, no `..`, alphanumeric +
/// `.`/`-`/`_` only. We reject here too so a malformed name never reaches a frozen run.
inline bool is_valid_filename(std::string_view f) {
    if (f.empty() || f.size() > 255)
        return false;
    if (f.find("..") != std::string_view::npos)
        return false;
    for (char c : f) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                        (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_';
        if (!ok)
            return false;
    }
    return true;
}

/// A hex SHA-256: exactly 64 hex digits (content_dist compares the lowercase hex
/// string from sha256_file). Case-insensitive accepted; the agent comparison is
/// exact, so the caller should pass it as produced.
inline bool is_valid_sha256(std::string_view h) {
    if (h.size() != 64)
        return false;
    for (char c : h) {
        const bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        if (!hex)
            return false;
    }
    return true;
}

/// A download URL we will hand to the agent: non-empty, http(s), no control bytes,
/// bounded. We do NOT fetch it (the agent does) — this only blocks the obviously
/// malformed from being frozen into a run.
inline bool is_valid_url(std::string_view u) {
    if (u.size() < 8 || u.size() > 2048)
        return false;
    if (u.rfind("http://", 0) != 0 && u.rfind("https://", 0) != 0)
        return false;
    for (char c : u)
        if (static_cast<unsigned char>(c) < 0x20)
            return false;
    return true;
}

/// execute_staged's args go through content_dist's `is_safe_arg` on the agent; we
/// pre-reject the SAME set here so a bad value is caught at config time, not after a
/// frozen run is running. Mirrors `is_safe_arg` EXACTLY (so the server is never
/// stricter than the agent — backslash, `=`, `:`, `/`, space stay ALLOWED for real
/// Windows path args like `/D C:\foo`) plus a NUL guard.
inline bool is_valid_args(std::string_view a) {
    if (a.size() > 1024)
        return false;
    for (char c : a) {
        switch (c) {
        case ';':
        case '&':
        case '|':
        case '`':
        case '$':
        case '(':
        case ')':
        case '{':
        case '}':
        case '<':
        case '>':
        case '!':
        case '~':
        case '^':
        case '"':
        case '\'':
        case '#':
        case '*':
        case '?':
        case '[':
        case ']':
        case '\n':
        case '\r':
        case '\0':
            return false;
        default:
            break;
        }
    }
    return true;
}

/// All required artifact fields valid (args optional). `why` (optional) names the
/// first failing field for an honest operator error.
inline bool config_valid(const DeploymentConfig& c, std::string* why = nullptr) {
    auto fail = [&](const char* m) {
        if (why)
            *why = m;
        return false;
    };
    if (!is_valid_url(c.url))
        return fail("download URL must be http(s) and well-formed");
    if (!is_valid_filename(c.filename))
        return fail("filename must be alphanumeric with . - _ only");
    if (!is_valid_sha256(c.sha256))
        return fail("SHA-256 must be 64 hex characters");
    if (!c.args.empty() && !is_valid_args(c.args))
        return fail("install args contain forbidden characters");
    return true;
}

// ── content_dist output parsing ──────────────────────────────────────────────

/// The outcome of reading one agent's best (status, output) for a phase.
enum class PhaseOutcome {
    kPending, ///< no terminal response yet (still in flight / offline)
    kOk,      ///< stage verified / execute exit 0
    kFailed,  ///< an error or non-zero exit
};

struct StageResult {
    PhaseOutcome outcome = PhaseOutcome::kPending;
    std::string error; ///< populated on kFailed (the agent's `error|<msg>`)
};

struct ExecResult {
    PhaseOutcome outcome = PhaseOutcome::kPending;
    std::int64_t exit_code = 0; ///< meaningful on kOk(0) / kFailed(non-zero)
    std::string error;          ///< populated on kFailed
};

/// `status` is the proto CommandResponse status (0=RUNNING, 1=SUCCESS, >=2=FAILURE)
/// — used only as a backstop; the pipe output is authoritative. nullopt-equivalent
/// (kPending) when no terminal signal is present.
inline StageResult parse_stage(int status, std::string_view output) {
    StageResult r;
    if (auto err = preflight::find_row(output, "error")) {
        r.outcome = PhaseOutcome::kFailed;
        if (err->size() >= 2)
            r.error = (*err)[1];
        return r;
    }
    if (auto st = preflight::find_row(output, "status"); st && st->size() >= 2 && (*st)[1] == "ok") {
        r.outcome = PhaseOutcome::kOk;
        return r;
    }
    // No pipe verdict: a terminal FAILURE proto status with no parsable body is a
    // failure (e.g. plugin crash); anything else is still pending.
    if (status >= 2) {
        r.outcome = PhaseOutcome::kFailed;
        r.error = "stage failed (no detail)";
    }
    return r;
}

inline ExecResult parse_exec(int status, std::string_view output) {
    ExecResult r;
    // execute_staged's validation-reject path emits ONLY `error|` (no status/exit).
    if (auto err = preflight::find_row(output, "error")) {
        r.outcome = PhaseOutcome::kFailed;
        if (err->size() >= 2)
            r.error = (*err)[1];
        return r;
    }
    auto st = preflight::find_row(output, "status");
    if (st && st->size() >= 2) {
        if (auto ec = preflight::find_row(output, "exit_code"); ec && ec->size() >= 2)
            r.exit_code = preflight::parse_i64((*ec)[1]);
        if ((*st)[1] == "ok") {
            r.outcome = PhaseOutcome::kOk;
        } else {
            r.outcome = PhaseOutcome::kFailed;
            r.error = "installer exited " + std::to_string(r.exit_code);
        }
        return r;
    }
    if (status >= 2) {
        r.outcome = PhaseOutcome::kFailed;
        r.error = "execute failed (no detail)";
    }
    return r;
}

} // namespace yuzu::server::deployment
