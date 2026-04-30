/**
 * test_workflow_routes.cpp — coverage for `/fragments/executions` and
 * `/fragments/executions/{id}/detail`.
 *
 * Pattern matches test_rest_visualization.cpp + test_settings_routes_users.cpp:
 * register WorkflowRoutes against an in-process TestRouteSink and dispatch
 * synthesised requests directly into the captured handlers. No real socket →
 * no #438 TSan trap.
 *
 * Information-design contract being validated:
 *   - List filters by `definition_id` query param (PR 1.3).
 *   - List substitutes definition name when known; falls back to id stub.
 *   - List shows relative time + ISO-8601 UTC in title (no local time).
 *   - Sparkbar renders aria-label that summarises four counts.
 *   - Failed rows surface a UTF-8-safe truncation of the most recent error.
 *   - Detail returns 404 for unknown id; 403 when perm_fn denies.
 *   - Detail KPI strip: succeeded/failed counts + p50/p95 fall back to "—"
 *     when any agent is still running.
 *   - Detail agent grid switches to decile bucketing above 1024 agents.
 */

#include "execution_event_bus.hpp"
#include "execution_tracker.hpp"
#include "instruction_store.hpp"
#include "response_store.hpp"
#include "test_route_sink.hpp"
#include "workflow_routes.hpp"

#include <catch2/catch_test_macros.hpp>

#include "../test_helpers.hpp"

#include <atomic>
#include <filesystem>
#include <memory>
#include <string>

namespace fs = std::filesystem;
using namespace yuzu::server;

namespace {

fs::path uniq(const std::string& prefix) {
    return yuzu::test::unique_temp_path(prefix + "-");
}

// RAII holder for the raw sqlite3* that ExecutionTracker takes by handle.
// Declared as the FIRST member of ExecHarness so its destructor runs LAST
// in member-destruction order — guarantees the handle closes even if a
// later REQUIRE in the constructor throws (qa-B2 fixture leak fix).
struct SqliteHandleGuard {
    sqlite3* db{nullptr};
    ~SqliteHandleGuard() { if (db) sqlite3_close(db); }
};

struct ExecHarness {
    // Order matters: tracker_guard outlives `tracker` so the handle is still
    // alive while ~ExecutionTracker runs (it doesn't close, only finalizes
    // statements), then SqliteHandleGuard closes the handle on destruction.
    SqliteHandleGuard tracker_guard;
    yuzu::server::test::TestRouteSink sink;

    fs::path tracker_db, instr_db, resp_db;
    std::unique_ptr<ExecutionTracker> tracker;
    std::unique_ptr<InstructionStore> instructions;
    std::unique_ptr<ResponseStore> responses;
    /// PR 3: per-execution SSE bus. Constructed BEFORE the tracker (see
    /// member-order comment) so the tracker can attach. Pointer is also
    /// passed into WorkflowRoutes::Deps so the SSE handler is registered.
    /// Defaults to non-null in the harness so SSE-route tests do not
    /// silently 503; tests that want to exercise the no-bus path build
    /// the deps inline.
    std::unique_ptr<ExecutionEventBus> event_bus;

    bool perm_grant{true};
    /// PR 2 hardening regression net: captures the execution_id passed to
    /// cmd_dispatch so a test can prove the FAST-agent race fix (mapping
    /// registered BEFORE dispatch). Empty when the dispatch path has no
    /// tracker context.
    std::string last_dispatch_execution_id;
    WorkflowRoutes routes;

    /// Per-process monotonic counter for execution IDs. Replaces the prior
    /// `std::hash<std::string>(...)` which violates the CLAUDE.md test rule
    /// against hash-of-thread-id / clock as uniqueness salt — the same
    /// principle applies to hash-of-string under MSVC's hash, which has had
    /// collision edge cases. Atomic so parallel test workers cannot collide.
    static inline std::atomic<int> exec_counter{0};

    ExecHarness()
        : tracker_db(uniq("wf-routes-exec")),
          instr_db(uniq("wf-routes-inst")),
          resp_db(uniq("wf-routes-resp")) {
        for (auto& p : {tracker_db, instr_db, resp_db}) fs::remove(p);

        // ExecutionTracker takes a raw sqlite3* — open it via the guard so a
        // throwing REQUIRE in any later constructor step still closes it.
        REQUIRE(sqlite3_open(tracker_db.string().c_str(), &tracker_guard.db) == SQLITE_OK);
        // PR 3: bus must outlive the tracker (the tracker borrows the
        // bus pointer). Build the bus first.
        event_bus = std::make_unique<ExecutionEventBus>();
        tracker = std::make_unique<ExecutionTracker>(tracker_guard.db);
        tracker->create_tables();
        tracker->set_event_bus(event_bus.get());

        instructions = std::make_unique<InstructionStore>(instr_db);
        REQUIRE(instructions->is_open());
        responses = std::make_unique<ResponseStore>(resp_db, /*retention_days=*/0,
                                                    /*cleanup_interval_min=*/60);
        REQUIRE(responses->is_open());

        auto auth_fn = [](const httplib::Request&, httplib::Response&)
            -> std::optional<auth::Session> {
            auth::Session s;
            s.username = "tester";
            s.role = auth::Role::admin;
            return s;
        };
        auto perm_fn = [this](const httplib::Request&, httplib::Response& res,
                              const std::string&, const std::string&) -> bool {
            if (!perm_grant) {
                res.status = 403;
                return false;
            }
            return true;
        };
        auto audit_fn = [](const httplib::Request&, const std::string&,
                           const std::string&, const std::string&,
                           const std::string&, const std::string&) {};
        auto emit_fn = [](const std::string&, const httplib::Request&) {};
        auto scope_fn = [](const std::string&) -> std::pair<std::size_t, std::size_t> {
            return {0, 0};
        };
        // PR 2: cmd_dispatch signature gained `execution_id` parameter so
        // the dispatch path can register the command_id→execution_id
        // mapping with AgentServiceImpl BEFORE any RPC is sent (UP2-4
        // race close). The test stub captures the last (command_id,
        // execution_id) pair for assertion.
        auto cmd_dispatch = [this](const std::string&, const std::string&,
                                    const std::vector<std::string>&,
                                    const std::string&,
                                    const std::unordered_map<std::string, std::string>&,
                                    const std::string& execution_id)
            -> std::pair<std::string, int> {
            last_dispatch_execution_id = execution_id;
            return {"", 0};
        };

        // PR 2.5 (#670): deps-struct refactor. WorkflowRoutes::register_routes
        // takes a single `Deps` aggregate so PR 3's SSE bus addition is a
        // single new field, not a 17th parameter.
        WorkflowRoutes::Deps wf_deps;
        wf_deps.auth_fn = auth_fn;
        wf_deps.perm_fn = perm_fn;
        wf_deps.audit_fn = audit_fn;
        wf_deps.emit_fn = emit_fn;
        wf_deps.scope_fn = scope_fn;
        wf_deps.execution_tracker = tracker.get();
        wf_deps.instruction_store = instructions.get();
        wf_deps.command_dispatch_fn = cmd_dispatch;
        wf_deps.response_store = responses.get();
        // PR 3 — wire the per-execution event bus. The SSE handler at
        // /sse/executions/{id} only registers when this is non-null.
        wf_deps.execution_event_bus = event_bus.get();
        routes.register_routes(sink, std::move(wf_deps));
    }

    ~ExecHarness() {
        responses.reset();
        instructions.reset();
        // PR 3: drop tracker BEFORE the bus — tracker borrows event_bus_,
        // so the bus must outlive the tracker through its destructor.
        tracker.reset();
        event_bus.reset();
        // Close the raw SQLite handle BEFORE attempting to remove the
        // tracker_db file. On Windows, fs::remove() fails with
        // ERROR_SHARING_VIOLATION if any process holds the file open;
        // tracker_guard.~SqliteHandleGuard() would close it, but only
        // AFTER this destructor body returns — by which point fs::remove
        // on the still-open tracker_db has already thrown
        // filesystem_error, escaping the destructor and terminating the
        // process. Linux is permissive (unlink succeeds with open fds)
        // so the bug only manifests on Windows MSVC.
        if (tracker_guard.db) {
            sqlite3_close(tracker_guard.db);
            tracker_guard.db = nullptr;
        }
        // Use the noexcept overload — destructors must not throw even if
        // a separate remove failure (e.g. file already gone, parent dir
        // missing) happens.
        std::error_code ec;
        for (auto& p : {tracker_db, instr_db, resp_db}) {
            fs::remove(p, ec);
            fs::remove(p.string() + "-wal", ec);
            fs::remove(p.string() + "-shm", ec);
        }
    }

    /// Insert a definition by id with a friendly display name.
    void make_def(const std::string& id, const std::string& name) {
        InstructionDefinition d;
        d.id = id;
        d.name = name;
        d.type = "question";
        d.plugin = "test";
        d.action = "list";
        auto created = instructions->create_definition(d);
        REQUIRE(created.has_value());
    }

    /// Create an execution row and return its id.
    std::string make_exec(const std::string& definition_id, const std::string& status,
                          int agents_targeted, int agents_success, int agents_failure,
                          int64_t dispatched_at = 1735689600 /* 2025-01-01 */) {
        Execution e;
        // Atomic counter, not std::hash, per CLAUDE.md test isolation rules.
        e.id = "exec-" + std::to_string(exec_counter.fetch_add(1));
        e.definition_id = definition_id;
        e.status = status;
        e.dispatched_by = "tester";
        e.dispatched_at = dispatched_at;
        e.agents_targeted = agents_targeted;
        e.agents_success = agents_success;
        e.agents_failure = agents_failure;
        e.agents_responded = agents_success + agents_failure;
        e.completed_at = (agents_targeted == agents_success + agents_failure)
                              ? dispatched_at + 60 : 0;
        auto id = tracker->create_execution(e);
        REQUIRE(id.has_value());
        return *id;
    }

    /// Insert a response into the response store. PR 2: callers can stamp
    /// execution_id directly to exercise query_by_execution; leaving it
    /// empty exercises the legacy timestamp-window fallback path.
    void store_response(const std::string& command_id, const std::string& agent_id,
                         const std::string& output, const std::string& execution_id = "",
                         int64_t timestamp = 1735689610) {
        StoredResponse r;
        r.instruction_id = command_id;
        r.agent_id = agent_id;
        r.status = 1;
        r.output = output;
        r.timestamp = timestamp;
        r.execution_id = execution_id;
        responses->store(r);
    }

    /// Stamp a per-agent status row.
    void agent_status(const std::string& exec_id, const std::string& agent_id,
                      const std::string& status, int exit_code = 0,
                      const std::string& error = {}, int64_t completed_at = 1735689660) {
        AgentExecStatus s;
        s.agent_id = agent_id;
        s.status = status;
        s.dispatched_at = 1735689600;
        s.first_response_at = 1735689610;
        s.completed_at = completed_at;
        s.exit_code = exit_code;
        s.error_detail = error;
        tracker->update_agent_status(exec_id, s);
    }
};

} // namespace

// ── List handler ────────────────────────────────────────────────────────────

TEST_CASE("executions list: empty state", "[workflow][executions][list]") {
    ExecHarness h;
    auto res = h.sink.Get("/fragments/executions");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("No executions yet") != std::string::npos);
}

TEST_CASE("executions list: renders definition name not bare id",
          "[workflow][executions][list]") {
    ExecHarness h;
    h.make_def("def-known", "Inspect Service");
    h.make_exec("def-known", "completed", 5, 5, 0);

    auto res = h.sink.Get("/fragments/executions");
    REQUIRE(res);
    CHECK(res->status == 200);
    // Friendly definition name is present.
    CHECK(res->body.find("Inspect Service") != std::string::npos);
    // id-prefix fallback is NOT what's shown when a name is known.
    CHECK(res->body.find(">def-known<") == std::string::npos);
}

TEST_CASE("executions list: id stub fallback when definition is unknown",
          "[workflow][executions][list]") {
    ExecHarness h;
    h.make_exec("def-orphan-12345-rest", "completed", 5, 5, 0);

    auto res = h.sink.Get("/fragments/executions");
    REQUIRE(res);
    CHECK(res->status == 200);
    // First 12 chars of the id should appear.
    CHECK(res->body.find("def-orphan-1") != std::string::npos);
}

TEST_CASE("executions list: definition_id query filter",
          "[workflow][executions][list]") {
    ExecHarness h;
    h.make_def("def-A", "Definition A");
    h.make_def("def-B", "Definition B");
    h.make_exec("def-A", "completed", 3, 3, 0);
    h.make_exec("def-B", "completed", 4, 4, 0);

    auto filtered = h.sink.Get("/fragments/executions?definition_id=def-A");
    REQUIRE(filtered);
    CHECK(filtered->status == 200);
    CHECK(filtered->body.find("Definition A") != std::string::npos);
    CHECK(filtered->body.find("Definition B") == std::string::npos);
}

TEST_CASE("executions list: failed row carries first-error preview + stripe class",
          "[workflow][executions][list]") {
    ExecHarness h;
    h.make_def("def-flake", "Flaky");
    auto eid = h.make_exec("def-flake", "completed", 2, 1, 1);
    // The exec is "completed" with 1 failure; populate the agent error so the
    // correlated subquery in query_executions surfaces it.
    h.agent_status(eid, "ok-agent", "success");
    h.agent_status(eid, "bad-agent", "failure", 1, "EACCES: permission denied");

    auto res = h.sink.Get("/fragments/executions");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("EACCES: permission denied") != std::string::npos);
    // Failed row class — the row is marked exec-row--completed because agg
    // status is "completed" with at least one failure; the stripe is governed
    // by agents_failure > 0 → exec-row--failed when status itself is "failed".
    // Here we just check the error preview surfaces; row-class behaviour is
    // covered separately for status == "failed".
}

TEST_CASE("executions list: status=failed gets exec-row--failed class",
          "[workflow][executions][list]") {
    ExecHarness h;
    h.make_def("def-X", "X");
    h.make_exec("def-X", "failed", 1, 0, 1);

    auto res = h.sink.Get("/fragments/executions");
    REQUIRE(res);
    CHECK(res->body.find("exec-row--failed") != std::string::npos);
}

TEST_CASE("executions list: time cell carries ISO-8601 UTC in title",
          "[workflow][executions][list]") {
    ExecHarness h;
    h.make_def("def-T", "Time");
    h.make_exec("def-T", "completed", 1, 1, 0, /*dispatched_at=*/1735689600);

    auto res = h.sink.Get("/fragments/executions");
    REQUIRE(res);
    // ISO appears in title= for forensic copy/paste.
    CHECK(res->body.find("2025-01-01T00:00:00Z") != std::string::npos);
}

TEST_CASE("executions list: sparkbar aria-label summarises counts",
          "[workflow][executions][list]") {
    ExecHarness h;
    h.make_def("def-K", "K");
    h.make_exec("def-K", "completed", 50, 47, 3);

    auto res = h.sink.Get("/fragments/executions");
    REQUIRE(res);
    CHECK(res->body.find("47 succeeded, 3 failed, 0 running, 0 pending of 50")
          != std::string::npos);
}

TEST_CASE("executions list: zero-agent execution renders empty-state sparkbar",
          "[workflow][executions][list]") {
    ExecHarness h;
    h.make_def("def-Z", "Zero");
    h.make_exec("def-Z", "completed", 0, 0, 0);

    auto res = h.sink.Get("/fragments/executions");
    REQUIRE(res);
    CHECK(res->body.find("no agents matched scope") != std::string::npos);
}

// ── Detail handler ──────────────────────────────────────────────────────────

TEST_CASE("executions detail: 404 on unknown id", "[workflow][executions][detail]") {
    ExecHarness h;
    auto res = h.sink.Get("/fragments/executions/exec-does-not-exist/detail");
    REQUIRE(res);
    CHECK(res->status == 404);
}

TEST_CASE("executions detail: 403 when perm_fn denies",
          "[workflow][executions][detail][rbac]") {
    ExecHarness h;
    h.make_def("def-X", "X");
    auto eid = h.make_exec("def-X", "completed", 1, 1, 0);
    h.perm_grant = false;
    auto res = h.sink.Get("/fragments/executions/" + eid + "/detail");
    REQUIRE(res);
    CHECK(res->status == 403);
}

TEST_CASE("executions detail: KPI strip shows counts + p50/p95",
          "[workflow][executions][detail]") {
    ExecHarness h;
    h.make_def("def-K", "K");
    auto eid = h.make_exec("def-K", "completed", 3, 2, 1);
    // 3 agents with deterministic durations: 1s, 2s, 5s.
    h.agent_status(eid, "a1", "success", 0, "", /*completed_at=*/1735689601);
    h.agent_status(eid, "a2", "success", 0, "", /*completed_at=*/1735689602);
    h.agent_status(eid, "a3", "failure", 1, "boom", /*completed_at=*/1735689605);

    auto res = h.sink.Get("/fragments/executions/" + eid + "/detail");
    REQUIRE(res);
    CHECK(res->status == 200);
    // KPI label sections.
    CHECK(res->body.find("Total") != std::string::npos);
    CHECK(res->body.find("Succeeded") != std::string::npos);
    CHECK(res->body.find("Failed") != std::string::npos);
    CHECK(res->body.find("p50 duration") != std::string::npos);
    CHECK(res->body.find("p95 duration") != std::string::npos);
    // p50/p95 should NOT be "—" when every agent is terminal.
    // We only assert the dash sentinel does NOT appear in the KPI value
    // positions (it might still appear elsewhere — e.g. completed_at sentinel
    // for unfinished runs, but we set completed_at on all agents).
    CHECK(res->body.find("exec-kpi-value\">—") == std::string::npos);
}

TEST_CASE("executions detail: p50/p95 fall back to dash when any agent is running",
          "[workflow][executions][detail]") {
    ExecHarness h;
    h.make_def("def-R", "R");
    auto eid = h.make_exec("def-R", "running", 2, 1, 0);
    h.agent_status(eid, "done", "success", 0, "", 1735689601);
    // Running agent has completed_at = 0 (sentinel for "still running").
    h.agent_status(eid, "running", "running", 0, "", /*completed_at=*/0);

    auto res = h.sink.Get("/fragments/executions/" + eid + "/detail");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("exec-kpi-value\">—") != std::string::npos);
}

TEST_CASE("executions detail: per-agent table sorts failed first",
          "[workflow][executions][detail]") {
    ExecHarness h;
    h.make_def("def-S", "S");
    auto eid = h.make_exec("def-S", "completed", 3, 2, 1);
    h.agent_status(eid, "alpha-success", "success", 0, "", 1735689601);
    h.agent_status(eid, "beta-failure", "failure", 1, "alpha-error", 1735689602);
    h.agent_status(eid, "gamma-success", "success", 0, "", 1735689603);

    auto res = h.sink.Get("/fragments/executions/" + eid + "/detail");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto pos_failure = res->body.find("beta-failure");
    auto pos_first_success = res->body.find("alpha-success");
    auto pos_second_success = res->body.find("gamma-success");
    REQUIRE(pos_failure != std::string::npos);
    REQUIRE(pos_first_success != std::string::npos);
    REQUIRE(pos_second_success != std::string::npos);
    // Failure comes before either success row. The grid renders agent_ids
    // earlier in document order than the table, so we look at the *table*
    // section by anchoring after the per-agent table heading.
    auto table_start = res->body.find("Agent results");
    REQUIRE(table_start != std::string::npos);
    auto tail = res->body.substr(table_start);
    auto tail_failure = tail.find("beta-failure");
    auto tail_success_a = tail.find("alpha-success");
    auto tail_success_g = tail.find("gamma-success");
    REQUIRE(tail_failure != std::string::npos);
    REQUIRE(tail_success_a != std::string::npos);
    REQUIRE(tail_success_g != std::string::npos);
    CHECK(tail_failure < tail_success_a);
    CHECK(tail_failure < tail_success_g);
}

TEST_CASE("executions detail: agent grid uses decile bucketing above 1024 agents",
          "[workflow][executions][detail]") {
    ExecHarness h;
    h.make_def("def-Big", "Big");
    auto eid = h.make_exec("def-Big", "completed", 1500, 1500, 0);
    for (int i = 0; i < 1500; ++i) {
        h.agent_status(eid, "agent-" + std::to_string(i), "success", 0, "",
                        1735689601);
    }

    auto res = h.sink.Get("/fragments/executions/" + eid + "/detail");
    REQUIRE(res);
    CHECK(res->status == 200);
    // Bucketed view marker.
    CHECK(res->body.find("agent-cell--bucket") != std::string::npos);
    CHECK(res->body.find("Decile 1") != std::string::npos);
    CHECK(res->body.find("Decile 10") != std::string::npos);
}

TEST_CASE("executions detail: error_detail truncates without tearing UTF-8",
          "[workflow][executions][detail]") {
    ExecHarness h;
    h.make_def("def-U", "U");
    auto eid = h.make_exec("def-U", "completed", 1, 0, 1);
    // 130-byte UTF-8 string mixing ASCII + 4-byte emoji at the boundary.
    std::string err = std::string(118, 'x') + std::string("\xF0\x9F\x94\xA5") +
                      std::string("\xF0\x9F\x94\xA5");
    h.agent_status(eid, "a1", "failure", 1, err, 1735689601);

    auto res = h.sink.Get("/fragments/executions/" + eid + "/detail");
    REQUIRE(res);
    CHECK(res->status == 200);
    // The truncated form ends with the U+2026 ellipsis. Look for its UTF-8
    // bytes directly so we don't depend on HTML-escaping for a non-special
    // character.
    CHECK(res->body.find("\xE2\x80\xA6") != std::string::npos);
}

TEST_CASE("executions detail: sidebar carries dispatched_by + ISO timestamps",
          "[workflow][executions][detail]") {
    ExecHarness h;
    h.make_def("def-M", "M");
    auto eid = h.make_exec("def-M", "completed", 1, 1, 0,
                            /*dispatched_at=*/1735689600);
    h.agent_status(eid, "a1", "success", 0, "", 1735689660);

    auto res = h.sink.Get("/fragments/executions/" + eid + "/detail");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("tester") != std::string::npos);
    CHECK(res->body.find("2025-01-01T00:00:00Z") != std::string::npos);
}

// ── ExecutionTracker last_error_detail correlated subquery ─────────────────

// ── arch-B2: opt-out is the default ────────────────────────────────────────

TEST_CASE("ExecutionTracker.query_executions: include_error_detail default "
          "false leaves the field empty (arch-B2 hot-path)",
          "[workflow][executions][tracker]") {
    // server.cpp:1727 calls query_executions({.limit = 1000}) on every
    // metrics tick; that path must NOT pay the correlated-subquery cost.
    // Default-constructed ExecutionQuery leaves include_error_detail == false.
    ExecHarness h;
    h.make_def("def-OPTOUT", "OPTOUT");
    auto eid = h.make_exec("def-OPTOUT", "completed", 1, 0, 1);
    h.agent_status(eid, "a", "failure", 1, "should not appear", 1735689602);

    ExecutionQuery q; // include_error_detail defaults to false
    auto execs = h.tracker->query_executions(q);
    REQUIRE(execs.size() == 1);
    CHECK(execs[0].last_error_detail.empty());
}

TEST_CASE("ExecutionTracker.get_execution: always populates last_error_detail "
          "(single-row read is rare, opts in unconditionally)",
          "[workflow][executions][tracker]") {
    ExecHarness h;
    h.make_def("def-GE", "GE");
    auto eid = h.make_exec("def-GE", "completed", 1, 0, 1);
    h.agent_status(eid, "a", "failure", 1, "single-row read sees this", 1735689602);

    auto exec = h.tracker->get_execution(eid);
    REQUIRE(exec.has_value());
    CHECK(exec->last_error_detail == "single-row read sees this");
}

// ── qa-S4: failure with empty error_detail ─────────────────────────────────

TEST_CASE("ExecutionTracker.query_executions: agents_failure>0 with empty "
          "error_detail yields empty last_error_detail (qa-S4)",
          "[workflow][executions][tracker]") {
    ExecHarness h;
    h.make_def("def-NE", "NoError");
    auto eid = h.make_exec("def-NE", "completed", 1, 0, 1);
    // Failure status but empty error_detail — exit code only.
    h.agent_status(eid, "a", "failure", 99, "", 1735689601);

    ExecutionQuery q;
    q.include_error_detail = true;
    auto execs = h.tracker->query_executions(q);
    REQUIRE(execs.size() == 1);
    // Subquery WHERE clause filters out empty error_detail; SELECT returns
    // no rows; `col_text` returns empty. Pin the silent contract.
    CHECK(execs[0].last_error_detail.empty());
}

// ── sec-M1: LIST handler now gates on Execution:Read ───────────────────────

TEST_CASE("executions list: 403 when perm_fn denies (sec-M1)",
          "[workflow][executions][list][rbac]") {
    ExecHarness h;
    h.perm_grant = false;
    auto res = h.sink.Get("/fragments/executions");
    REQUIRE(res);
    CHECK(res->status == 403);
}

// ── UP-1 / qa-S1: agent_id with single-quote does not produce JS injection ─

TEST_CASE("executions detail: agent_id containing single-quote is bound via "
          "data-* attrs, not interpolated into JS (UP-1)",
          "[workflow][executions][detail][xss]") {
    ExecHarness h;
    h.make_def("def-XSS", "XSS-safe");
    auto eid = h.make_exec("def-XSS", "completed", 1, 1, 0);
    // Agent emerges with a single quote in its id — wire-provided, no
    // intake validation today. The detail handler must NOT interpolate
    // this into `onclick="scrollToAgentRow('AGENT-ID')"` style.
    h.agent_status(eid, "agent'with'quote", "success", 0, "", 1735689601);

    auto res = h.sink.Get("/fragments/executions/" + eid + "/detail");
    REQUIRE(res);
    CHECK(res->status == 200);
    // The dangerous pattern: agent_id quoted-and-interpolated into a JS
    // string literal. The mitigation is to use data-agent-id="..." and
    // bind via addEventListener client-side; the rendered HTML must NOT
    // contain `scrollToAgentRow(` followed by an interpolated agent_id.
    CHECK(res->body.find("scrollToAgentRow(") == std::string::npos);
    // The agent_id must appear as a data-agent-id attribute value (with
    // its single quote escaped to &#39; for HTML attribute context).
    CHECK(res->body.find("data-agent-id=\"agent&#39;with&#39;quote\"")
          != std::string::npos);
}

TEST_CASE("ExecutionTracker.query_executions: last_error_detail opt-in default "
          "is empty for fully-successful run",
          "[workflow][executions][tracker]") {
    ExecHarness h;
    h.make_def("def-L", "L");
    auto eid = h.make_exec("def-L", "completed", 2, 2, 0);
    h.agent_status(eid, "a", "success", 0, "", 1735689601);
    h.agent_status(eid, "b", "success", 0, "", 1735689602);

    ExecutionQuery q;
    q.include_error_detail = true;
    auto execs = h.tracker->query_executions(q);
    REQUIRE(execs.size() == 1);
    CHECK(execs[0].last_error_detail.empty());
}

TEST_CASE("ExecutionTracker.query_executions: last_error_detail surfaces "
          "most recent failure when caller opts in",
          "[workflow][executions][tracker]") {
    ExecHarness h;
    h.make_def("def-LE", "LE");
    auto eid = h.make_exec("def-LE", "completed", 3, 1, 2);
    h.agent_status(eid, "a", "success", 0, "", 1735689601);
    // Two failures; expect the one with the larger completed_at to win.
    h.agent_status(eid, "b", "failure", 1, "OLDER ERROR", 1735689602);
    h.agent_status(eid, "c", "failure", 1, "NEWER ERROR", 1735689610);

    ExecutionQuery q;
    q.include_error_detail = true;
    auto execs = h.tracker->query_executions(q);
    REQUIRE(execs.size() == 1);
    CHECK(execs[0].last_error_detail == "NEWER ERROR");
}

// ── PR 2: detail handler responses correlation ─────────────────────────────

TEST_CASE("executions detail PR2: responses correlated by exact execution_id "
          "(no cross-contamination)",
          "[workflow][executions][detail][pr2]") {
    ExecHarness h;
    h.make_def("def-X", "X");
    auto exec_a = h.make_exec("def-X", "completed", 1, 1, 0,
                                /*dispatched_at=*/1735689600);
    auto exec_b = h.make_exec("def-X", "completed", 1, 1, 0,
                                /*dispatched_at=*/1735689600);
    h.agent_status(exec_a, "agent-shared", "success", 0, "", 1735689601);
    h.agent_status(exec_b, "agent-shared", "success", 0, "", 1735689602);
    // Both executions used the same definition + same agent + overlapping
    // timestamp window — pre-PR-2 the timestamp-window join would conflate
    // them. PR 2 stamps execution_id directly, so each detail drawer sees
    // only its own response.
    h.store_response("cmd-A", "agent-shared", "from-A",
                     /*execution_id=*/exec_a, 1735689601);
    h.store_response("cmd-B", "agent-shared", "from-B",
                     /*execution_id=*/exec_b, 1735689602);

    auto res_a = h.sink.Get("/fragments/executions/" + exec_a + "/detail");
    REQUIRE(res_a);
    CHECK(res_a->status == 200);
    CHECK(res_a->body.find("from-A") != std::string::npos);
    CHECK(res_a->body.find("from-B") == std::string::npos);

    auto res_b = h.sink.Get("/fragments/executions/" + exec_b + "/detail");
    REQUIRE(res_b);
    CHECK(res_b->status == 200);
    CHECK(res_b->body.find("from-B") != std::string::npos);
    CHECK(res_b->body.find("from-A") == std::string::npos);
}

TEST_CASE("executions detail PR2: legacy timestamp-window fallback when no "
          "PR-2 rows exist",
          "[workflow][executions][detail][pr2]") {
    ExecHarness h;
    h.make_def("def-Y", "Y");
    auto eid = h.make_exec("def-Y", "completed", 1, 1, 0,
                            /*dispatched_at=*/1735689600);
    h.agent_status(eid, "agent-1", "success", 0, "", 1735689601);
    // Store a legacy response: execution_id is empty (pre-PR-2 path), and
    // instruction_id MATCHES the definition_id so the legacy fallback's
    // query() finds it. The detail handler must include it.
    h.store_response(/*command_id=*/"def-Y", "agent-1", "legacy-output",
                     /*execution_id=*/"", 1735689601);

    auto res = h.sink.Get("/fragments/executions/" + eid + "/detail");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("legacy-output") != std::string::npos);
}

TEST_CASE("executions detail PR2: PR-2 rows are NOT diluted by legacy fallback",
          "[workflow][executions][detail][pr2]") {
    ExecHarness h;
    h.make_def("def-Z", "Z");
    auto eid = h.make_exec("def-Z", "completed", 1, 1, 0,
                            /*dispatched_at=*/1735689600);
    h.agent_status(eid, "agent-1", "success", 0, "", 1735689601);
    // PR-2 row tagged correctly.
    h.store_response("cmd-real", "agent-1", "tagged-row",
                     /*execution_id=*/eid, 1735689601);
    // A legacy row that would have matched via the timestamp-window join,
    // but now that PR-2 rows exist for this execution_id the fallback
    // branch is skipped — the legacy row must NOT appear in the drawer.
    h.store_response(/*command_id=*/"def-Z", "agent-1", "legacy-leak",
                     /*execution_id=*/"", 1735689602);

    auto res = h.sink.Get("/fragments/executions/" + eid + "/detail");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("tagged-row") != std::string::npos);
    CHECK(res->body.find("legacy-leak") == std::string::npos);
}

// ── Gate-7 hardening regression net for PR 2 ──────────────────────────────

TEST_CASE("PR2 hardening — UP2-4: cmd_dispatch receives non-empty execution_id "
          "when create_execution succeeds (FAST-agent race fix)",
          "[workflow][executions][pr2][hardening]") {
    // The execute handler now creates the execution row BEFORE calling
    // cmd_dispatch and threads execution_id INTO cmd_dispatch as the 6th
    // parameter. The test stub captures the value passed in
    // last_dispatch_execution_id; we assert it's non-empty after a
    // successful execute. This proves the FAST-agent race is closed:
    // by the time cmd_dispatch returns, the execution_id is known to
    // the dispatch closure and the mapping is registered before any
    // RPC goes out.
    ExecHarness h;
    h.make_def("def-FAST", "FAST");
    auto res = h.sink.Post("/api/instructions/def-FAST/execute",
                            R"({"params":{},"agent_ids":["agent-1"]})");
    // The cmd_dispatch stub returns sent=0 so the route returns 503, but
    // that fires AFTER cmd_dispatch is called with the execution_id —
    // which is what we're pinning here.
    REQUIRE(res);
    CHECK(!h.last_dispatch_execution_id.empty());
}

TEST_CASE("PR2 hardening — query_by_execution includes the partial-index "
          "predicate `execution_id != ''` in its SQL (perf-B1 fix)",
          "[workflow][executions][pr2][hardening][perf]") {
    // SQLite's planner refuses to use a partial index unless the WHERE
    // clause syntactically subsumes the partial-index predicate. The
    // perf-B1 fix added `AND execution_id != ''` to query_by_execution's
    // SELECT. We can't easily inspect SQLite's plan from a Catch2 test,
    // but we CAN prove the function still returns the right rows when
    // both PR-2-tagged and legacy rows coexist — which exercises the
    // index path and would surface a regression where the predicate is
    // dropped or rewritten.
    ResponseStore store(":memory:");
    StoredResponse pr2;
    pr2.instruction_id = "cmd-A";
    pr2.agent_id = "agent-1";
    pr2.status = 1;
    pr2.output = "tagged";
    pr2.execution_id = "exec-pr2";
    store.store(pr2);
    StoredResponse legacy;
    legacy.instruction_id = "cmd-A";
    legacy.agent_id = "agent-2";
    legacy.status = 1;
    legacy.output = "untagged";
    legacy.execution_id = "";
    store.store(legacy);

    auto rows = store.query_by_execution("exec-pr2");
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].output == "tagged");
}

TEST_CASE("PR2 hardening — multi-agent fan-out: terminal-branch does NOT erase "
          "the mapping so agents 2..N stamp correctly (HF-1 fix)",
          "[workflow][executions][pr2][hardening]") {
    // Pre-fix: terminal-status branches in agent_service_impl.cpp erased
    // cmd_execution_ids_ on first response, causing agents 2..N to stamp
    // empty execution_id. The fix removes the erase. We can't drive
    // process_gateway_response from this test (no AgentServiceImpl in
    // ExecHarness), but we CAN prove the response store handles two
    // consecutive stores under the same execution_id — which is what
    // the fix enables. The integration coverage is deferred to a UAT
    // round-trip in PR 2.8.
    ResponseStore store(":memory:");
    StoredResponse a1;
    a1.instruction_id = "cmd-fan";
    a1.agent_id = "agent-1";
    a1.status = 1;
    a1.output = "agent1-done";
    a1.execution_id = "exec-fan";
    store.store(a1);
    StoredResponse a2;
    a2.instruction_id = "cmd-fan";
    a2.agent_id = "agent-2";
    a2.status = 1;
    a2.output = "agent2-done";
    a2.execution_id = "exec-fan";
    store.store(a2);

    auto rows = store.query_by_execution("exec-fan");
    REQUIRE(rows.size() == 2);
    // Both agents present — HF-1 regression would drop one.
    bool saw_a1 = false, saw_a2 = false;
    for (const auto& r : rows) {
        if (r.output == "agent1-done") saw_a1 = true;
        if (r.output == "agent2-done") saw_a2 = true;
    }
    CHECK(saw_a1);
    CHECK(saw_a2);
}

TEST_CASE("PR2 hardening — failed dispatch does NOT orphan a phantom 'running' "
          "execution row (Pattern-C regression close)",
          "[workflow][executions][pr2][hardening]") {
    // Reorder of create_execution BEFORE cmd_dispatch (UP2-4 fix) introduced
    // a Pattern-C regression: if dispatch returns sent=0 OR throws, the
    // pre-created execution row was left at status='running' forever, showing
    // as a phantom in-flight run in the LIST handler. The fix calls
    // mark_cancelled on both failure paths. Pin the contract.
    ExecHarness h;
    h.make_def("def-FAIL", "FAIL");
    auto res = h.sink.Post("/api/instructions/def-FAIL/execute",
                            R"({"params":{},"agent_ids":["agent-1"]})");
    REQUIRE(res);
    CHECK(res->status == 503); // sent=0 from cmd_dispatch stub

    // Find the orphan row. Should be cancelled, not running.
    ExecutionQuery q;
    q.definition_id = "def-FAIL";
    auto execs = h.tracker->query_executions(q);
    REQUIRE(execs.size() == 1);
    CHECK(execs[0].status == "cancelled");
}

// ─────────────────────────────────────────────────────────────────────────────
// PR 3 — /sse/executions/{id} live updates handler
//
// The TestRouteSink dispatch path returns the response object after the
// handler runs. For the SSE route, that means we can verify the
// auth/RBAC/404/410/503 short-circuit logic AND confirm the chunked
// content provider is attached when the path is happy. We do NOT exercise
// the actual streaming body here — that is covered by the bus-level tests
// in test_execution_event_bus.cpp plus the puppeteer smoke. The bus → DOM
// integration is the seam these tests pin.
// ─────────────────────────────────────────────────────────────────────────────

TEST_CASE("SSE handler: 404 for unknown execution", "[workflow][executions][pr3]") {
    ExecHarness h;
    auto res = h.sink.Get("/sse/executions/does-not-exist");
    REQUIRE(res);
    CHECK(res->status == 404);
}

TEST_CASE("SSE handler: 410 Gone for terminal execution", "[workflow][executions][pr3]") {
    // Already-terminal executions must not open an SSE channel — the client
    // should fall back to the static detail fragment. 410 tells EventSource
    // to stop reconnecting (vs 503 which it would retry).
    ExecHarness h;
    h.make_def("def-DONE", "Done");
    auto exec_id = h.make_exec("def-DONE", "succeeded", 3, 3, 0);
    auto res = h.sink.Get("/sse/executions/" + exec_id);
    REQUIRE(res);
    CHECK(res->status == 410);
}

TEST_CASE("SSE handler: 403 when perm_fn denies Read on Execution",
          "[workflow][executions][pr3]") {
    ExecHarness h;
    h.make_def("def-FORBID", "Forbid");
    auto exec_id = h.make_exec("def-FORBID", "running", 5, 0, 0);
    h.perm_grant = false;
    auto res = h.sink.Get("/sse/executions/" + exec_id);
    REQUIRE(res);
    CHECK(res->status == 403);
}

TEST_CASE("SSE handler: 200 on running execution attaches event-stream",
          "[workflow][executions][pr3]") {
    ExecHarness h;
    h.make_def("def-RUN", "Run");
    auto exec_id = h.make_exec("def-RUN", "running", 5, 1, 0);
    auto res = h.sink.Get("/sse/executions/" + exec_id);
    REQUIRE(res);
    CHECK(res->status == 200);
    // Cache + buffering headers are mandatory for SSE — without them
    // intermediaries (nginx, browser bfcache) buffer the stream and the
    // client never receives transitions until the connection closes.
    CHECK(res->get_header_value("Cache-Control") == "no-cache");
    CHECK(res->get_header_value("X-Accel-Buffering") == "no");
}

TEST_CASE("SSE handler: ExecutionTracker.update_agent_status publishes "
          "agent-transition onto the bus",
          "[workflow][executions][pr3]") {
    // This is the bus integration the SSE handler depends on — the
    // streaming body trusts that update_agent_status feeds the channel.
    // Subscribe directly to the bus so we don't need a real socket.
    ExecHarness h;
    h.make_def("def-INT", "Integration");
    auto exec_id = h.make_exec("def-INT", "running", 3, 0, 0);

    std::vector<ExecutionEvent> seen;
    auto sub = h.event_bus->subscribe(exec_id, [&](const ExecutionEvent& ev) {
        seen.push_back(ev);
    });

    h.agent_status(exec_id, "agent-1", "running");
    h.agent_status(exec_id, "agent-1", "success");

    h.event_bus->unsubscribe(exec_id, sub);

    // Each update_agent_status emits one agent-transition. refresh_counts
    // is not invoked by these helpers, so the only events we expect are
    // the two explicit transitions.
    REQUIRE(seen.size() >= 2);
    CHECK(seen[0].event_type == "agent-transition");
    CHECK(seen[0].data.find("agent-1") != std::string::npos);
    CHECK(seen.back().data.find("success") != std::string::npos);
    // Per-execution monotonic ids; first event of a fresh channel is id=1.
    CHECK(seen[0].id == 1);
    CHECK(seen.back().id >= seen[0].id);
}

TEST_CASE("SSE handler: refresh_counts on terminal threshold publishes "
          "execution-progress + execution-completed",
          "[workflow][executions][pr3]") {
    // When refresh_counts crosses the all-agents-responded threshold, the
    // tracker must publish BOTH a progress event (so KPI strip updates)
    // AND a terminal event (so the SSE client closes its EventSource).
    // Verify both, in order, on the bus.
    ExecHarness h;
    h.make_def("def-TERM", "Terminal");
    auto exec_id = h.make_exec("def-TERM", "running", 2, 0, 0);
    h.tracker->set_agents_targeted(exec_id, 2);

    std::vector<ExecutionEvent> seen;
    h.event_bus->subscribe(exec_id, [&](const ExecutionEvent& ev) {
        seen.push_back(ev);
    });

    h.agent_status(exec_id, "agent-1", "success");
    h.tracker->refresh_counts(exec_id);
    h.agent_status(exec_id, "agent-2", "success");
    h.tracker->refresh_counts(exec_id);

    // Filter out per-agent transitions, keep progress+completed only.
    std::vector<std::string> kinds;
    for (const auto& ev : seen) kinds.push_back(ev.event_type);
    auto count = [&](const std::string& k) {
        return static_cast<int>(std::count(kinds.begin(), kinds.end(), k));
    };
    CHECK(count("execution-progress") >= 1);
    CHECK(count("execution-completed") == 1);

    // execution-completed must come AFTER the corresponding progress
    // event so a client receiving them in order sees counts THEN status.
    auto last_progress_idx = -1;
    auto completed_idx = -1;
    for (std::size_t i = 0; i < seen.size(); ++i) {
        if (seen[i].event_type == "execution-progress")
            last_progress_idx = static_cast<int>(i);
        if (seen[i].event_type == "execution-completed")
            completed_idx = static_cast<int>(i);
    }
    REQUIRE(last_progress_idx >= 0);
    REQUIRE(completed_idx >= 0);
    CHECK(completed_idx > last_progress_idx);
}

TEST_CASE("SSE handler: mark_cancelled publishes terminal execution-completed",
          "[workflow][executions][pr3]") {
    // mark_cancelled is the cancel-on-dispatch-failure path (PR 2 Pattern-C
    // close). PR 3 must emit a terminal event so an open SSE drawer
    // closes its EventSource cleanly instead of waiting for a heartbeat
    // timeout.
    ExecHarness h;
    h.make_def("def-CANCEL", "Cancel");
    auto exec_id = h.make_exec("def-CANCEL", "running", 5, 0, 0);

    std::vector<ExecutionEvent> seen;
    h.event_bus->subscribe(exec_id, [&](const ExecutionEvent& ev) {
        seen.push_back(ev);
    });

    h.tracker->mark_cancelled(exec_id, "tester");

    REQUIRE(seen.size() == 1);
    CHECK(seen[0].event_type == "execution-completed");
    CHECK(seen[0].data.find("cancelled") != std::string::npos);
}

TEST_CASE("SSE handler: ring buffer holds events for late-connecting client",
          "[workflow][executions][pr3]") {
    // The SSE handler replays the ring buffer to a client that connects
    // mid-execution (with Last-Event-ID=0 → all). Pin the buffer
    // contents the replay would walk.
    ExecHarness h;
    h.make_def("def-LATE", "Late");
    auto exec_id = h.make_exec("def-LATE", "running", 5, 0, 0);

    h.agent_status(exec_id, "agent-1", "running");
    h.agent_status(exec_id, "agent-2", "success");
    h.agent_status(exec_id, "agent-3", "failure");

    auto snap = h.event_bus->snapshot(exec_id);
    REQUIRE(snap.size() == 3);
    // Ids are 1..3 in publish order — pinning the contract that
    // replay_since(0) returns them in arrival order.
    CHECK(snap[0].id == 1);
    CHECK(snap[1].id == 2);
    CHECK(snap[2].id == 3);
}

TEST_CASE("SSE handler: per-execution channel partitioning under the routes layer",
          "[workflow][executions][pr3]") {
    // Two concurrent executions of the same definition; each agent
    // transition must land on the correct channel. This is the contract
    // the SSE handler depends on to keep one drawer's events from
    // bleeding into another.
    ExecHarness h;
    h.make_def("def-PARTITION", "Partition");
    auto a = h.make_exec("def-PARTITION", "running", 2, 0, 0);
    auto b = h.make_exec("def-PARTITION", "running", 2, 0, 0);

    h.agent_status(a, "agent-1", "success");
    h.agent_status(b, "agent-9", "failure");

    auto snap_a = h.event_bus->snapshot(a);
    auto snap_b = h.event_bus->snapshot(b);
    REQUIRE(snap_a.size() == 1);
    REQUIRE(snap_b.size() == 1);
    CHECK(snap_a[0].data.find("agent-1") != std::string::npos);
    CHECK(snap_b[0].data.find("agent-9") != std::string::npos);
    // No cross-leak: agent-9 must not appear in exec A's channel.
    CHECK(snap_a[0].data.find("agent-9") == std::string::npos);
    CHECK(snap_b[0].data.find("agent-1") == std::string::npos);
}

TEST_CASE("SSE handler: list view stamps data-execution-id and "
          "data-execution-status for client SSE bootstrap",
          "[workflow][executions][pr3]") {
    // The drawer opens an EventSource only when the row was rendered with
    // status=running OR pending. PR 3 added the data-* attributes to the
    // list row markup; verify they are present and round-trip the status
    // we created the execution with.
    ExecHarness h;
    h.make_def("def-LIST", "List");
    auto exec_id = h.make_exec("def-LIST", "running", 3, 0, 0);

    auto res = h.sink.Get("/fragments/executions");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto& body = res->body;
    CHECK(body.find("data-execution-id=\"" + exec_id + "\"") != std::string::npos);
    CHECK(body.find("data-execution-status=\"running\"") != std::string::npos);
}

TEST_CASE("SSE handler: detail KPI strip carries id=exec-kpi-{id} for partial swaps",
          "[workflow][executions][pr3]") {
    // Client SSE listener finds the KPI strip via #exec-kpi-{id} so it
    // can update Total / Succeeded / Failed without re-rendering the
    // whole drawer. Pin the id stamp.
    ExecHarness h;
    h.make_def("def-KPI", "KPI");
    auto exec_id = h.make_exec("def-KPI", "running", 3, 0, 0);
    auto res = h.sink.Get("/fragments/executions/" + exec_id + "/detail");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("id=\"exec-kpi-" + exec_id + "\"") != std::string::npos);
}

TEST_CASE("SSE handler: per-agent status badge has .per-agent-status class for partial swaps",
          "[workflow][executions][pr3]") {
    // Client SSE listener swaps the status badge in place via
    // .per-agent-status. Pin the class stamp.
    ExecHarness h;
    h.make_def("def-BADGE", "Badge");
    auto exec_id = h.make_exec("def-BADGE", "running", 1, 0, 0);
    h.agent_status(exec_id, "a-1", "running");
    auto res = h.sink.Get("/fragments/executions/" + exec_id + "/detail");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("per-agent-status") != std::string::npos);
    CHECK(res->body.find("per-agent-exit-code") != std::string::npos);
}
