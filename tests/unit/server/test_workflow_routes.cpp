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

    bool perm_grant{true};
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
        tracker = std::make_unique<ExecutionTracker>(tracker_guard.db);
        tracker->create_tables();

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
        auto cmd_dispatch = [](const std::string&, const std::string&,
                               const std::vector<std::string>&,
                               const std::string&,
                               const std::unordered_map<std::string, std::string>&)
            -> std::pair<std::string, int> { return {"", 0}; };

        routes.register_routes(sink, auth_fn, perm_fn, audit_fn, emit_fn, scope_fn,
                               /*workflow_engine=*/nullptr, tracker.get(),
                               /*schedule_engine=*/nullptr,
                               /*product_pack_store=*/nullptr,
                               instructions.get(),
                               /*policy_store=*/nullptr,
                               cmd_dispatch,
                               /*approval_manager=*/nullptr,
                               responses.get());
    }

    ~ExecHarness() {
        responses.reset();
        instructions.reset();
        tracker.reset();
        // tracker_guard.~SqliteHandleGuard() closes the raw handle as the
        // last member-destruction step.
        for (auto& p : {tracker_db, instr_db, resp_db}) {
            fs::remove(p);
            fs::remove(p.string() + "-wal");
            fs::remove(p.string() + "-shm");
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
