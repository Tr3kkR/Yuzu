/**
 * test_agent_service_impl.cpp — coverage for AgentServiceImpl response-path
 * helpers. Closes the gap explicitly deferred at
 * test_workflow_routes.cpp:820 ("no AgentServiceImpl in ExecHarness")
 * by constructing a real AgentServiceImpl and driving response receipt
 * end-to-end into a real ResponseStore.
 *
 * Pins three contracts called out in #117 (response-streaming coverage):
 *
 *   1. record_execution_id() registers the command_id → execution_id
 *      mapping consumed at response receipt; passing an empty
 *      execution_id removes the entry (the documented "clear" semantics
 *      from agent_service_impl.cpp:586).
 *
 *   2. process_gateway_response() stamps execution_id onto every
 *      StoredResponse (RUNNING and terminal branches both), so the
 *      executions detail drawer's `query_by_execution` path sees the
 *      stream. A response with no recorded mapping degrades cleanly —
 *      execution_id stays empty rather than crashing or fabricating.
 *
 *   3. The HF-1 multi-agent fan-out invariant: the terminal branch
 *      MUST NOT erase the mapping after the first agent's terminal
 *      response, otherwise agents 2..N stamp empty execution_id and
 *      the drawer drops them. This was a real PR-2 hardening regression
 *      (see agent_service_impl.cpp:672-674); the response-store-level
 *      pin at test_workflow_routes.cpp:814 only proves the store
 *      handles two stamped rows — this test proves the upstream path
 *      actually emits two stamped rows from a single mapping.
 */

#include "agent_service_impl.hpp"

#include <catch2/catch_test_macros.hpp>

#include "agent_registry.hpp"
#include "event_bus.hpp"
#include "response_store.hpp"
#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auto_approve.hpp>

#include <memory>
#include <string>

namespace apb = ::yuzu::agent::v1;
using yuzu::server::ResponseStore;
using yuzu::server::StoredResponse;
using yuzu::server::detail::AgentRegistry;
using yuzu::server::detail::AgentServiceImpl;
using yuzu::server::detail::EventBus;

namespace {

/// Minimal harness: real AgentServiceImpl wired against in-memory
/// ResponseStore. analytics/notification/webhook stores stay null so
/// the side-effect branches in process_gateway_response short-circuit
/// on their `if (store_)` guards — keeps the test focused on the
/// execution_id stamping invariant.
struct GatewayResponseHarness {
    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    yuzu::server::auth::AuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    AgentServiceImpl svc{
        registry, bus, /*require_client_identity=*/false, auth_mgr, auto_approve, metrics,
        /*gateway_mode=*/false};
    ResponseStore responses{":memory:"};

    GatewayResponseHarness() {
        REQUIRE(responses.is_open());
        svc.set_response_store(&responses);
    }

    static apb::CommandResponse make_response(const std::string& command_id,
                                              apb::CommandResponse::Status status,
                                              const std::string& output = "",
                                              int exit_code = 0) {
        apb::CommandResponse r;
        r.set_command_id(command_id);
        r.set_status(status);
        r.set_output(output);
        r.set_exit_code(exit_code);
        return r;
    }
};

} // namespace

// ── record_execution_id ────────────────────────────────────────────────────

TEST_CASE("record_execution_id: terminal response stamps mapped execution_id",
          "[agent_service][executions][pr2]") {
    GatewayResponseHarness h;
    h.svc.record_execution_id("cmd-A", "exec-42");

    auto resp = GatewayResponseHarness::make_response(
        "cmd-A", apb::CommandResponse::SUCCESS, /*output=*/"", /*exit_code=*/0);
    h.svc.process_gateway_response("agent-1", resp);

    auto rows = h.responses.query_by_execution("exec-42");
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].execution_id == "exec-42");
    CHECK(rows[0].agent_id == "agent-1");
    CHECK(rows[0].instruction_id == "cmd-A");
    CHECK(rows[0].status == static_cast<int>(apb::CommandResponse::SUCCESS));
}

TEST_CASE("record_execution_id: empty execution_id removes the mapping",
          "[agent_service][executions][pr2]") {
    GatewayResponseHarness h;
    h.svc.record_execution_id("cmd-A", "exec-42");
    h.svc.record_execution_id("cmd-A", ""); // documented clear semantics

    auto resp = GatewayResponseHarness::make_response("cmd-A",
                                                     apb::CommandResponse::SUCCESS);
    h.svc.process_gateway_response("agent-1", resp);

    auto by_exec = h.responses.query_by_execution("exec-42");
    CHECK(by_exec.empty()); // mapping cleared → row not tagged
    auto by_cmd = h.responses.get_by_instruction("cmd-A");
    REQUIRE(by_cmd.size() == 1);
    CHECK(by_cmd[0].execution_id.empty());
}

// ── process_gateway_response: per-status branches ──────────────────────────

TEST_CASE("process_gateway_response: RUNNING streaming row carries execution_id",
          "[agent_service][executions][pr2]") {
    // The RUNNING branch lives at agent_service_impl.cpp:597-655 — it both
    // stores a streaming row and stamps execution_id from the same map.
    // Pin both halves: the row exists AND it carries the tag.
    GatewayResponseHarness h;
    h.svc.record_execution_id("cmd-stream", "exec-stream");

    auto running = GatewayResponseHarness::make_response("cmd-stream",
                                                        apb::CommandResponse::RUNNING,
                                                        /*output=*/"row-1");
    h.svc.process_gateway_response("agent-1", running);

    auto rows = h.responses.query_by_execution("exec-stream");
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].status == static_cast<int>(apb::CommandResponse::RUNNING));
    CHECK(rows[0].output == "row-1");
}

TEST_CASE("process_gateway_response: FAILURE preserves error_detail and execution_id",
          "[agent_service][executions][pr2]") {
    GatewayResponseHarness h;
    h.svc.record_execution_id("cmd-fail", "exec-fail");

    auto resp = GatewayResponseHarness::make_response("cmd-fail",
                                                     apb::CommandResponse::FAILURE,
                                                     /*output=*/"",
                                                     /*exit_code=*/2);
    resp.mutable_error()->set_message("plugin returned non-zero");
    h.svc.process_gateway_response("agent-1", resp);

    auto rows = h.responses.query_by_execution("exec-fail");
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].error_detail == "plugin returned non-zero");
    CHECK(rows[0].execution_id == "exec-fail");
    CHECK(rows[0].status == static_cast<int>(apb::CommandResponse::FAILURE));
}

TEST_CASE("process_gateway_response: unmapped command_id stamps empty execution_id",
          "[agent_service][executions][pr2]") {
    // Out-of-band dispatch (CLI / direct gRPC) bypasses the dispatch path
    // that calls record_execution_id. The receipt path must degrade to an
    // empty execution_id rather than crashing or inventing a value.
    GatewayResponseHarness h;
    auto resp = GatewayResponseHarness::make_response("cmd-orphan",
                                                     apb::CommandResponse::SUCCESS);
    h.svc.process_gateway_response("agent-1", resp);

    auto by_cmd = h.responses.get_by_instruction("cmd-orphan");
    REQUIRE(by_cmd.size() == 1);
    CHECK(by_cmd[0].execution_id.empty());
}

// ── HF-1 multi-agent fan-out invariant ─────────────────────────────────────

TEST_CASE("process_gateway_response: terminal branch does NOT erase mapping "
          "(HF-1 multi-agent fan-out invariant)",
          "[agent_service][executions][pr2][hardening]") {
    // PR-2 ladder regression. Pre-fix, the terminal branch erased
    // cmd_execution_ids_ on the FIRST agent's response so agents 2..N
    // stamped empty execution_id and the executions drawer dropped them.
    // The fix at agent_service_impl.cpp:672-674 keeps the mapping live
    // until a future sweeper. This test drives the path the test_workflow_
    // routes pin couldn't reach (it operated on ResponseStore directly).
    GatewayResponseHarness h;
    h.svc.record_execution_id("cmd-fan", "exec-fan");

    for (const auto& agent_id : {"agent-1", "agent-2", "agent-3"}) {
        auto r = GatewayResponseHarness::make_response("cmd-fan",
                                                      apb::CommandResponse::SUCCESS);
        h.svc.process_gateway_response(agent_id, r);
    }

    auto rows = h.responses.query_by_execution("exec-fan");
    REQUIRE(rows.size() == 3);
    for (const auto& row : rows) {
        CHECK(row.execution_id == "exec-fan");
        CHECK(row.status == static_cast<int>(apb::CommandResponse::SUCCESS));
    }
}

TEST_CASE("process_gateway_response: streaming + terminal both carry execution_id",
          "[agent_service][executions][pr2]") {
    // The drawer's per-execution timeline expects both the RUNNING
    // streaming rows and the final SUCCESS row to be query_by_execution-
    // visible. Two RUNNING rows then a terminal SUCCESS = 3 rows tagged.
    GatewayResponseHarness h;
    h.svc.record_execution_id("cmd-mix", "exec-mix");

    auto r1 = GatewayResponseHarness::make_response("cmd-mix",
                                                    apb::CommandResponse::RUNNING,
                                                    /*output=*/"line-1");
    h.svc.process_gateway_response("agent-1", r1);
    auto r2 = GatewayResponseHarness::make_response("cmd-mix",
                                                    apb::CommandResponse::RUNNING,
                                                    /*output=*/"line-2");
    h.svc.process_gateway_response("agent-1", r2);
    auto r3 = GatewayResponseHarness::make_response("cmd-mix",
                                                    apb::CommandResponse::SUCCESS);
    h.svc.process_gateway_response("agent-1", r3);

    auto rows = h.responses.query_by_execution("exec-mix");
    REQUIRE(rows.size() == 3);
    int running = 0, success = 0;
    for (const auto& row : rows) {
        if (row.status == static_cast<int>(apb::CommandResponse::RUNNING)) ++running;
        if (row.status == static_cast<int>(apb::CommandResponse::SUCCESS)) ++success;
        CHECK(row.execution_id == "exec-mix");
    }
    CHECK(running == 2);
    CHECK(success == 1);
}

TEST_CASE("process_gateway_response: re-mapping a command_id updates the stamp",
          "[agent_service][executions][pr2]") {
    // Defensive contract: if the dispatch path overwrites a command_id's
    // mapping (e.g. retry under a new execution row), responses arriving
    // after the overwrite stamp the new execution_id. Old execution_id
    // sees only pre-overwrite responses.
    GatewayResponseHarness h;
    h.svc.record_execution_id("cmd-re", "exec-old");
    auto first = GatewayResponseHarness::make_response("cmd-re",
                                                       apb::CommandResponse::RUNNING,
                                                       /*output=*/"old");
    h.svc.process_gateway_response("agent-1", first);

    h.svc.record_execution_id("cmd-re", "exec-new");
    auto second = GatewayResponseHarness::make_response("cmd-re",
                                                        apb::CommandResponse::SUCCESS);
    h.svc.process_gateway_response("agent-1", second);

    auto old_rows = h.responses.query_by_execution("exec-old");
    REQUIRE(old_rows.size() == 1);
    CHECK(old_rows[0].status == static_cast<int>(apb::CommandResponse::RUNNING));

    auto new_rows = h.responses.query_by_execution("exec-new");
    REQUIRE(new_rows.size() == 1);
    CHECK(new_rows[0].status == static_cast<int>(apb::CommandResponse::SUCCESS));
}
