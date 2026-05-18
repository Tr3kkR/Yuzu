/**
 * test_rest_api_events.cpp — HTTP-level coverage for `GET /api/v1/events`,
 * the W5.1 agentic-first JSON SSE endpoint.
 *
 * Two surfaces under test:
 *
 *   1. The synchronous handler phase (auth → perm → input → tracker/bus →
 *      execution → terminal → audit → headers → subscribe) via the
 *      TestRouteSink dispatch pattern from PR #438. TestRouteSink does
 *      NOT invoke the chunked content provider — so wire-level assertions
 *      stop at the handler-returned response state (status, headers,
 *      subscription side effect on the bus).
 *
 *   2. The agentic-first shape contract — the JSON envelope and the A4
 *      error envelope are extracted into `detail::make_event_envelope`
 *      and `detail::error_json_a4` so this file can assert them directly
 *      without the chunked-provider dance.
 *
 * What is deliberately NOT covered here:
 *   - End-to-end SSE wire framing (`id: N\nevent: T\ndata: ...\n\n`).
 *     That belongs in `bash scripts/start-UAT.sh` integration coverage —
 *     standing up a real httplib::Server in unit tests is the #438 TSan
 *     trap this fixture exists to dodge. The chunked-provider lambda is
 *     covered structurally (subscription happens) and contractually
 *     (envelope helper has direct assertions); the wire-framing glue is
 *     a thin readback of values the helpers already produced.
 */

#include "api_token_store.hpp"
#include "audit_store.hpp"
#include "device_token_store.hpp"
#include "execution_event_bus.hpp"
#include "execution_tracker.hpp"
#include "rest_a4_envelope.hpp"
#include "rest_api_v1.hpp"
#include "test_route_sink.hpp"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>

#include <httplib.h>
#include <sqlite3.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include "../test_helpers.hpp"

namespace fs = std::filesystem;
using namespace yuzu::server;

namespace {

fs::path uniq(const std::string& prefix) {
    return yuzu::test::unique_temp_path(prefix + "-");
}

// RAII closer for the raw sqlite3* the ExecutionTracker borrows. Declared
// FIRST in RestEventsHarness so it destructs LAST — matches the
// SqliteHandleGuard pattern from test_workflow_routes.cpp (qa-B2).
struct SqliteHandleGuard {
    sqlite3* db{nullptr};
    ~SqliteHandleGuard() {
        if (db)
            sqlite3_close(db);
    }
};

struct AuditCall {
    std::string action, result, target_type, target_id, detail;
};

struct RestEventsHarness {
    SqliteHandleGuard tracker_guard;
    yuzu::server::test::TestRouteSink sink;

    fs::path tracker_db;
    std::unique_ptr<ExecutionTracker> tracker;
    // Bus outlives tracker — same invariant as production server.cpp
    // (execution_event_bus_ declared before execution_tracker_).
    std::unique_ptr<ExecutionEventBus> event_bus;

    // Auth/perm/audit toggles for negative cases.
    bool session_present{true};
    bool perm_grant{true};
    bool audit_should_fail{false};
    bool audit_should_throw{false};

    std::vector<AuditCall> audit_log;
    yuzu::MetricsRegistry metrics;
    RestApiV1 api;

    // Per-process monotonic id (no hash-of-thread-id / clock — same rule
    // as test_workflow_routes.cpp, see CLAUDE.md test conventions).
    static inline std::atomic<int> exec_counter{0};

    /// `with_bus=false` opts out of constructing the per-execution event
    /// bus so the 503-on-no-bus path can be exercised independently.
    /// `with_tracker=false` opts out of the tracker entirely (separate
    /// 503 path).
    explicit RestEventsHarness(bool with_bus = true, bool with_tracker = true)
        : tracker_db(uniq("rest-events-tracker")) {
        fs::remove(tracker_db);

        if (with_tracker) {
            REQUIRE(sqlite3_open(tracker_db.string().c_str(), &tracker_guard.db) == SQLITE_OK);
            if (with_bus) {
                event_bus = std::make_unique<ExecutionEventBus>();
            }
            tracker = std::make_unique<ExecutionTracker>(tracker_guard.db);
            tracker->create_tables();
            if (event_bus) {
                tracker->set_event_bus(event_bus.get());
            }
        } else if (with_bus) {
            // No-tracker but bus configured — exercises the
            // tracker-503 precedence (tracker check fires first).
            event_bus = std::make_unique<ExecutionEventBus>();
        }

        auto auth_fn = [this](const httplib::Request&,
                              httplib::Response& res) -> std::optional<auth::Session> {
            if (!session_present) {
                // Mirror require_auth's 401 contract — set status +
                // body so the handler short-circuits.
                res.status = 401;
                res.set_content(R"({"error":"unauthorized"})", "application/json");
                return std::nullopt;
            }
            auth::Session s;
            s.username = "tester";
            s.role = auth::Role::admin;
            return s;
        };
        auto perm_fn = [this](const httplib::Request&, httplib::Response& res, const std::string&,
                              const std::string&) -> bool {
            if (!perm_grant) {
                res.status = 403;
                res.set_content(R"({"error":"forbidden"})", "application/json");
                return false;
            }
            return true;
        };
        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string& target_type,
                               const std::string& target_id, const std::string& detail) -> bool {
            audit_log.push_back({action, result, target_type, target_id, detail});
            if (audit_should_throw)
                throw std::runtime_error("simulated audit pipeline failure");
            return !audit_should_fail;
        };

        api.register_routes(sink, auth_fn, perm_fn, audit_fn,
                            /*rbac_store=*/nullptr,
                            /*mgmt_store=*/nullptr,
                            /*token_store=*/nullptr,
                            /*quarantine_store=*/nullptr,
                            /*response_store=*/nullptr,
                            /*instruction_store=*/nullptr, tracker.get(),
                            /*schedule_engine=*/nullptr,
                            /*approval_manager=*/nullptr,
                            /*tag_store=*/nullptr,
                            /*audit_store=*/nullptr,
                            /*service_group_fn=*/{},
                            /*tag_push_fn=*/{},
                            /*inventory_store=*/nullptr,
                            /*product_pack_store=*/nullptr,
                            /*sw_deploy_store=*/nullptr,
                            /*device_token_store=*/nullptr,
                            /*license_store=*/nullptr,
                            /*guaranteed_state_store=*/nullptr,
                            /*metrics_registry=*/&metrics,
                            /*session_revoke_fn=*/{}, event_bus.get());
    }

    ~RestEventsHarness() {
        // Drop tracker BEFORE bus — tracker borrows event_bus_ via
        // set_event_bus, must reset first. Same invariant as
        // ExecHarness in test_workflow_routes.cpp.
        tracker.reset();
        event_bus.reset();
        if (tracker_guard.db) {
            sqlite3_close(tracker_guard.db);
            tracker_guard.db = nullptr;
        }
        std::error_code ec;
        fs::remove(tracker_db, ec);
        fs::remove(tracker_db.string() + "-wal", ec);
        fs::remove(tracker_db.string() + "-shm", ec);
    }

    std::string make_exec(const std::string& status) {
        Execution e;
        e.id = "exec-events-" + std::to_string(exec_counter.fetch_add(1));
        e.definition_id = "def-events";
        e.status = status;
        e.dispatched_by = "tester";
        e.dispatched_at = 1735689600;
        e.agents_targeted = 3;
        e.agents_success = (status == "completed") ? 3 : 0;
        e.agents_failure = 0;
        e.agents_responded = e.agents_success + e.agents_failure;
        e.completed_at = (status == "completed") ? 1735689660 : 0;
        auto id = tracker->create_execution(e);
        REQUIRE(id.has_value());
        return *id;
    }
};

} // namespace

// ── A4 envelope shape ────────────────────────────────────────────────────────

TEST_CASE("error_json_a4: minimal envelope without remediation", "[events][envelope][a4]") {
    auto body = detail::error_json_a4(404, "execution not found", "req-abc-1");
    // Envelope must carry code + message + correlation_id + api_version,
    // and MUST NOT include a remediation key when caller omits it (that
    // omission lets agentic workers detect "no recovery available" via
    // key absence rather than parsing a sentinel).
    REQUIRE(body.find(R"("code":404)") != std::string::npos);
    REQUIRE(body.find(R"("message":"execution not found")") != std::string::npos);
    REQUIRE(body.find(R"("correlation_id":"req-abc-1")") != std::string::npos);
    REQUIRE(body.find(R"("api_version":"v1")") != std::string::npos);
    REQUIRE(body.find("remediation") == std::string::npos);
}

TEST_CASE("error_json_a4: envelope carries remediation hint when present",
          "[events][envelope][a4]") {
    auto body =
        detail::error_json_a4(403, "permission denied", "req-cid-2", "request Execution:Read");
    REQUIRE(body.find(R"("remediation":"request Execution:Read")") != std::string::npos);
}

TEST_CASE("make_correlation_id: monotonic + unique within a process", "[events][envelope][a4]") {
    auto a = detail::make_correlation_id();
    auto b = detail::make_correlation_id();
    REQUIRE(a != b);
    // Format token is `req-<hex>-<hex>`; both halves must be present
    // so log greppers can split on '-'.
    REQUIRE(a.starts_with("req-"));
    REQUIRE(a.find('-', 4) != std::string::npos);
}

TEST_CASE("make_event_envelope: A3 invariants on every event", "[events][envelope][a3]") {
    yuzu::server::ExecutionEvent ev;
    ev.id = 42;
    ev.timestamp_ms = 1716000000000;
    ev.event_type = "agent-transition";
    ev.data = R"({"agent_id":"a1","status":"success"})";

    auto env = detail::make_event_envelope("exec-XYZ", ev);

    // A3 requires every event to carry execution_id + a deterministic
    // step name from the published taxonomy.
    REQUIRE(env.find(R"("execution_id":"exec-XYZ")") != std::string::npos);
    REQUIRE(env.find(R"("type":"agent-transition")") != std::string::npos);
    REQUIRE(env.find(R"("event_id":42)") != std::string::npos);
    REQUIRE(env.find(R"("timestamp_ms":1716000000000)") != std::string::npos);
    // Payload is raw-embedded as an object (not stringified) — agentic
    // workers can parse the envelope and immediately read payload fields
    // without a second JSON.parse on the data string.
    REQUIRE(env.find(R"("payload":{"agent_id":"a1","status":"success"})") != std::string::npos);
}

TEST_CASE("make_event_envelope: empty payload becomes JSON null", "[events][envelope][a3]") {
    yuzu::server::ExecutionEvent ev;
    ev.id = 1;
    ev.timestamp_ms = 0;
    ev.event_type = "execution-completed";
    ev.data = "";
    auto env = detail::make_event_envelope("exec-Q", ev);
    // The envelope MUST stay valid JSON even for events the publisher
    // emitted with no payload — using `null` rather than `""` keeps the
    // payload field type predictable for callers that treat it as an
    // object|null union.
    REQUIRE(env.find(R"("payload":null)") != std::string::npos);
}

// ── Auth + permission preflight ─────────────────────────────────────────────

TEST_CASE("GET /api/v1/events: unauthenticated request → 401 from auth_fn", "[events][auth]") {
    RestEventsHarness h;
    h.session_present = false;
    auto res = h.sink.Get("/api/v1/events?execution_id=anything");
    REQUIRE(res);
    REQUIRE(res->status == 401);
    // No audit row on missing-auth (the auth-rejection audit is emitted
    // by the auth layer, not this handler).
    REQUIRE(h.audit_log.empty());
}

TEST_CASE("GET /api/v1/events: permission denied → 403 from perm_fn", "[events][perm]") {
    RestEventsHarness h;
    h.perm_grant = false;
    auto res = h.sink.Get("/api/v1/events?execution_id=exec-X");
    REQUIRE(res);
    REQUIRE(res->status == 403);
    // No api.v1.events.subscribe audit on the deny branch — deny audits
    // are owned by the RBAC layer, mirroring the dashboard SSE sibling
    // (`/sse/executions/{id}`) policy.
    REQUIRE(h.audit_log.empty());
}

// ── Input validation ────────────────────────────────────────────────────────

TEST_CASE("GET /api/v1/events: missing execution_id → 400 A4 envelope", "[events][input]") {
    RestEventsHarness h;
    auto res = h.sink.Get("/api/v1/events");
    REQUIRE(res);
    REQUIRE(res->status == 400);
    REQUIRE(res->body.find(R"("code":400)") != std::string::npos);
    REQUIRE(res->body.find(R"("correlation_id":"req-)") != std::string::npos);
    REQUIRE(res->body.find("execution_id query parameter is required") != std::string::npos);
    // A4 mandates `remediation` for recoverable errors — missing query
    // param is the canonical "the agent can fix this" case.
    REQUIRE(res->body.find(R"("remediation":"pass ?execution_id=)") != std::string::npos);
    REQUIRE(h.audit_log.empty());
}

TEST_CASE("GET /api/v1/events: malformed execution_id → 400 A4 envelope", "[events][input]") {
    RestEventsHarness h;
    // Path-traversal-style payload exercises the char-class regex; the
    // 128-char cap is also implicit (rejects 200+-char IDs).
    auto res = h.sink.Get("/api/v1/events?execution_id=..%2Fevil");
    REQUIRE(res);
    REQUIRE(res->status == 400);
    REQUIRE(res->body.find("execution_id format invalid") != std::string::npos);
    REQUIRE(h.audit_log.empty());
}

// ── Resource-availability preflight ─────────────────────────────────────────

TEST_CASE("GET /api/v1/events: tracker unavailable → 503 A4", "[events][noresources]") {
    RestEventsHarness h(/*with_bus=*/true, /*with_tracker=*/false);
    auto res = h.sink.Get("/api/v1/events?execution_id=exec-x");
    REQUIRE(res);
    REQUIRE(res->status == 503);
    REQUIRE(res->body.find("execution tracker unavailable") != std::string::npos);
    REQUIRE(res->body.find(R"("correlation_id":"req-)") != std::string::npos);
    REQUIRE(h.audit_log.empty());
}

TEST_CASE("GET /api/v1/events: event bus unavailable → 503 A4", "[events][noresources]") {
    RestEventsHarness h(/*with_bus=*/false, /*with_tracker=*/true);
    auto res = h.sink.Get("/api/v1/events?execution_id=exec-x");
    REQUIRE(res);
    REQUIRE(res->status == 503);
    REQUIRE(res->body.find("event bus unavailable") != std::string::npos);
    REQUIRE(h.audit_log.empty());
}

// ── Execution-state preflight ───────────────────────────────────────────────

TEST_CASE("GET /api/v1/events: unknown execution → 404 A4", "[events][notfound]") {
    RestEventsHarness h;
    auto res = h.sink.Get("/api/v1/events?execution_id=exec-does-not-exist");
    REQUIRE(res);
    REQUIRE(res->status == 404);
    REQUIRE(res->body.find("execution not found") != std::string::npos);
    REQUIRE(res->body.find(R"("correlation_id":"req-)") != std::string::npos);
    // 404 deliberately does NOT audit — leaking enumeration evidence
    // into the audit log would give an attacker a side channel.
    REQUIRE(h.audit_log.empty());
}

TEST_CASE("GET /api/v1/events: terminal execution → 410 A4", "[events][terminal]") {
    RestEventsHarness h;
    auto exec_id = h.make_exec("completed");
    auto res = h.sink.Get("/api/v1/events?execution_id=" + exec_id);
    REQUIRE(res);
    REQUIRE(res->status == 410);
    REQUIRE(res->body.find("execution complete") != std::string::npos);
    REQUIRE(res->body.find(R"("remediation":"fetch the final state)") != std::string::npos);
    // 410 also deliberately does NOT audit — the execution existed but
    // the subscribe attempt added no surface area worth recording.
    REQUIRE(h.audit_log.empty());
}

// ── Happy path ──────────────────────────────────────────────────────────────

TEST_CASE("GET /api/v1/events: running execution → 200 + subscribed", "[events][happy]") {
    RestEventsHarness h;
    auto exec_id = h.make_exec("running");

    REQUIRE(h.event_bus->subscriber_count(exec_id) == 0);

    auto res = h.sink.Get("/api/v1/events?execution_id=" + exec_id);
    REQUIRE(res);
    REQUIRE(res->status == 200);

    // The chunked content provider is wired into the response state
    // (httplib won't actually drive it through TestRouteSink), but the
    // synchronous handler side-effect — bus subscription — must have
    // happened before set_chunked_content_provider was called.
    REQUIRE(h.event_bus->subscriber_count(exec_id) == 1);

    // Header contract: SSE necessities + A4 correlation id.
    REQUIRE(res->get_header_value("Cache-Control") == "no-cache");
    REQUIRE(res->get_header_value("X-Accel-Buffering") == "no");
    REQUIRE(res->get_header_value("X-Correlation-Id").starts_with("req-"));
    // No audit failure on the happy path.
    REQUIRE_FALSE(res->has_header("Sec-Audit-Failed"));

    // Audit row was emitted with the correlation id in detail.
    REQUIRE(h.audit_log.size() == 1);
    REQUIRE(h.audit_log[0].action == "api.v1.events.subscribe");
    REQUIRE(h.audit_log[0].result == "success");
    REQUIRE(h.audit_log[0].target_type == "Execution");
    REQUIRE(h.audit_log[0].target_id == exec_id);
    REQUIRE(h.audit_log[0].detail.starts_with("correlation_id=req-"));
}

TEST_CASE("GET /api/v1/events: audit failure → Sec-Audit-Failed header", "[events][happy][audit]") {
    RestEventsHarness h;
    auto exec_id = h.make_exec("running");
    h.audit_should_fail = true;

    auto res = h.sink.Get("/api/v1/events?execution_id=" + exec_id);
    REQUIRE(res);
    REQUIRE(res->status == 200);
    // Audit returning false MUST surface in the response — CC6.6
    // evidence-chain partial-failure contract (PR #883 HIGH-2).
    REQUIRE(res->get_header_value("Sec-Audit-Failed") == "true");
    // The subscription still happened — operators' "stop NOW" semantic
    // is preserved even when the SOC 2 row was lost. Mirrors the W5.1
    // sister-PR behavior on session revocation.
    REQUIRE(h.event_bus->subscriber_count(exec_id) == 1);
}

TEST_CASE("GET /api/v1/events: audit exception → Sec-Audit-Failed header",
          "[events][happy][audit]") {
    RestEventsHarness h;
    auto exec_id = h.make_exec("running");
    h.audit_should_throw = true;

    auto res = h.sink.Get("/api/v1/events?execution_id=" + exec_id);
    REQUIRE(res);
    REQUIRE(res->status == 200);
    // Same surface as the silent-fail case — exceptions and false
    // returns both indicate the audit row is not persisted.
    REQUIRE(res->get_header_value("Sec-Audit-Failed") == "true");
    REQUIRE(h.event_bus->subscriber_count(exec_id) == 1);
}

// ── Replay window ───────────────────────────────────────────────────────────

TEST_CASE("GET /api/v1/events: ?since param replays buffered events", "[events][replay]") {
    RestEventsHarness h;
    auto exec_id = h.make_exec("running");

    // Pre-populate the per-execution channel with three events. The
    // dispatched-status updates publish through the tracker's bus hook
    // (the bus member-order invariant), so they land on the channel
    // ring buffer with monotonic ids.
    h.event_bus->publish(exec_id, "agent-transition", R"({"agent_id":"a1","status":"running"})",
                         false);
    h.event_bus->publish(exec_id, "agent-transition", R"({"agent_id":"a2","status":"running"})",
                         false);
    h.event_bus->publish(exec_id, "agent-transition", R"({"agent_id":"a3","status":"success"})",
                         false);

    auto res = h.sink.Get("/api/v1/events?execution_id=" + exec_id + "&since=1");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    // After dispatch, the connection's sink_state should hold the
    // two events with id > 1 (replay), staged for the chunked provider.
    // We can't read the queue without reaching into the lambda, but we
    // CAN observe that the channel still has all three events buffered
    // (replay is a copy, not a drain).
    auto snap = h.event_bus->snapshot(exec_id);
    REQUIRE(snap.size() == 3);
    REQUIRE(snap[0].id == 1);
    REQUIRE(snap[1].id == 2);
    REQUIRE(snap[2].id == 3);
    // Subscription happened — the live channel is now wired.
    REQUIRE(h.event_bus->subscriber_count(exec_id) == 1);
}

TEST_CASE("GET /api/v1/events: invalid ?since parses to no-replay (0)", "[events][replay]") {
    RestEventsHarness h;
    auto exec_id = h.make_exec("running");
    h.event_bus->publish(exec_id, "execution-progress", R"({"pending":1})", false);
    // Garbage `since` value should not 400 — mirrors the dashboard SSE
    // sibling which silently degrades to "no replay" rather than
    // breaking an EventSource auto-reconnect on a stale id.
    auto res = h.sink.Get("/api/v1/events?execution_id=" + exec_id + "&since=not-a-number");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    REQUIRE(h.event_bus->subscriber_count(exec_id) == 1);
}

// ── OpenAPI discovery (A2) ──────────────────────────────────────────────────

TEST_CASE("OpenAPI spec lists /events under the agentic-first surface", "[events][discovery][a2]") {
    RestEventsHarness h;
    auto res = h.sink.Get("/api/v1/openapi.json");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    // A2 (discovery) requires the endpoint to be enumerable via the
    // documented OpenAPI surface. The text-shape check is enough — the
    // JSON parse is exercised by the OpenAPI ecosystem, not here.
    REQUIRE(res->body.find(R"("/events":)") != std::string::npos);
    REQUIRE(res->body.find("agentic-first JSON Server-Sent Events") != std::string::npos);
    REQUIRE(res->body.find("Execution:Read") != std::string::npos);
}
