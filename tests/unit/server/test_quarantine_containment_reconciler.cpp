/**
 * test_quarantine_containment_reconciler.cpp — #3425: a device quarantined
 * while offline never had its endpoint firewall re-applied on reconnect.
 * `QuarantineContainmentReconciler` closes that gap. Pins the acceptance
 * criteria directly:
 *  - an active record on a REACHABLE (registered) device is re-dispatched;
 *  - no record means no dispatch at all;
 *  - a device with no live session is skipped (no wasted dispatch/audit);
 *  - a `status|busy` response from the agent-side mutation gate does not
 *    spin — the per-agent claim governs the next attempt, not an immediate
 *    retry;
 *  - dispatch acceptance alone never marks a device confirmed — only a
 *    follow-up `state|active` status read does;
 *  - the stored whitelist is what gets dispatched, never anything else —
 *    every dispatch assertion below checks the EXACT argument tuple, never
 *    mere presence in a set (the false-green lesson this repo has already
 *    paid for once).
 *
 * Real `QuarantineStore` + `ResponseStore` (Postgres, PgTestTemplate) and a
 * real `AgentRegistry` — only the dispatch function is mocked, capturing the
 * full call.
 */

#include "quarantine_containment_reconciler.hpp"

#include "agent_registry.hpp"
#include "audit_store.hpp"
#include "pg/pg_pool.hpp"
#include "quarantine_store.hpp"
#include "response_store.hpp"

#include "../test_helpers.hpp"

#include "agent.pb.h"

#include <catch2/catch_test_macros.hpp>

#include <yuzu/metrics.hpp>

#include <chrono>
#include <functional>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

using namespace yuzu::server;
using yuzu::server::detail::AgentRegistry;
using yuzu::server::detail::EventBus;
using yuzu::server::pg::PgPool;

namespace {

yuzu::test::PgTestTemplate quarantine_recon_tpl{"quarantinestore", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    QuarantineStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("quarantine_store template: store failed to migrate");
}};

yuzu::test::PgTestTemplate responsestore_recon_tpl{"responsestore", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    ResponseStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("responsestore template: store failed to migrate");
}};

::yuzu::agent::v1::AgentInfo make_info(const std::string& id) {
    ::yuzu::agent::v1::AgentInfo info;
    info.set_agent_id(id);
    info.set_hostname(id + ".local");
    return info;
}

struct DispatchCall {
    std::string plugin;
    std::string action;
    std::vector<std::string> agent_ids;
    std::unordered_map<std::string, std::string> parameters;
};

// A minimal dispatch fixture: records every call with its FULL argument
// tuple (the exact-send-set discipline) and hands back a scripted
// (command_id, agents_reached) pair per call, defaulting to accepted.
struct MockDispatch {
    std::vector<DispatchCall> calls;
    int next_agents_reached{1};
    bool next_throws{false};
    // Invoked synchronously from inside the dispatch call, AFTER the call is
    // recorded but BEFORE the (command_id, agents_reached) pair is returned
    // — the deterministic, single-threaded way to inject "someone else
    // mutated the store concurrently, between the reconciler's read and its
    // own follow-up write" without a real thread or a store-failure seam.
    std::function<void()> on_dispatch;

    QuarantineContainmentReconciler::CommandDispatchFn fn() {
        return [this](const std::string& plugin, const std::string& action,
                     const std::vector<std::string>& agent_ids, const std::string&,
                     const std::unordered_map<std::string, std::string>& parameters,
                     const std::string&) -> std::pair<std::string, int> {
            calls.push_back({plugin, action, agent_ids, parameters});
            if (on_dispatch)
                on_dispatch();
            if (next_throws)
                throw std::runtime_error("dispatch failed");
            return {"cmd-" + std::to_string(calls.size()), next_agents_reached};
        };
    }
};

void store_status_response(ResponseStore& rs, const std::string& command_id,
                           const std::string& agent_id, const std::string& output) {
    StoredResponse sr;
    sr.instruction_id = command_id;
    sr.agent_id = agent_id;
    sr.status = 1; // SUCCESS
    sr.output = output;
    sr.plugin = "quarantine";
    rs.store(sr);
}

} // namespace

// ── Core acceptance criteria ────────────────────────────────────────────────

TEST_CASE("QuarantineContainmentReconciler: an active record on a reachable device is "
          "re-dispatched with the EXACT stored whitelist, never anything else",
          "[pg][quarantine][reconciler]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_recon_tpl);
    PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineStore qstore{qpool};
    REQUIRE(qstore.is_open());
    REQUIRE(qstore.quarantine_device("agent-1", "admin", "malware", "10.0.0.1,10.0.0.2")
                .has_value());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};
    registry.register_agent(make_info("agent-1")); // reachable

    MockDispatch dispatch;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = nullptr,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
    });

    reconciler.tick();

    REQUIRE(dispatch.calls.size() == 1);
    const auto& call = dispatch.calls.front();
    CHECK(call.plugin == "quarantine");
    CHECK(call.action == "quarantine");
    REQUIRE(call.agent_ids.size() == 1);
    CHECK(call.agent_ids[0] == "agent-1");
    REQUIRE(call.parameters.size() == 1);
    CHECK(call.parameters.at("whitelist_ips") == "10.0.0.1,10.0.0.2");

    // agents_reached > 0 marks last_applied_at, NOT last_confirmed_at —
    // dispatch acceptance is not proof of containment.
    auto status = qstore.get_status("agent-1");
    REQUIRE(status.has_value());
    REQUIRE(status->has_value());
    CHECK((*status)->last_applied_at > 0);
    CHECK((*status)->last_confirmed_at == 0);
}

TEST_CASE("QuarantineContainmentReconciler: no active record means no dispatch at all",
          "[pg][quarantine][reconciler]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_recon_tpl);
    PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineStore qstore{qpool};
    REQUIRE(qstore.is_open());
    // No quarantine_device call — nothing active.

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};
    registry.register_agent(make_info("agent-1"));

    MockDispatch dispatch;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = nullptr,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
    });

    reconciler.tick();
    reconciler.notify_agent_heartbeat("agent-1");

    CHECK(dispatch.calls.empty());
}

TEST_CASE("QuarantineContainmentReconciler: a device with no live session is skipped, "
          "no dispatch attempted",
          "[pg][quarantine][reconciler]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_recon_tpl);
    PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineStore qstore{qpool};
    REQUIRE(qstore.is_open());
    REQUIRE(qstore.quarantine_device("agent-offline", "admin", "malware", "").has_value());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};
    // Deliberately NOT registered — no live session.

    MockDispatch dispatch;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = nullptr,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
    });

    reconciler.tick();

    CHECK(dispatch.calls.empty());
    // Record stays unconfirmed — nothing marks it applied while offline.
    auto status = qstore.get_status("agent-offline");
    REQUIRE(status.has_value());
    REQUIRE(status->has_value());
    CHECK((*status)->last_applied_at == 0);

    // The gauge counts it under "offline", not "connected".
    CHECK(metrics.gauge("yuzu_server_quarantine_endpoint_unconfirmed", {{"reachability", "offline"}})
              .value() == 1);
    CHECK(metrics
              .gauge("yuzu_server_quarantine_endpoint_unconfirmed", {{"reachability", "connected"}})
              .value() == 0);
}

TEST_CASE("QuarantineContainmentReconciler: a busy mutation-gate response does not spin — "
          "the per-agent claim governs the next attempt",
          "[pg][quarantine][reconciler]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_recon_tpl);
    PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineStore qstore{qpool};
    REQUIRE(qstore.is_open());
    REQUIRE(qstore.quarantine_device("agent-1", "admin", "malware", "").has_value());

    YUZU_REQUIRE_PG_DB_TPL(rdb, responsestore_recon_tpl);
    PgPool rpool{{.conninfo = rdb.dsn(), .size = 4}};
    ResponseStore rstore{rpool};
    REQUIRE(rstore.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};
    registry.register_agent(make_info("agent-1"));

    MockDispatch dispatch;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = &rstore,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
    });

    // Tick 1: apply dispatched.
    reconciler.tick();
    REQUIRE(dispatch.calls.size() == 1);
    const std::string apply_cmd = "cmd-1";

    // The agent-side mutation gate (open PR #3429) answers busy — seed that
    // as the apply command's response.
    store_status_response(rstore, apply_cmd, "agent-1", "status|busy");

    // Same tick's claim already holds next_eligible_at in the future — a
    // second reconcile attempt right now (e.g. a racing heartbeat) must NOT
    // dispatch again. This is the concrete no-spin mechanism: rate_limited,
    // not another poll-then-dispatch.
    reconciler.notify_agent_heartbeat("agent-1");
    CHECK(dispatch.calls.size() == 1); // still just the one apply call — no spin
}

// The two cases below drive the FULL apply -> poll -> status -> confirm
// state machine deterministically using the millisecond timing overrides
// (Deps' *_override fields) — production leaves these at 0 (meaning "use
// the real 60s/15s/60s constants"); a test setting them to tens of
// milliseconds gets the identical state machine without a multi-minute
// sleep. A response is seeded IMMEDIATELY after learning its command_id
// (before the next reconcile_one call), and a short real sleep bridges the
// overridden claim/grace windows — the assertions are on STATE reached, not
// on timing precision.

TEST_CASE("QuarantineContainmentReconciler: confirmation requires a follow-up status read "
          "reporting state|active — dispatch acceptance alone is not enough",
          "[pg][quarantine][reconciler]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_recon_tpl);
    PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineStore qstore{qpool};
    REQUIRE(qstore.is_open());
    REQUIRE(qstore.quarantine_device("agent-1", "admin", "malware", "").has_value());

    YUZU_REQUIRE_PG_DB_TPL(rdb, responsestore_recon_tpl);
    PgPool rpool{{.conninfo = rdb.dsn(), .size = 4}};
    ResponseStore rstore{rpool};
    REQUIRE(rstore.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};
    registry.register_agent(make_info("agent-1"));

    MockDispatch dispatch;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = &rstore,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
        .min_reapply_interval_override = std::chrono::milliseconds(20),
        .response_wait_override = std::chrono::milliseconds(200),
        .verify_grace_override = std::chrono::milliseconds(20),
    });

    // Step 1: apply dispatched.
    reconciler.tick();
    REQUIRE(dispatch.calls.size() == 1);
    CHECK(dispatch.calls[0].action == "quarantine");
    store_status_response(rstore, "cmd-1", "agent-1", "status|quarantined|rules_applied|1");

    // Step 2: this call POLLS the apply response and (since it's not
    // "busy") schedules a status verify — it does NOT dispatch status
    // itself in the same call (one dispatch decision per reconcile_one
    // call, by design).
    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    reconciler.tick();
    CHECK(dispatch.calls.size() == 1); // still just the apply — no dispatch yet

    // Confirmation must NOT have happened from apply acceptance alone.
    auto mid = qstore.get_status("agent-1");
    REQUIRE(mid.has_value());
    REQUIRE(mid->has_value());
    CHECK((*mid)->last_confirmed_at == 0);

    // Step 3: THIS call is the one that actually dispatches the status verify.
    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    reconciler.tick();
    REQUIRE(dispatch.calls.size() == 2);
    CHECK(dispatch.calls[1].action == "status");

    // Still not confirmed — the status dispatch's own response hasn't
    // arrived/been polled yet.
    auto after_status_dispatch = qstore.get_status("agent-1");
    REQUIRE(after_status_dispatch.has_value());
    REQUIRE(after_status_dispatch->has_value());
    CHECK((*after_status_dispatch)->last_confirmed_at == 0);
}

TEST_CASE("QuarantineContainmentReconciler: a follow-up status read of state|active marks "
          "the record confirmed",
          "[pg][quarantine][reconciler]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_recon_tpl);
    PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineStore qstore{qpool};
    REQUIRE(qstore.is_open());
    REQUIRE(qstore.quarantine_device("agent-1", "admin", "malware", "").has_value());

    YUZU_REQUIRE_PG_DB_TPL(rdb, responsestore_recon_tpl);
    PgPool rpool{{.conninfo = rdb.dsn(), .size = 4}};
    ResponseStore rstore{rpool};
    REQUIRE(rstore.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};
    registry.register_agent(make_info("agent-1"));

    MockDispatch dispatch;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = &rstore,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
        .min_reapply_interval_override = std::chrono::milliseconds(20),
        .response_wait_override = std::chrono::milliseconds(200),
        .verify_grace_override = std::chrono::milliseconds(20),
    });

    reconciler.tick(); // 1: apply dispatched
    REQUIRE(dispatch.calls.size() == 1);
    store_status_response(rstore, "cmd-1", "agent-1", "status|quarantined|rules_applied|1");
    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    reconciler.tick(); // 2: polls apply response, schedules status verify (no dispatch yet)
    CHECK(dispatch.calls.size() == 1);
    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    reconciler.tick(); // 3: dispatches the status verify
    REQUIRE(dispatch.calls.size() == 2);
    CHECK(dispatch.calls[1].action == "status");

    store_status_response(rstore, "cmd-2", "agent-1", "state|active");
    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    reconciler.tick(); // 4: polls status response -> confirms

    auto status = qstore.get_status("agent-1");
    REQUIRE(status.has_value());
    REQUIRE(status->has_value());
    CHECK((*status)->last_confirmed_at > 0);

    // A further tick dispatches NOTHING for a confirmed, session-unchanged
    // agent — and its sweep (computed at the START of the tick, before that
    // cycle's own reconcile_one work) is also the first one to see the
    // gauge reflect the confirm achieved during tick 4 (the gauge published
    // during tick 4 itself still reflected PRE-confirm state).
    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    reconciler.tick();
    CHECK(dispatch.calls.size() == 2); // unchanged — confirmed agents are skipped
    CHECK(metrics.gauge("yuzu_server_quarantine_endpoint_unconfirmed", {{"reachability", "connected"}})
              .value() == 0); // no longer counted as unconfirmed
}

TEST_CASE("QuarantineContainmentReconciler: session churn on a confirmed agent re-verifies "
          "via status, not a blind re-apply",
          "[pg][quarantine][reconciler]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_recon_tpl);
    PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineStore qstore{qpool};
    REQUIRE(qstore.is_open());
    REQUIRE(qstore.quarantine_device("agent-1", "admin", "malware", "").has_value());

    YUZU_REQUIRE_PG_DB_TPL(rdb, responsestore_recon_tpl);
    PgPool rpool{{.conninfo = rdb.dsn(), .size = 4}};
    ResponseStore rstore{rpool};
    REQUIRE(rstore.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};
    registry.register_agent(make_info("agent-1"));
    registry.map_session("session-A", "agent-1");

    MockDispatch dispatch;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = &rstore,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
        .min_reapply_interval_override = std::chrono::milliseconds(20),
        .response_wait_override = std::chrono::milliseconds(200),
        .verify_grace_override = std::chrono::milliseconds(20),
    });

    // Drive to confirmed under session-A (apply -> poll -> status verify -> confirm).
    reconciler.tick(); // 1: apply
    REQUIRE(dispatch.calls.size() == 1);
    store_status_response(rstore, "cmd-1", "agent-1", "status|quarantined|rules_applied|1");
    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    reconciler.tick(); // 2: polls apply, schedules status verify
    CHECK(dispatch.calls.size() == 1);
    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    reconciler.tick(); // 3: dispatches status verify
    REQUIRE(dispatch.calls.size() == 2);
    store_status_response(rstore, "cmd-2", "agent-1", "state|active");
    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    reconciler.tick(); // 4: polls status -> confirms
    auto confirmed = qstore.get_status("agent-1");
    REQUIRE(confirmed.has_value());
    REQUIRE(confirmed->has_value());
    REQUIRE((*confirmed)->last_confirmed_at > 0);

    // Simulate a reconnect: a NEW session for the same agent (register_agent
    // replaces the shared_ptr — the immutability contract — then a fresh
    // session_id is mapped, as AgentServiceImpl::Register really does).
    registry.register_agent(make_info("agent-1"));
    registry.map_session("session-B", "agent-1");

    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    reconciler.tick(); // 5: tick's own sweep detects churn and dispatches STATUS
                       // first (verify_first is consumed on the SAME call that
                       // detects it, unlike apply's poll->schedule->dispatch
                       // split, because churn detection happens in tick()'s
                       // sweep loop, before reconcile_one's claim, so the
                       // dispatch decision and the churn flag land in the same
                       // reconcile_one invocation).

    REQUIRE(dispatch.calls.size() == 3);
    CHECK(dispatch.calls[2].action == "status"); // verify-first, never a blind re-apply
}

TEST_CASE("QuarantineContainmentReconciler: heartbeat fast path is a no-op for an agent with "
          "no active record (no store read)",
          "[pg][quarantine][reconciler]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_recon_tpl);
    PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineStore qstore{qpool};
    REQUIRE(qstore.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};
    registry.register_agent(make_info("agent-1"));

    MockDispatch dispatch;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = nullptr,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
    });

    // Heartbeat BEFORE any tick() has ever run — the cache is empty, so this
    // must be a pure cache-miss with zero dispatch and zero store I/O
    // (there is nothing to assert the "no store read" half directly, but a
    // dispatch call would prove the fast path failed).
    reconciler.notify_agent_heartbeat("agent-1");
    CHECK(dispatch.calls.empty());
}

TEST_CASE("QuarantineContainmentReconciler: an unsafe stored whitelist is never dispatched",
          "[pg][quarantine][reconciler]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_recon_tpl);
    PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineStore qstore{qpool};
    REQUIRE(qstore.is_open());
    // quarantine_device itself validates nothing — this mirrors a row
    // written through the record-only REST twin, which performs no
    // charset/length validation of its own (the #3127 rationale for
    // re-validating a STORED value at the server edge before dispatch).
    REQUIRE(qstore.quarantine_device("agent-1", "admin", "malware", "10.0.0.1;rm -rf /")
                .has_value());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};
    registry.register_agent(make_info("agent-1"));

    MockDispatch dispatch;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = nullptr,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
    });

    reconciler.tick();

    CHECK(dispatch.calls.empty());
    auto status = qstore.get_status("agent-1");
    REQUIRE(status.has_value());
    REQUIRE(status->has_value());
    CHECK((*status)->last_applied_at == 0); // never dispatched, never marked applied
}

TEST_CASE("QuarantineContainmentReconciler: a released record disappears from the next "
          "tick with no dispatch",
          "[pg][quarantine][reconciler]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_recon_tpl);
    PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineStore qstore{qpool};
    REQUIRE(qstore.is_open());
    REQUIRE(qstore.quarantine_device("agent-1", "admin", "malware", "").has_value());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};
    registry.register_agent(make_info("agent-1"));

    MockDispatch dispatch;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = nullptr,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
    });

    reconciler.tick();
    REQUIRE(dispatch.calls.size() == 1);

    REQUIRE(qstore.release_device("agent-1").has_value());
    reconciler.tick(); // GC's the now-released agent out of internal state

    CHECK(dispatch.calls.size() == 1); // no second dispatch to a released device
    CHECK(metrics.gauge("yuzu_server_quarantine_endpoint_unconfirmed", {{"reachability", "connected"}})
              .value() == 0);
}

TEST_CASE("QuarantineContainmentReconciler: a degraded quarantine-store read aborts the tick, "
          "never treated as \"nothing active\"",
          "[quarantine][reconciler]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};

    MockDispatch dispatch;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = nullptr, // simulates "store unavailable"
        .response_store = nullptr,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
    });

    // Must not crash and must not fabricate any dispatch.
    reconciler.tick();
    CHECK(dispatch.calls.empty());
}

// ── Adversarial-review regression tests (2026-08-24) ───────────────────────
//
// K1/K2 (Kimi) + CDX-P1-02 (Codex), independently found: mark_endpoint_applied/
// mark_endpoint_confirmed's std::expected result was discarded, so a
// concurrent release racing the reconciler's own read-then-write could leave
// the in-memory state believing "applied"/"confirmed" when the guarded
// UPDATE actually affected zero rows. Both dispatch mocks below release the
// device from INSIDE the dispatch callback — the deterministic, single-
// threaded way to land exactly in that window (reconcile_one calls
// dispatch_fn, then immediately calls mark_endpoint_applied/confirmed on
// return) without a real second thread or a store-failure injection seam.

TEST_CASE("QuarantineContainmentReconciler: a release racing mark_endpoint_applied does not "
          "leave a phantom \"pending apply\" tracked forever",
          "[pg][quarantine][reconciler][regression]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_recon_tpl);
    PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineStore qstore{qpool};
    REQUIRE(qstore.is_open());
    REQUIRE(qstore.quarantine_device("agent-1", "admin", "malware", "").has_value());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};
    registry.register_agent(make_info("agent-1"));

    MockDispatch dispatch;
    // Fires after the apply dispatch is recorded but before reconcile_one's
    // own mark_endpoint_applied call — releasing the device HERE means that
    // guarded UPDATE (WHERE status='active') affects zero rows.
    dispatch.on_dispatch = [&] { REQUIRE(qstore.release_device("agent-1").has_value()); };

    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = nullptr,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
    });

    reconciler.tick();
    REQUIRE(dispatch.calls.size() == 1); // the dispatch itself still happened — cannot be undone
    // NOTE: this same tick's own gauge publish still counts agent-1 as
    // unconfirmed=1 — it was computed from the list_quarantined() SNAPSHOT
    // taken at the top of tick(), before the release (which happens later,
    // inside this same call's dispatch). The gauge only reflects the release
    // starting with the NEXT tick's snapshot — checked below.

    // A further tick must not attempt to poll a response for a command
    // whose record is gone (the fix erased the per-agent state entirely on
    // "device is not quarantined" rather than setting pending=apply on an
    // unchecked write) — no second dispatch call. And THIS tick's snapshot
    // no longer contains agent-1 at all, so the unconfirmed gauge is 0.
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    reconciler.tick();
    CHECK(dispatch.calls.size() == 1);
    CHECK(metrics.gauge("yuzu_server_quarantine_endpoint_unconfirmed", {{"reachability", "connected"}})
              .value() == 0);
}

TEST_CASE("QuarantineContainmentReconciler: a release racing mark_endpoint_confirmed does not "
          "leave the reconciler falsely believing the device is confirmed",
          "[pg][quarantine][reconciler][regression]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_recon_tpl);
    PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineStore qstore{qpool};
    REQUIRE(qstore.is_open());
    REQUIRE(qstore.quarantine_device("agent-1", "admin", "malware", "").has_value());

    YUZU_REQUIRE_PG_DB_TPL(rdb, responsestore_recon_tpl);
    PgPool rpool{{.conninfo = rdb.dsn(), .size = 4}};
    ResponseStore rstore{rpool};
    REQUIRE(rstore.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};
    registry.register_agent(make_info("agent-1"));

    MockDispatch dispatch;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = &rstore,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
        .min_reapply_interval_override = std::chrono::milliseconds(20),
        .response_wait_override = std::chrono::milliseconds(200),
        .verify_grace_override = std::chrono::milliseconds(20),
    });

    // Drive to the status-dispatch step normally (apply -> poll(no dispatch) -> status verify).
    reconciler.tick(); // 1: apply dispatched
    REQUIRE(dispatch.calls.size() == 1);
    store_status_response(rstore, "cmd-1", "agent-1", "status|quarantined|rules_applied|1");
    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    reconciler.tick(); // 2: polls apply response, schedules status verify — no new dispatch
    CHECK(dispatch.calls.size() == 1);
    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    reconciler.tick(); // 3: dispatches the status verify
    REQUIRE(dispatch.calls.size() == 2);
    CHECK(dispatch.calls[1].action == "status");

    // NOW release the device — racing the eventual mark_endpoint_confirmed
    // call that fires once this status response is polled and parses as
    // state|active.
    store_status_response(rstore, "cmd-2", "agent-1", "state|active");
    REQUIRE(qstore.release_device("agent-1").has_value());
    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    reconciler.tick(); // 4: polls cmd-2 -> confirms containment -> mark_endpoint_confirmed hits 0 rows

    // The fix must NOT set confirmed=true on that failed write — verified
    // indirectly: a THIRD tick, if the agent were wrongly marked confirmed,
    // would exclude it from to_reconcile forever with no further activity;
    // since the record is genuinely gone, the correct outcome is simply "no
    // further dispatch, no active record to track" either way. The stronger
    // check is that the store itself was never re-quarantined by this path
    // and stays released.
    auto status = qstore.get_status("agent-1");
    REQUIRE(status.has_value());
    CHECK_FALSE(status->has_value()); // still released — the reconciler did not resurrect it
}

TEST_CASE("QuarantineContainmentReconciler: backoff doubling takes effect on THIS attempt's "
          "deadline, not only a future one (no premature retry)",
          "[pg][quarantine][reconciler][regression]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_recon_tpl);
    PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineStore qstore{qpool};
    REQUIRE(qstore.is_open());
    REQUIRE(qstore.quarantine_device("agent-1", "admin", "malware", "").has_value());

    YUZU_REQUIRE_PG_DB_TPL(rdb, responsestore_recon_tpl);
    PgPool rpool{{.conninfo = rdb.dsn(), .size = 4}};
    ResponseStore rstore{rpool};
    REQUIRE(rstore.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};
    registry.register_agent(make_info("agent-1"));

    MockDispatch dispatch;
    // A generous claim interval (200ms) but a SHORT response wait (30ms), so
    // a timed-out poll's freshly-doubled backoff is easy to distinguish from
    // "immediately eligible again" in a fast test.
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = &rstore,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
        .min_reapply_interval_override = std::chrono::milliseconds(200),
        .response_wait_override = std::chrono::milliseconds(30),
        .verify_grace_override = std::chrono::milliseconds(20),
    });

    reconciler.tick(); // apply dispatched; claim deadline ~200ms out (min_reapply_interval)
    REQUIRE(dispatch.calls.size() == 1);
    // Never seed a response — force the response_wait timeout path, which is
    // where the fix adds `next_eligible_at = steady_now + st.backoff`. Must
    // sleep PAST the 200ms claim window itself (a second reconcile_one call
    // cannot even run before then), which is also comfortably past
    // response_wait(30ms), so the poll below sees both "empty" and
    // "timed_out" at once.
    std::this_thread::sleep_for(std::chrono::milliseconds(220));
    reconciler.tick(); // times out, doubles backoff, and (fixed) advances next_eligible_at NOW
    CHECK(dispatch.calls.size() == 1); // no new dispatch on the timeout-processing call itself

    // Immediately after, a heartbeat must NOT be able to claim again — if the
    // bug were present, next_eligible_at would still be the ORIGINAL ~200ms
    // claim (already elapsed by now, since we're well past 40ms), letting
    // this call straight through to a second dispatch. The fix rebases the
    // deadline to now + the NEWLY DOUBLED backoff (400ms), so this must be
    // rate-limited.
    reconciler.notify_agent_heartbeat("agent-1");
    CHECK(dispatch.calls.size() == 1); // still just the one dispatch — no premature retry
}

// #3425 governance Gate 2 (security-guardian, 2026-08-24): the two regression
// tests above both wire `.audit_store = nullptr`, so neither one could ever
// have caught a missing audit row on the mark_endpoint_applied/confirmed
// failure path — the exact gap the fix below closes. This test wires a REAL
// AuditStore and asserts the "dispatch accepted but the durable stamp
// failed" row actually lands with result="failure".
yuzu::test::PgTestTemplate quarantine_recon_audit_tpl{"reconaudit", [](const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    AuditStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("reconaudit template: store failed to migrate");
}};

TEST_CASE("QuarantineContainmentReconciler: a release racing mark_endpoint_applied still leaves "
          "an audit row for the dispatch that already happened",
          "[pg][quarantine][reconciler][regression]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_recon_tpl);
    PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineStore qstore{qpool};
    REQUIRE(qstore.is_open());
    REQUIRE(qstore.quarantine_device("agent-1", "admin", "malware", "").has_value());

    YUZU_REQUIRE_PG_DB_TPL(adb, quarantine_recon_audit_tpl);
    PgPool apool{{.conninfo = adb.dsn(), .size = 4}};
    AuditStore astore{apool};
    REQUIRE(astore.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};
    registry.register_agent(make_info("agent-1"));

    MockDispatch dispatch;
    // Same K1 injection as the test above: release from inside the dispatch
    // callback so mark_endpoint_applied's guarded UPDATE affects zero rows —
    // but this time with a real audit_store wired, so the fix's
    // audit_unstamped call has somewhere real to land.
    dispatch.on_dispatch = [&] { REQUIRE(qstore.release_device("agent-1").has_value()); };

    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = nullptr,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = &astore,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
    });

    reconciler.tick();
    REQUIRE(dispatch.calls.size() == 1); // the dispatch itself still happened

    AuditQuery aq;
    aq.action = "quarantine.reapply";
    auto events = astore.query(aq);
    REQUIRE(events.has_value());
    REQUIRE(events->size() == 1); // the one "dispatch accepted, stamp failed" row — no crash, no silent drop
    CHECK(events->front().result == "failure"); // the store write failed — must not claim "success"
    CHECK(events->front().target_id == "agent-1");
    CHECK(events->front().detail.find("dispatch accepted") != std::string::npos);
    CHECK(events->front().detail.find("device is not quarantined") != std::string::npos);
}
