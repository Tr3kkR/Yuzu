/**
 * test_policy_evaluator.cpp — Unit tests for the compliance check -> verdict
 * pipeline (PolicyEvaluator).
 *
 * Strategy: real PolicyStore (Postgres, ADR-0056) / InstructionStore (Postgres,
 * ADR-0058) / ResponseStore (Postgres, ADR-0039) / ManagementGroupStore
 * (Postgres, ADR-0042) on a shared pool + per-test temp files, target
 * resolution via a static management group (so no AgentRegistry is needed),
 * a FAKE dispatch_fn that synchronously seeds canned ResponseStore rows
 * under the execution_id it is handed (keyed by agent + plugin), and an
 * injectable clock to drive the grace window deterministically.
 *
 * The final TEST_CASE is the regression test for ADR-0056's headline design:
 * two PolicyEvaluator instances sharing one PolicyStore assert exactly one
 * dispatch per policy per interval (the durable claim_due_policies lease),
 * and that only the dispatching instance ever collects its own in-flight
 * check (the other instance's tick claims nothing for it, by design — see
 * policy_store.hpp's header comment on why collect stays per-replica).
 */

#include "instruction_store.hpp"
#include "management_group_store.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "test_mgmt_group_pg_helper.hpp"
#include "policy_evaluator.hpp"
#include "policy_store.hpp"
#include "response_store.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <libpq-fe.h>

#include <map>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace yuzu::server;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;

namespace {

// ResponseStore is a migrated Postgres store (ADR-0039) — shares the
// "responsestore" template key with test_response_store.cpp (identical
// setup). PolicyStore (ADR-0056) is constructed against the SAME pool/DB
// (a different schema namespace, `policy_store` vs `response_store` —
// exactly how they coexist in production's one shared pg_pool_); it is not
// part of this template's pre-baked setup, so each fresh clone pays its own
// migration on first construction — a fine trade-off here (this file is not
// benchmarking migration cost), and avoids adding PolicyStore's migration
// cost to every OTHER test file that shares the "responsestore" key.
yuzu::test::PgTestTemplate responsestore_tpl{"responsestore", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    ResponseStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("responsestore template: store failed to migrate");
}};

// A result envelope parse_result understands: columns + rows arrays.
std::string out_json(const std::string& col, const std::string& val) {
    return R"({"columns":[{"name":")" + col + R"(","type":"string"}],"rows":[{")" + col +
           R"(":")" + val + R"("}]})";
}

// Two-column variant for expressions that reference two fields.
std::string out_json2(const std::string& c1, const std::string& v1, const std::string& c2,
                      const std::string& v2) {
    return R"({"columns":[{"name":")" + c1 + R"(","type":"string"},{"name":")" + c2 +
           R"(","type":"string"}],"rows":[{")" + c1 + R"(":")" + v1 + R"(",")" + c2 + R"(":")" +
           v2 + R"("}]})";
}

struct Harness {
    // PolicyStore (ADR-0056) and InstructionStore (ADR-0058) are both migrated
    // Postgres stores now — share the same pool/database as ResponseStore
    // below (schema-per-store, ADR-0008).
    PolicyStore ps;
    InstructionStore is;
    ResponseStore rs;
    yuzu::test::ManagementGroupStorePg mg_bundle;
    ManagementGroupStore& mg = *mg_bundle;

    int64_t fake_now{1000};
    int dispatch_calls{0};
    std::vector<std::string> dispatched_plugins;
    // canned[agent + "|" + plugin] -> (status, output)
    std::map<std::string, std::pair<int, std::string>> canned;

    std::string group_id;

    explicit Harness(pg::PgPool& pool) : ps(pool), is(pool), rs(pool) {
        auto def = [&](const std::string& id, const std::string& plugin) {
            InstructionDefinition d;
            d.id = id;
            d.name = id;
            d.version = "1.0.0";
            d.type = "question";
            d.plugin = plugin;
            d.action = "run";
            d.enabled = true;
            REQUIRE(is.create_definition(d).has_value());
        };
        def("test.check", "checkp");
        def("test.fix", "fixp");
        def("test.verify", "verifyp");

        ManagementGroup g;
        g.name = "grp";
        g.membership_type = "static";
        auto gid = mg.create_group(g);
        REQUIRE(gid.has_value());
        group_id = *gid;
        REQUIRE(mg.add_member(group_id, "agentA").has_value());
        REQUIRE(mg.add_member(group_id, "agentB").has_value());
    }

    PolicyEvaluator::Deps deps() {
        PolicyEvaluator::Deps d;
        d.policy_store = &ps;
        d.instruction_store = &is;
        d.response_store = &rs;
        d.registry = nullptr;
        d.tag_store = nullptr;
        d.custom_properties_store = nullptr;
        d.mgmt_group_store = &mg;
        d.grace_seconds = 15;
        d.default_interval_seconds = 3600;
        d.fixing_stale_seconds = 1800;
        d.now_fn = [this] { return fake_now; };
        d.dispatch_fn = [this](const std::string& plugin, const std::string&,
                               const std::vector<std::string>& agents, const std::string&,
                               const std::unordered_map<std::string, std::string>&,
                               const std::string& execid) -> std::pair<std::string, int> {
            ++dispatch_calls;
            dispatched_plugins.push_back(plugin);
            int sent = 0;
            for (const auto& a : agents) {
                auto it = canned.find(a + "|" + plugin);
                if (it == canned.end())
                    continue; // non-responder
                StoredResponse r;
                r.instruction_id = "test";
                r.agent_id = a;
                r.status = it->second.first;
                r.output = it->second.second;
                r.plugin = plugin;
                r.execution_id = execid;
                r.timestamp = fake_now;
                rs.store(r);
                ++sent;
            }
            return {"cmd-" + execid, sent};
        };
        return d;
    }

    // Author a fragment + policy bound to the static group. Returns policy id.
    std::string author(const std::string& check_cel, bool with_fix = false,
                       int64_t interval_seconds = 0) {
        std::string frag = std::string("apiVersion: yuzu.io/v1alpha1\nkind: PolicyFragment\n") +
                           "spec:\n  check:\n    instruction: test.check\n    compliance: \"" +
                           check_cel + "\"\n";
        if (with_fix) {
            frag += "  fix:\n    instruction: test.fix\n";
            frag += "  postCheck:\n    instruction: test.verify\n    compliance: \"result.fixed "
                    "== 'yes'\"\n";
        }
        auto fid = ps.create_fragment(frag);
        REQUIRE(fid.has_value());

        std::string pol = std::string("apiVersion: yuzu.io/v1alpha1\nkind: Policy\n") + "spec:\n  fragment: " +
                          *fid + "\n  managementGroups:\n    - " + group_id + "\n";
        if (interval_seconds > 0) {
            pol += "  triggers:\n    - type: interval\n      interval_seconds: " +
                   std::to_string(interval_seconds) + "\n";
        }
        auto pid = ps.create_policy(pol);
        REQUIRE(pid.has_value());
        return *pid;
    }

    std::string status_of(const std::string& pid, const std::string& agent) {
        auto s = ps.get_agent_status(pid, agent);
        if (!s || !*s)
            return "<none>";
        return (*s)->status;
    }
};

} // namespace

TEST_CASE("policy evaluator: compliant + non_compliant verdicts (multi-agent fan-out)",
          "[pg][policy][evaluator]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    Harness h(pool);
    h.canned["agentA|checkp"] = {1, out_json("hostname", "yuzu-a")};
    h.canned["agentB|checkp"] = {1, out_json("hostname", "")};
    auto pid = h.author("result.hostname != ''");

    PolicyEvaluator ev(h.deps());
    REQUIRE_FALSE(ev.evaluate_now(pid).value_or("").empty());
    h.fake_now += 20; // past grace
    ev.tick();

    CHECK(h.status_of(pid, "agentA") == "compliant");
    CHECK(h.status_of(pid, "agentB") == "non_compliant");
}

TEST_CASE("policy evaluator: evaluate_now does not dispatch when record_dispatch fails "
          "(adversarial review, round 2)",
          "[pg][policy][evaluator]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    Harness h(pool);
    auto pid = h.author("result.hostname != ''");

    // Drop the durable claim table out from under the live store — a
    // reproducible stand-in for a transient connection loss / botched
    // migration. record_dispatch() (called first inside evaluate_now())
    // must now fail, and evaluate_now() must NOT proceed to dispatch: a
    // dispatch that runs without a durable stamp is exactly the "next
    // automatic tick sees no row and re-claims immediately" bug this
    // store's dispatch-claim design exists to prevent.
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult r{PQexec(conn.get(), "DROP TABLE policy_store.policy_dispatch_state CASCADE")};
        REQUIRE(r.ok());
    }

    PolicyEvaluator ev(h.deps());
    auto result = ev.evaluate_now(pid);
    CHECK_FALSE(result.has_value()); // degraded, never a silent "no targets" empty string
    CHECK(h.dispatch_calls == 0);
}

TEST_CASE("policy evaluator: evaluate_now degrades (not a silent no-op) when the fragment "
          "table is unavailable (governance, 2026-08-24)",
          "[pg][policy][evaluator]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    Harness h(pool);
    auto pid = h.author("result.hostname != ''");

    // record_dispatch() (the durable claim stamp) touches only
    // policy_dispatch_state and must still succeed here — this test targets
    // kickoff_check()'s OWN get_fragment() read, which used to collapse a
    // degraded read into the same "" a genuine "no check instruction /
    // matches no agents" no-op returns, so a false REST 409 masked what was
    // actually a 503.
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult r{PQexec(conn.get(), "DROP TABLE policy_store.policy_fragments CASCADE")};
        REQUIRE(r.ok());
    }

    PolicyEvaluator ev(h.deps());
    auto result = ev.evaluate_now(pid);
    CHECK_FALSE(result.has_value());
    CHECK(h.dispatch_calls == 0);
}

TEST_CASE("policy evaluator: non-responder -> unknown, plugin failure -> error",
          "[pg][policy][evaluator]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    Harness h(pool);
    h.canned["agentA|checkp"] = {2, ""}; // FAILURE status -> error
    // agentB intentionally absent -> non-responder -> unknown
    auto pid = h.author("result.hostname != ''");

    PolicyEvaluator ev(h.deps());
    REQUIRE_FALSE(ev.evaluate_now(pid).value_or("").empty());
    h.fake_now += 20;
    ev.tick();

    CHECK(h.status_of(pid, "agentA") == "error");
    CHECK(h.status_of(pid, "agentB") == "unknown");
}

TEST_CASE("policy evaluator: InstructionStore DB error on dispatch is distinct from unknown "
          "instruction (ADR-0058: must not collapse a genuine failure into the same skip)",
          "[pg][policy][evaluator]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    Harness h(pool);
    auto pid = h.author("result.hostname != ''");

    // A second InstructionStore backed by an unreachable pool simulates a genuine DB failure —
    // swapped in for this test only, in place of the harness's normally-open store.
    PgPool broken_pool{{.conninfo = "=quohth4eeQu5 garbage =", .size = 1}};
    REQUIRE_FALSE(broken_pool.valid());
    InstructionStore broken_is{broken_pool};
    REQUIRE_FALSE(broken_is.is_open());

    auto deps = h.deps();
    deps.instruction_store = &broken_is;
    PolicyEvaluator ev(deps);

    auto result = ev.evaluate_now(pid);
    CHECK_FALSE(result.has_value()); // degraded, never a silent "no targets" empty string
    CHECK(h.dispatch_calls == 0); // never reached dispatch_fn — failed resolving the definition
}

TEST_CASE("policy evaluator: missing CEL field resolves empty -> non_compliant",
          "[pg][policy][evaluator]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    Harness h(pool);
    // Success status, but the result has no 'hostname' column the CEL references.
    // CEL resolves a missing result field to "" (not an error), so
    // `result.hostname != ''` is `'' != ''` -> false -> non_compliant. Missing
    // data is treated as non-compliant, NOT as an evaluation error.
    h.canned["agentA|checkp"] = {1, out_json("other", "x")};
    auto pid = h.author("result.hostname != ''");

    PolicyEvaluator ev(h.deps());
    REQUIRE_FALSE(ev.evaluate_now(pid).value_or("").empty());
    h.fake_now += 20;
    ev.tick();

    CHECK(h.status_of(pid, "agentA") == "non_compliant");
}

TEST_CASE("policy evaluator: CEL evaluation error -> error", "[pg][policy][evaluator]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    Harness h(pool);
    // Division by zero yields a top-level CEL evaluation error (monostate ->
    // eval_error), which the evaluator must surface as status "error", distinct
    // from a non-compliant verdict. (A comparison like `... > 1` would coerce
    // the monostate to the string "null" and mask the error, so the bare
    // arithmetic expression is the deterministic eval_error trigger.)
    h.canned["agentA|checkp"] = {1, out_json2("num", "10", "den", "0")};
    auto pid = h.author("result.num / result.den");

    PolicyEvaluator ev(h.deps());
    REQUIRE_FALSE(ev.evaluate_now(pid).value_or("").empty());
    h.fake_now += 20;
    ev.tick();

    CHECK(h.status_of(pid, "agentA") == "error");
}

TEST_CASE("policy evaluator: interval throttles re-dispatch", "[pg][policy][evaluator]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    Harness h(pool);
    h.canned["agentA|checkp"] = {1, out_json("hostname", "a")};
    h.canned["agentB|checkp"] = {1, out_json("hostname", "b")};
    auto pid = h.author("result.hostname != ''");

    PolicyEvaluator ev(h.deps());
    REQUIRE_FALSE(ev.evaluate_now(pid).value_or("").empty()); // dispatch #1
    CHECK(h.dispatch_calls == 1);

    h.fake_now += 20;
    ev.tick(); // collect only; interval (3600s) not elapsed -> no new dispatch
    CHECK(h.dispatch_calls == 1);

    h.fake_now += 4000;
    ev.tick(); // interval elapsed -> dispatch #2
    CHECK(h.dispatch_calls == 2);
}

TEST_CASE("policy evaluator: empty compliance CEL -> error (no false compliant)",
          "[pg][policy][evaluator]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    Harness h(pool);
    // A successful check whose fragment defines an EMPTY check_compliance. The CEL
    // layer treats empty as always-compliant; the evaluator must NOT report this
    // as compliant (it would be false assurance) — it surfaces as error instead.
    h.canned["agentA|checkp"] = {1, out_json("hostname", "yuzu-a")};
    auto pid = h.author(/*check_cel=*/"");

    PolicyEvaluator ev(h.deps());
    REQUIRE_FALSE(ev.evaluate_now(pid).value_or("").empty());
    h.fake_now += 20;
    ev.tick();

    CHECK(h.status_of(pid, "agentA") == "error");
}

TEST_CASE("policy evaluator: remediation attempt cap -> error after 3 fixing transitions",
          "[pg][policy][evaluator]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    Harness h(pool);
    h.canned["agentA|checkp"] = {1, out_json("hostname", "")}; // non_compliant
    auto pid = h.author("result.hostname != ''", /*with_fix=*/true);
    h.canned["agentA|fixp"] = {1, "ok"};

    PolicyEvaluator ev(h.deps());
    REQUIRE_FALSE(ev.evaluate_now(pid).value_or("").empty());
    h.fake_now += 20;
    ev.tick();
    REQUIRE(h.status_of(pid, "agentA") == "non_compliant");

    // Drive remediation with an explicit (in-scope) agent list. Each call marks
    // the agent 'fixing'; PolicyStore caps fix attempts at 3 and forces 'error'
    // on the transition that would exceed it. Verify the cap is reached.
    //
    // Governance UP-3 (2026-08-24): remediate() now refuses a second call
    // while the prior attempt's FixWait is still outstanding (closes a
    // double-dispatch / double-attempt-count hazard), so each attempt must
    // mature — advance time past grace, tick() — before the next call. This
    // is the realistic shape anyway: an operator waits for one fix attempt to
    // resolve before retrying.
    for (int i = 0; i < 4; ++i) {
        auto rr = ev.remediate(pid, {"agentA"});
        // The first three dispatch the fix; the 4th still dispatches but the
        // status write trips the cap. remediate reports dispatch success either way.
        REQUIRE(rr.ok);
        if (i < 3) {
            // Mature this attempt's FixWait (clearing it from in_flight_) so the
            // NEXT remediate() call isn't refused as already-in-flight. Skip
            // this on the 4th/final call — collect_ready()'s own verify-phase
            // write (no canned "agentA|verifyp" response here -> non-responder
            // -> "unknown") would otherwise overwrite the cap's "error" write
            // this assertion is checking for.
            h.fake_now += 20;
            ev.tick();
        }
    }
    CHECK(h.status_of(pid, "agentA") == "error");
}

TEST_CASE("policy evaluator: remediate refuses a second call while a FixWait is already "
          "in flight for the policy (governance UP-3, 2026-08-24)",
          "[pg][policy][evaluator]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    Harness h(pool);
    h.canned["agentA|checkp"] = {1, out_json("hostname", "")}; // non_compliant
    auto pid = h.author("result.hostname != ''", /*with_fix=*/true);
    h.canned["agentA|fixp"] = {1, "ok"};

    PolicyEvaluator ev(h.deps());
    REQUIRE_FALSE(ev.evaluate_now(pid).value_or("").empty());
    h.fake_now += 20;
    ev.tick();
    REQUIRE(h.status_of(pid, "agentA") == "non_compliant");

    auto rr1 = ev.remediate(pid, {"agentA"});
    REQUIRE(rr1.ok);
    const int calls_after_first = h.dispatch_calls;

    // NO tick() here — the first call's FixWait entry is still in in_flight_
    // (collect_ready() is the only thing that clears it, and its grace
    // window hasn't elapsed). A second call for the SAME policy must be
    // refused rather than dispatching another fix and burning a second
    // attempt against the retry cap on top of the first.
    auto rr2 = ev.remediate(pid, {"agentA"});
    CHECK_FALSE(rr2.ok);
    CHECK_FALSE(rr2.degraded); // this is a business rejection, not a store degrade
    CHECK(rr2.error.find("already in flight") != std::string::npos);
    CHECK(h.dispatch_calls == calls_after_first); // no second dispatch happened
}

TEST_CASE("policy evaluator: verify dispatch failure -> error", "[pg][policy][evaluator]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    Harness h(pool);
    h.canned["agentA|checkp"] = {1, out_json("hostname", "")}; // non_compliant
    h.canned["agentA|fixp"] = {1, "ok"};
    auto pid = h.author("result.hostname != ''", /*with_fix=*/true);

    PolicyEvaluator ev(h.deps());
    REQUIRE_FALSE(ev.evaluate_now(pid).value_or("").empty());
    h.fake_now += 20;
    ev.tick();
    REQUIRE(h.status_of(pid, "agentA") == "non_compliant");

    auto rr = ev.remediate(pid, {});
    REQUIRE(rr.ok);

    // Remove the verify instruction definition before the FixWait matures, so the
    // post-check dispatch resolves to an unknown instruction and returns "".
    REQUIRE(h.is.delete_definition("test.verify"));

    h.fake_now += 20;
    ev.tick(); // collect FixWait -> verify dispatch fails -> error

    CHECK(h.status_of(pid, "agentA") == "error");
}

TEST_CASE("policy evaluator: manual remediation fix -> verify -> compliant",
          "[pg][policy][evaluator]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    Harness h(pool);
    h.canned["agentA|checkp"] = {1, out_json("hostname", "")}; // non_compliant first
    auto pid = h.author("result.hostname != ''", /*with_fix=*/true);

    PolicyEvaluator ev(h.deps());
    REQUIRE_FALSE(ev.evaluate_now(pid).value_or("").empty());
    h.fake_now += 20;
    ev.tick();
    REQUIRE(h.status_of(pid, "agentA") == "non_compliant");

    // Wire up the fix + verify responses, then remediate.
    h.canned["agentA|fixp"] = {1, "ok"};
    h.canned["agentA|verifyp"] = {1, out_json("fixed", "yes")};

    auto rr = ev.remediate(pid, {});
    REQUIRE(rr.ok);
    CHECK(rr.agents == 1);

    h.fake_now += 20;
    ev.tick(); // collect FixWait -> dispatch verify
    h.fake_now += 20;
    ev.tick(); // collect verify -> final verdict

    CHECK(h.status_of(pid, "agentA") == "compliant");
}

TEST_CASE("policy evaluator: remediation rejected when no fix_instruction",
          "[pg][policy][evaluator]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    Harness h(pool);
    h.canned["agentA|checkp"] = {1, out_json("hostname", "")};
    auto pid = h.author("result.hostname != ''", /*with_fix=*/false);

    PolicyEvaluator ev(h.deps());
    REQUIRE_FALSE(ev.evaluate_now(pid).value_or("").empty());
    h.fake_now += 20;
    ev.tick();
    REQUIRE(h.status_of(pid, "agentA") == "non_compliant");

    auto rr = ev.remediate(pid, {});
    CHECK_FALSE(rr.ok);
    CHECK(rr.error.find("remediation pathway") != std::string::npos);
}

// ============================================================================
// Multi-replica dispatch claim (ADR-0056) — the regression test for the
// design this migration exists to settle.
// ============================================================================

TEST_CASE("policy evaluator: two instances sharing one store dispatch a policy exactly once "
          "per interval, and only the dispatcher collects it",
          "[pg][policy][evaluator][claim]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 8}};
    Harness h(pool);
    h.canned["agentA|checkp"] = {1, out_json("hostname", "yuzu-a")};
    h.canned["agentB|checkp"] = {1, out_json("hostname", "")};
    // A short, explicit interval so dispatch_due() actually claims on tick()
    // rather than relying on evaluate_now()'s bypass.
    auto pid = h.author("result.hostname != ''", /*with_fix=*/false, /*interval_seconds=*/300);

    // Two independent PolicyEvaluator instances, sharing the SAME
    // PolicyStore/DB (simulating two server replicas) but each with its OWN
    // in-memory in_flight_ (Deps carries no shared state between them) and
    // its OWN dispatch counter via a shared Harness dispatch_fn (dispatch
    // calls are counted process-wide in `h`, which is enough to prove
    // dedup — both evaluators funnel through the same fake dispatch_fn).
    PolicyEvaluator evA(h.deps());
    PolicyEvaluator evB(h.deps());

    // Both tick at the same logical moment. Only one may win the advisory
    // lock and claim the due policy; the other's dispatch_due() must claim
    // nothing this tick.
    evA.tick();
    evB.tick();
    CHECK(h.dispatch_calls == 1);

    // A second simultaneous tick round, still within the 300s interval:
    // neither dispatches again (the durable claim, not either evaluator's
    // own memory, is what prevents the second dispatch).
    h.fake_now += 20;
    evA.tick();
    evB.tick();
    CHECK(h.dispatch_calls == 1);

    // Whichever evaluator dispatched is the only one whose in_flight_ holds
    // the check — advance past grace and let BOTH collect. The verdict must
    // land exactly once, correctly, regardless of which instance dispatched
    // (the other's collect_ready() has nothing in its own in_flight_ for
    // this execution, so it is a no-op for this check).
    h.fake_now += 300; // past grace AND past the 300s interval
    evA.tick();
    evB.tick();

    CHECK(h.status_of(pid, "agentA") == "compliant");
    CHECK(h.status_of(pid, "agentB") == "non_compliant");
    // The interval elapsed during that last round, so a THIRD dispatch is
    // expected (from whichever instance's dispatch_due() wins the claim
    // this time) — total calls is 2, not 3+, proving the second round above
    // truly claimed nothing.
    CHECK(h.dispatch_calls == 2);
}

// #3495 governance Gate 3 re-review (architect, 2026-08-30): PolicyEvaluator
// was the fourth production consumer of the shared command_dispatch_fn
// closure and was missed by the original #3495 fix — policy_eval_thread_
// still joined before agent_server_->Shutdown(deadline). That join-ordering
// half of the fix is real and stays (see test_shutdown_join_order.cpp).
//
// An EARLIER version of this Gate 3 round also added a should_stop check
// inside dispatch_due()'s per-claimed-policy loop, mirroring the other three
// engines. Gate 4 unhappy-path (2026-08-30, UP-1/UP-2) caught that this was
// itself a NEW BLOCKING bug: claim_due_policies durably stamps
// `last_dispatched_at` for EVERY due policy in ONE transaction BEFORE the
// loop starts — a should_stop break partway through the loop leaves the
// un-processed tail claimed but never actually checked, silently skipping
// them for up to a full `default_interval_seconds` (not "the next tick" as
// an earlier version of the removed check's comment incorrectly claimed —
// the staleness sweep it cited only resets 'fixing' status rows, never this
// claim). That should_stop check was REMOVED (see dispatch_due()'s own
// comment for the full reasoning); this test now proves the corrected
// behavior — should_stop does NOT stop dispatch_due() from processing every
// claimed policy — so a future regression re-adding that check fails here,
// not silently in production.
TEST_CASE("policy evaluator: dispatch_due() processes every claimed policy "
          "regardless of should_stop, since claim_due_policies already "
          "durably committed all of them",
          "[pg][policy][evaluator]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    Harness h(pool);

    // A second check instruction/plugin distinct from Harness's own
    // "test.check" -> "checkp", so the two policies' dispatches are
    // distinguishable BY PLUGIN NAME. Both policies dispatch the same
    // targets under the same generated-execution_id shape, and a status row
    // is only written later by collect_ready() (not by this single tick) —
    // dispatched_plugins is the one signal available within one tick call
    // that ties a dispatch back to a specific policy.
    InstructionDefinition d2;
    d2.id = "test.check2";
    d2.name = "test.check2";
    d2.version = "1.0.0";
    d2.type = "question";
    d2.plugin = "checkp2";
    d2.action = "run";
    d2.enabled = true;
    REQUIRE(h.is.create_definition(d2).has_value());

    // Two distinct policies, each with exactly one applicable check — a
    // fresh policy has no policy_dispatch_state row yet, so claim_due_policies
    // claims it on its very first tick with no preceding evaluate_now().
    h.author("result.hostname != ''"); // check: test.check -> checkp
    const std::string frag_b = "apiVersion: yuzu.io/v1alpha1\nkind: PolicyFragment\n"
                               "spec:\n  check:\n    instruction: test.check2\n    compliance: "
                               "\"result.hostname != ''\"\n";
    auto fid_b = h.ps.create_fragment(frag_b);
    REQUIRE(fid_b.has_value());
    const std::string pol_b = "apiVersion: yuzu.io/v1alpha1\nkind: Policy\n"
                              "spec:\n  fragment: " +
                              *fid_b + "\n  managementGroups:\n    - " + h.group_id + "\n";
    REQUIRE(h.ps.create_policy(pol_b).has_value()); // check: test.check2 -> checkp2

    auto deps = h.deps();
    // Stop signals true from the very first check — the strongest possible
    // adversarial case. If dispatch_due() honored this (like its Gate 3
    // round briefly did), NEITHER policy would be checked despite BOTH
    // already being durably claimed above.
    deps.should_stop = [] { return true; };
    PolicyEvaluator ev(deps);

    ev.tick(); // collect_ready() is a no-op (nothing in flight yet); dispatch_due() claims both, must dispatch both

    REQUIRE(h.dispatch_calls == 2); // NOT 0, NOT 1 — should_stop=true never gates this loop
    REQUIRE(h.dispatched_plugins.size() == 2);
    // Both plugins fired — proves BOTH policies' kickoff_check ran despite
    // should_stop reporting true throughout.
    const bool checkp_fired =
        h.dispatched_plugins[0] == "checkp" || h.dispatched_plugins[1] == "checkp";
    const bool checkp2_fired =
        h.dispatched_plugins[0] == "checkp2" || h.dispatched_plugins[1] == "checkp2";
    CHECK(checkp_fired);
    CHECK(checkp2_fired);
}

// #3495 (governance consistency-auditor, 2026-08-30): collect_ready() is now
// the ONLY should_stop site left in PolicyEvaluator (dispatch_due()'s was
// removed above) — this proves it actually works, not just that it exists.
// Unlike dispatch_due()'s claim, collect_ready()'s `ready` items carry no
// durable pre-commit, so deferring them to the next tick is genuinely safe
// here (see collect_ready()'s own comment). should_stop is checked once per
// item, at the TOP of the loop before that item's own work begins (same
// semantics as every other engine) — so should_stop already true when
// tick() is called defers EVERY ready item, not just the ones after the
// first; there is no partial-processing case to observe here the way there
// is for a dispatch-bearing loop (dispatch_due()'s own test covers that
// shape instead, where each iteration's own work is a blocking call).
TEST_CASE("policy evaluator: collect_ready() defers every ready item when "
          "should_stop() already reports true",
          "[pg][policy][evaluator]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    Harness h(pool);
    h.canned["agentA|checkp"] = {1, out_json("hostname", "a")};
    auto pid_a = h.author("result.hostname != ''");
    auto pid_b = h.author("result.hostname != ''");

    // A mutable flag rather than a fixed lambda: should_stop must read false
    // while seeding two in-flight checks (evaluate_now doesn't consult it —
    // it's a manual, operator-triggered dispatch, not a tick loop), then
    // true once collect_ready() itself is under test.
    bool stop = false;
    auto deps = h.deps();
    deps.should_stop = [&stop] { return stop; };
    PolicyEvaluator ev(deps);

    REQUIRE_FALSE(ev.evaluate_now(pid_a).value_or("").empty());
    REQUIRE_FALSE(ev.evaluate_now(pid_b).value_or("").empty());
    h.fake_now += 20; // past grace_seconds (15) — both now "ready" for collect_ready()

    stop = true;
    ev.tick(); // collect_ready() must process NEITHER ready item

    // Neither policy got an agent_status write. (Both policies' next
    // interval due-time was already pushed out by evaluate_now's own
    // durable stamp, so dispatch_due() finds nothing due in this same
    // tick() and cannot interfere with this assertion.)
    CHECK(h.status_of(pid_a, "agentA") == "<none>");
    CHECK(h.status_of(pid_b, "agentA") == "<none>");

    // NOT a temporary defer: collect_ready() dequeues every past-grace item
    // from in_flight_ into `ready` UNCONDITIONALLY, before the should_stop
    // loop even runs (see collect_ready()'s own comment) — so both entries
    // are already gone from in_flight_ by this point, regardless of
    // should_stop's value. A second tick(), even with should_stop now
    // false, has nothing left to collect for either policy; both stay
    // "<none>" until the next interval's fresh Check dispatch (UP-3, Gate 4
    // unhappy-path) — proving the bounded-but-real loss this component's
    // design accepts, not a false "it recovers on retry" claim.
    stop = false;
    ev.tick();
    CHECK(h.status_of(pid_a, "agentA") == "<none>");
    CHECK(h.status_of(pid_b, "agentA") == "<none>");
}

// #3495 companion (mirrors the PreflightRunner/ScheduleRunner control cases,
// governance quality-engineer, 2026-08-30): should_stop literally UNSET
// (every pre-existing production/test Deps that predates this field) must
// still process every due policy in one tick, not just the first — the
// classic off-by-one risk for a newly added optional predicate.
TEST_CASE("policy evaluator: an unset should_stop claims every due policy, "
          "not just the first",
          "[pg][policy][evaluator]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    Harness h(pool);
    h.author("result.hostname != ''");
    h.author("result.hostname != ''");

    PolicyEvaluator ev(h.deps()); // .should_stop left unset (default std::function<bool()>{})
    ev.tick();

    CHECK(h.dispatch_calls == 2);
}
