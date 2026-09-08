// test_command_outbox_delivery.cpp — WS-3 slice 3.3 (ADR-2002 §6): the
// leader-gated delivery loop that drains the command outbox. Real Postgres
// store + real fenced LeaderElector; the dispatch/authority seams are faked so
// the test binds the loop's DECISIONS:
//   * a pending occurrence is dispatched with its STABLE command_id and marked
//     sent (so it is not re-driven);
//   * re-authorization at send time — arming denied → mark_failed, no dispatch;
//   * a transient containment_unreadable → reschedule (stays pending, backed
//     off, attempts bumped), never mark_sent;
//   * approval provenance carried from the row's approval_id is stamped on the
//     re-resolved caller (#1398);
//   * not-leader (elector resigned) → the loop no-ops (nothing dispatched).

#include "command_outbox_delivery.hpp"
#include "command_outbox_store.hpp"
#include "leader_elector.hpp"

#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>

#include <cstdint>
#include <cstdlib>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

using namespace yuzu::server;

namespace {

yuzu::test::PgTestTemplate delivery_tpl{"cmdoutboxdeliver", [](const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    yuzu::server::CommandOutboxStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("delivery template: outbox store failed to migrate");
    yuzu::server::LeaderElector le{
        yuzu::server::LeaderElector::Config{.dsn = dsn, .holder_id = "template"}};
    if (!le.is_open())
        throw std::runtime_error("delivery template: leader_elector failed to migrate");
}};

// Records what the fake dispatch fn saw, and lets a test steer the outcome.
struct DispatchProbe {
    int calls{0};
    std::string last_command_id;
    std::string last_plugin;
    std::string last_action;
    ApprovalProvenance last_provenance{ApprovalProvenance::None};
    ConfinedDispatchOutcome next{}; // returned each call; test sets .sent etc.
};

class DeliveryPg {
public:
    DeliveryPg() {
        if (yuzu::test::pg_admin_dsn_env() == nullptr)
            SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
        db_.emplace(delivery_tpl);
        REQUIRE(db_->available());
        pool_.emplace(yuzu::server::pg::PgPool::Options{.conninfo = db_->dsn(), .size = 4});
        REQUIRE(pool_->valid());
        store_ = std::make_unique<CommandOutboxStore>(*pool_);
        REQUIRE(store_->is_open());
        elector_ = std::make_unique<LeaderElector>(
            LeaderElector::Config{.dsn = db_->dsn(), .holder_id = "test-leader"});
        REQUIRE(elector_->is_open());
        REQUIRE(elector_->try_acquire());
        epoch_ = *elector_->epoch();
    }
    DeliveryPg(const DeliveryPg&) = delete;
    DeliveryPg& operator=(const DeliveryPg&) = delete;

    CommandOutboxStore& store() { return *store_; }
    LeaderElector& elector() { return *elector_; }
    std::int64_t epoch() const { return epoch_; }
    static std::string lock() { return kServerBackgroundLeaderLock; }

    // Build a delivery loop whose dispatch/arming seams the test controls.
    CommandOutboxDelivery make_delivery(DispatchProbe& probe, bool arming_allow) {
        CommandOutboxDelivery::Deps d;
        d.outbox = store_.get();
        d.leader = elector_.get();
        d.dispatch_fn = [&probe](const std::string& plugin, const std::string& action,
                                 const std::vector<std::string>&, const std::string&,
                                 const std::unordered_map<std::string, std::string>&,
                                 const std::string&, const DispatchCaller& caller,
                                 const std::string& command_id) {
            probe.calls++;
            probe.last_command_id = command_id;
            probe.last_plugin = plugin;
            probe.last_action = action;
            probe.last_provenance = caller.approval_provenance;
            auto out = probe.next;
            out.command_id = command_id;
            return out;
        };
        d.resolve_caller = [](const std::string& principal) {
            DispatchCaller c;
            c.principal = principal;
            return c;
        };
        d.arming_check = [arming_allow](const std::string&, const std::string&,
                                        const std::string&) { return arming_allow; };
        return CommandOutboxDelivery{std::move(d)};
    }

    OutboxEnqueueRequest req(const std::string& occ, const std::string& cmd,
                             const std::string& approval = "") {
        OutboxEnqueueRequest r;
        r.occurrence_id = occ;
        r.command_id = cmd;
        r.source = "schedule_runner";
        r.plugin = "power_health";
        r.action = "report";
        r.scope_expr = "tag:linux";
        r.parameters = R"({"k":"v"})";
        r.execution_id = "exec-1";
        r.principal = "svc-scheduler";
        r.approval_id = approval;
        return r;
    }

    std::string raw_state(const std::string& occ) {
        yuzu::server::pg::PgConn conn{PQconnectdb(db_->dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        const char* p = occ.c_str();
        yuzu::server::pg::PgResult r{
            PQexecParams(conn.get(),
                         "SELECT state FROM command_outbox_store.outbox WHERE occurrence_id=$1", 1,
                         nullptr, &p, nullptr, nullptr, 0)};
        REQUIRE(r.status() == PGRES_TUPLES_OK);
        return PQntuples(r.get()) == 1 ? PQgetvalue(r.get(), 0, 0) : std::string("<absent>");
    }

private:
    std::optional<yuzu::test::PostgresTestDb> db_;
    std::optional<yuzu::server::pg::PgPool> pool_;
    std::unique_ptr<CommandOutboxStore> store_;
    std::unique_ptr<LeaderElector> elector_;
    std::int64_t epoch_{0};
};

} // namespace

TEST_CASE("CommandOutboxDelivery[pg]: delivers a pending occurrence with its stable command_id",
          "[command_outbox][pg][delivery]") {
    DeliveryPg fx;
    REQUIRE(fx.store().claim_and_enqueue(fx.req("occ-1", "cmd-STABLE"), fx.lock(), fx.epoch()) ==
            OutboxEnqueueOutcome::Enqueued);

    DispatchProbe probe;
    probe.next.sent = 3;
    auto loop = fx.make_delivery(probe, /*arming_allow=*/true);
    loop.tick();

    CHECK(probe.calls == 1);
    CHECK(probe.last_command_id == "cmd-STABLE"); // the stored id, not a fresh mint
    CHECK(probe.last_plugin == "power_health");
    CHECK(fx.raw_state("occ-1") == "sent"); // not re-driven

    // A second tick finds nothing pending — no double dispatch.
    loop.tick();
    CHECK(probe.calls == 1);
}

TEST_CASE("CommandOutboxDelivery[pg]: arming denied at delivery fails the occurrence, no dispatch",
          "[command_outbox][pg][delivery]") {
    DeliveryPg fx;
    REQUIRE(fx.store().claim_and_enqueue(fx.req("occ-deny", "cmd-x"), fx.lock(), fx.epoch()) ==
            OutboxEnqueueOutcome::Enqueued);

    DispatchProbe probe;
    auto loop = fx.make_delivery(probe, /*arming_allow=*/false);
    loop.tick();

    CHECK(probe.calls == 0); // re-authorization denied before any send
    CHECK(fx.raw_state("occ-deny") == "failed");
}

TEST_CASE("CommandOutboxDelivery[pg]: containment_unreadable reschedules, never marks sent",
          "[command_outbox][pg][delivery]") {
    DeliveryPg fx;
    REQUIRE(fx.store().claim_and_enqueue(fx.req("occ-retry", "cmd-r"), fx.lock(), fx.epoch()) ==
            OutboxEnqueueOutcome::Enqueued);

    DispatchProbe probe;
    probe.next.containment_unreadable = true;
    auto loop = fx.make_delivery(probe, /*arming_allow=*/true);
    loop.tick();

    CHECK(probe.calls == 1);
    CHECK(fx.raw_state("occ-retry") == "pending"); // still owed, backed off
    // Backed off (next_attempt_at pushed) → not due, so a same-second re-tick
    // does not redeliver.
    loop.tick();
    CHECK(probe.calls == 1);
}

TEST_CASE("CommandOutboxDelivery[pg]: carries approval provenance from the row",
          "[command_outbox][pg][delivery]") {
    DeliveryPg fx;
    REQUIRE(fx.store().claim_and_enqueue(fx.req("occ-appr", "cmd-a", /*approval=*/"ticket-77"),
                                         fx.lock(), fx.epoch()) == OutboxEnqueueOutcome::Enqueued);

    DispatchProbe probe;
    probe.next.sent = 1;
    auto loop = fx.make_delivery(probe, /*arming_allow=*/true);
    loop.tick();
    CHECK(probe.last_provenance == ApprovalProvenance::Ticket);

    // An occurrence with no approval_id stamps None.
    REQUIRE(fx.store().claim_and_enqueue(fx.req("occ-noappr", "cmd-b"), fx.lock(), fx.epoch()) ==
            OutboxEnqueueOutcome::Enqueued);
    loop.tick();
    CHECK(probe.last_provenance == ApprovalProvenance::None);
}

TEST_CASE("CommandOutboxDelivery[pg]: does nothing when this replica is not leader",
          "[command_outbox][pg][delivery]") {
    DeliveryPg fx;
    REQUIRE(fx.store().claim_and_enqueue(fx.req("occ-nolead", "cmd-n"), fx.lock(), fx.epoch()) ==
            OutboxEnqueueOutcome::Enqueued);

    DispatchProbe probe;
    auto loop = fx.make_delivery(probe, /*arming_allow=*/true);
    fx.elector().resign(); // epoch() now nullopt

    loop.tick();
    CHECK(probe.calls == 0);
    CHECK(fx.raw_state("occ-nolead") == "pending"); // left for the true leader
}
