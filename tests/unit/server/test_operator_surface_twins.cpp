/**
 * test_operator_surface_twins.cpp — PR1.5c + PR1.6c (p14): ADR-0031 operator
 * surface server wiring — MCP/REST twin parity, the ScheduleRunner
 * arming_check re-authorization seam, and the upload-session MCP exemption.
 *
 * WHAT THIS FILE BINDS. `ServerImpl::start_web_server`'s arming_check lambda
 * and the `kek_ops_.{rotate,rewrap,status}` multi-codec generalization are
 * private ServerImpl members with no live-Session-free construction path —
 * the same situation test_dispatch_chokepoint.cpp's file header documents
 * for `build_classified_command`. This file therefore binds the SAME pure
 * decision the arming_check lambda is built around
 * (`compose_arming_check` below — a byte-for-byte mirror of server.cpp's
 * lambda: classify() -> rbac_enforcement_in_effect() -> check_permission()),
 * wired into a real `ScheduleRunner` so the auto and approval-gated fire
 * paths are proven end-to-end, not just the composed function in isolation.
 * `ScheduleRunner` itself already has thorough D7 arming_check coverage in
 * `test_schedule_runner.cpp` (p4's file, not modified here) — that file
 * proves the runner correctly gates on a CANNED true/false arming_check;
 * this file proves the REAL composition (classify+rbac) server.cpp wires in
 * produces the right true/false for a real, permission-losing principal.
 *
 * The MCP/REST twin-parity and A5-contract sweeps bind the REAL served
 * tables via `mcp_server_testonly.hpp`'s accessors (kToolSecurity/
 * kToolAnnotation/kWriteTools/kTools mirrors) rather than a live McpServer —
 * hermetic, no httplib acceptor thread (#438).
 *
 * The multi-codec KEK enrolment (`kek_enrolled_codecs()`,
 * `kek_ops_.{rotate,rewrap,status}`) is NOT covered by an automated test
 * here: it is a private ServerImpl member whose exercise requires a live
 * Postgres substrate (SecretCodec::init/rotate_kek/rewrap_all all take a
 * PGconn*), which the standing unit-suite discipline
 * (docs/postgres-store-playbook.md, CLAUDE.md test-efficiency rules) keeps
 * out of the hermetic unit suites. Verified instead by careful reading
 * against `pg/secret_codec.hpp`'s documented contract — recorded as a
 * manual verification in the package summary, as the spec's acceptance
 * criterion for this item explicitly allows.
 */

#include "approval_manager.hpp"
#include "authz_model.hpp"
#include "capability_decls/plugin_action_catalogue_a.hpp"
#include "command_capability.hpp"
#include "execution_tracker.hpp"
#include "instruction_store.hpp"
#include "mcp_server_testonly.hpp"
#include "rbac_store.hpp"
#include "schedule_engine.hpp"
#include "schedule_runner.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sqlite3.h>

#include <algorithm>
#include <string>
#include <unordered_map>
#include <vector>

using namespace yuzu::server;
using namespace yuzu::server::mcp;

namespace {

// ── The seam under test: server.cpp's arming_check lambda, mirrored ────────
//
// This is the EXACT decision rule server.cpp's ScheduleRunner::Deps
// `.arming_check` lambda implements (see the "D7/PLAN-003 (p14)" comment at
// its construction site) — reproduced here so it is independently testable
// with a real CommandCapabilityRegistry and a real RbacStore, without a live
// ServerImpl. Any change to the real lambda's decision rule must be mirrored
// here too, or this test stops proving anything about the shipped seam.
bool compose_arming_check(const CommandCapabilityRegistry& registry, RbacStore* rbac,
                          const std::string& principal, const std::string& plugin,
                          const std::string& action) {
    const auto classified = registry.classify(plugin, action);
    if (!classified)
        return false;
    if (!rbac || !rbac->is_open())
        return false;
    if (!rbac_enforcement_in_effect(rbac))
        return true;
    return rbac->check_permission(principal, std::string(classified->securable),
                                  std::string(yuzu::server::authz::to_string(classified->operation)));
}

} // namespace

// ═════════════════════════════════════════════════════════════════════════
// compose_arming_check — the composed decision in isolation
// ═════════════════════════════════════════════════════════════════════════

TEST_CASE("arming_check composition: unclassified plugin.action denies (ADR-0033 §2)",
          "[server][routes][mcp]") {
    CommandCapabilityRegistry registry{capdecls::plugin_action_catalogue_a()};
    RbacStore rbac(":memory:");
    rbac.set_rbac_enabled(true);
    REQUIRE(rbac.assign_role(PrincipalRole{"user", "alice", "Administrator"}).has_value());

    // "no.such.plugin"/"nope" is not in plugin_action_catalogue_a() — a
    // missing classification means the capability does not exist (ADR-0033
    // §2), never a permissive default, even for an Administrator principal.
    CHECK_FALSE(compose_arming_check(registry, &rbac, "alice", "no.such.plugin", "nope"));
}

TEST_CASE("arming_check composition: null/closed RbacStore denies fail-closed",
          "[server][routes][mcp]") {
    CommandCapabilityRegistry registry{capdecls::plugin_action_catalogue_a()};
    CHECK_FALSE(compose_arming_check(registry, nullptr, "alice", "filesystem", "exists"));
}

TEST_CASE("arming_check composition: RBAC legacy-open (disabled) admits regardless of grant",
          "[server][routes][mcp]") {
    CommandCapabilityRegistry registry{capdecls::plugin_action_catalogue_a()};
    RbacStore rbac(":memory:");
    // Fresh store defaults to rbac_enabled_=false (legacy-open) — no
    // set_rbac_enabled(true) call here, on purpose.
    CHECK(compose_arming_check(registry, &rbac, "nobody-with-no-role", "filesystem", "exists"));
}

TEST_CASE("arming_check composition: RBAC enabled + granted principal admits",
          "[server][routes][mcp]") {
    CommandCapabilityRegistry registry{capdecls::plugin_action_catalogue_a()};
    RbacStore rbac(":memory:");
    rbac.set_rbac_enabled(true);
    // filesystem.exists classifies to FileRetrieval:Read (plugin_action_catalogue_a.hpp);
    // Administrator holds every (securable, operation) pair (rbac_store.cpp's
    // seed_defaults() generic grant loop).
    REQUIRE(rbac.assign_role(PrincipalRole{"user", "alice", "Administrator"}).has_value());
    CHECK(compose_arming_check(registry, &rbac, "alice", "filesystem", "exists"));
}

TEST_CASE("arming_check composition: RBAC enabled + ungranted principal denies",
          "[server][routes][mcp]") {
    CommandCapabilityRegistry registry{capdecls::plugin_action_catalogue_a()};
    RbacStore rbac(":memory:");
    rbac.set_rbac_enabled(true);
    // "bob" holds no role at all -> check_permission's collect_roles_locked
    // returns empty -> false.
    CHECK_FALSE(compose_arming_check(registry, &rbac, "bob", "filesystem", "exists"));
}

// ═════════════════════════════════════════════════════════════════════════
// ScheduleRunner, wired to compose_arming_check — auto and approval paths
// ═════════════════════════════════════════════════════════════════════════

namespace {

struct TestDb {
    sqlite3* db = nullptr;
    TestDb() { sqlite3_open(":memory:", &db); }
    ~TestDb() {
        if (db)
            sqlite3_close(db);
    }
};

// Minimal harness — the D7 unset/canned-arming_check ScheduleRunner
// contract itself is p4's test_schedule_runner.cpp's job; this harness
// exists only to wire compose_arming_check (a REAL registry + REAL
// RbacStore) through a real ScheduleRunner end to end.
struct Harness {
    TestDb db;
    yuzu::test::TempDbFile insdb{std::string_view("yuzu_test_optwins_ins_")};

    ScheduleEngine engine{db.db};
    ExecutionTracker tracker{db.db};
    ApprovalManager approvals{db.db};
    InstructionStore is{insdb.path};

    CommandCapabilityRegistry registry{capdecls::plugin_action_catalogue_a()};
    RbacStore rbac{":memory:"};

    std::vector<std::string> dispatched_actions;

    ScheduleRunner runner;

    explicit Harness()
        : runner(ScheduleRunner::Deps{
              .schedule_engine = &engine,
              .instruction_store = &is,
              .execution_tracker = &tracker,
              .approval_manager = &approvals,
              .dispatch_fn =
                  [this](const std::string& plugin, const std::string& action,
                         const std::vector<std::string>&, const std::string&,
                         const std::unordered_map<std::string, std::string>&,
                         const std::string&) -> std::pair<std::string, int> {
                      dispatched_actions.push_back(plugin + "." + action);
                      return {"cmd-" + std::to_string(dispatched_actions.size()), 1};
                  },
              .arming_check =
                  [this](const std::string& principal, const std::string& plugin,
                        const std::string& action) {
                      return compose_arming_check(registry, &rbac, principal, plugin, action);
                  },
          }) {
        engine.create_tables();
        tracker.create_tables();
        approvals.create_tables();
        rbac.set_rbac_enabled(true);

        // filesystem.exists -> FileRetrieval:Read (plugin_action_catalogue_a.hpp).
        InstructionDefinition d;
        d.id = "test.fsexists";
        d.name = "test.fsexists";
        d.version = "1.0.0";
        d.type = "question";
        d.plugin = "filesystem";
        d.action = "exists";
        d.enabled = true;
        REQUIRE(is.create_definition(d).has_value());
    }

    std::string make_due(const std::string& created_by, bool requires_approval) {
        InstructionSchedule s;
        s.name = "sched-" + created_by;
        s.definition_id = "test.fsexists";
        s.frequency_type = "interval";
        s.interval_minutes = 60;
        s.scope_expression = "";
        s.requires_approval = requires_approval;
        s.enabled = true;
        s.created_by = created_by;
        s.next_execution_at = 1; // due immediately
        auto id = engine.create_schedule(s);
        REQUIRE(id.has_value());
        return *id;
    }

    void force_due(const std::string& id) {
        char* err = nullptr;
        auto sql = "UPDATE schedules SET next_execution_at = 1 WHERE id = '" + id + "'";
        REQUIRE(sqlite3_exec(db.db, sql.c_str(), nullptr, nullptr, &err) == SQLITE_OK);
    }
};

} // namespace

TEST_CASE("arming_check (auto path): a schedule whose creator lost the required permission "
          "does not fire, and re-fires once permission is restored",
          "[server][routes][mcp][schedule]") {
    Harness h;
    REQUIRE(h.rbac.assign_role(PrincipalRole{"user", "carol", "Administrator"}).has_value());
    auto id = h.make_due("carol", /*requires_approval=*/false);

    h.runner.tick();
    REQUIRE(h.dispatched_actions.size() == 1);
    CHECK(h.dispatched_actions[0] == "filesystem.exists");

    // Permission lost: unassign the role the arming check re-verifies.
    REQUIRE(h.rbac.unassign_role("user", "carol", "Administrator").has_value());
    h.force_due(id);
    h.runner.tick();
    // No new dispatch — the occurrence is skipped (fire-and-advance), not
    // fired under stale authority.
    CHECK(h.dispatched_actions.size() == 1);

    // Restore: re-verified fresh on the NEXT occurrence too, not cached.
    REQUIRE(h.rbac.assign_role(PrincipalRole{"user", "carol", "Administrator"}).has_value());
    h.force_due(id);
    h.runner.tick();
    CHECK(h.dispatched_actions.size() == 2);
}

TEST_CASE("arming_check (approval path): a schedule whose creator lost the required "
          "permission does not submit an approval ticket and does not fire",
          "[server][routes][mcp][schedule]") {
    Harness h;
    REQUIRE(h.rbac.assign_role(PrincipalRole{"user", "dave", "Administrator"}).has_value());
    auto id = h.make_due("dave", /*requires_approval=*/true);

    // Still armed: fires the approval-gated arm, submitting exactly one ticket.
    h.runner.tick();
    auto pending = h.approvals.query({.status = "pending"});
    REQUIRE(pending.size() == 1);
    REQUIRE(h.approvals.approve(pending[0].id, "boss", "ok").has_value());
    h.runner.tick();
    REQUIRE(h.dispatched_actions.size() == 1);

    // Permission lost before the NEXT occurrence.
    REQUIRE(h.rbac.unassign_role("user", "dave", "Administrator").has_value());
    h.force_due(id);
    h.runner.tick();
    // The arming re-check gates IN FRONT OF fire_with_approval (schedule_runner.hpp's
    // fire() doc comment) — a denial here must mean fire_with_approval never
    // runs at all: no new ticket, no new dispatch.
    CHECK(h.approvals.query({.status = "pending"}).empty());
    CHECK(h.dispatched_actions.size() == 1);
}

// ═════════════════════════════════════════════════════════════════════════
// MCP/REST twin parity — same securable, same operation, per pair
// ═════════════════════════════════════════════════════════════════════════

namespace {

struct TwinRow {
    std::string_view tool;
    std::string_view securable;
    std::string_view operation;
    bool is_read;
};

// Pinned against plugin_config_routes.hpp's / file_retrieval_routes.hpp's
// documented REST route tables — the SAME (securable, operation) each REST
// handler gates on (see those headers' file-header route tables).
constexpr TwinRow kExpectedTwins[] = {
    {"get_plugin_config", "PluginConfig", "Read", true},
    {"list_plugin_config", "PluginConfig", "Read", true},
    {"set_plugin_config", "PluginConfig", "Write", false},
    {"delete_plugin_config", "PluginConfig", "Delete", false},
    {"set_plugin_secret", "PluginSecret", "Write", false},
    {"delete_plugin_secret", "PluginSecret", "Delete", false},
    {"get_plugin_kill_switch", "PluginConfig", "Read", true},
    {"set_plugin_kill_switch", "PluginConfig", "Write", false},
    {"mint_upload_grant", "UploadGrant", "Write", false},
    {"list_upload_grants", "UploadGrant", "Read", true},
    {"revoke_upload_grant", "UploadGrant", "Delete", false},
};

} // namespace

TEST_CASE("operator surface MCP twins: securable/operation parity with the REST routes",
          "[server][routes][mcp]") {
    const auto rows = tool_security_rows_for_test();
    for (const auto& expected : kExpectedTwins) {
        INFO("tool: " << expected.tool);
        const auto it = std::find_if(rows.begin(), rows.end(), [&](const ToolSecurityRow& r) {
            return r.name == expected.tool;
        });
        REQUIRE(it != rows.end());
        CHECK(it->securable == expected.securable);
        CHECK(it->operation == expected.operation);
    }
}

TEST_CASE("operator surface MCP twins: non-Read tools are in kWriteTools, Read tools are not",
          "[server][routes][mcp]") {
    const auto write_tools = write_tool_names_for_test();
    for (const auto& expected : kExpectedTwins) {
        INFO("tool: " << expected.tool);
        const bool present =
            std::find(write_tools.begin(), write_tools.end(), expected.tool) != write_tools.end();
        CHECK(present == !expected.is_read);
    }
}

// ═════════════════════════════════════════════════════════════════════════
// A5 contract sweep (docs/agentic-first-principle.md:88)
// ═════════════════════════════════════════════════════════════════════════

TEST_CASE("operator surface MCP twins: every tool satisfies the A5 contract",
          "[server][routes][mcp]") {
    const auto served = tool_names_for_test();
    const auto annotated = tool_annotation_names_for_test();
    const auto schemas = input_schemas_for_test();

    for (const auto& expected : kExpectedTwins) {
        INFO("tool: " << expected.tool);
        // Served + classified.
        CHECK(std::find(served.begin(), served.end(), expected.tool) != served.end());
        // Annotation-map entry present (readOnlyHint/destructiveHint/idempotentHint).
        CHECK(std::find(annotated.begin(), annotated.end(), expected.tool) != annotated.end());
        // Bounded, typed input schema — no free-form object.
        const auto schema_it =
            std::find_if(schemas.begin(), schemas.end(),
                        [&](const auto& s) { return s.name == expected.tool; });
        REQUIRE(schema_it != schemas.end());
        CHECK(schema_it->schema_json.find("\"type\":\"object\"") != std::string::npos);
        CHECK(schema_it->schema_json.find("\"properties\"") != std::string::npos);
        // A bare {"type":"object","properties":{}} with no further structure
        // would be the free-form-object footgun the spec forbids for every
        // tool that takes an argument at all — every one of these 11 takes
        // at least one property.
        CHECK(schema_it->schema_json != R"({"type":"object","properties":{}})");
    }
}

TEST_CASE("operator surface MCP twins: no MCP tool exists for any agent-authenticated "
          "upload session endpoint",
          "[server][routes][mcp]") {
    // The exemption (spec item 3): POST /api/v1/uploads, PUT .../chunk, GET
    // .../{upload_id}, POST .../commit, DELETE .../{upload_id} authenticate
    // on a grant/session bearer credential, never an operator session, and
    // get NO MCP twin. The upload-grant tool family must be EXACTLY the
    // three operator routes — proving no 4th/5th tool for a session
    // endpoint slipped in alongside them.
    const auto served = tool_names_for_test();
    std::vector<std::string> upload_grant_tools;
    for (const auto& name : served)
        if (name.find("upload_grant") != std::string::npos)
            upload_grant_tools.push_back(name);
    std::sort(upload_grant_tools.begin(), upload_grant_tools.end());
    const std::vector<std::string> expected = {"list_upload_grants", "mint_upload_grant",
                                               "revoke_upload_grant"};
    CHECK(upload_grant_tools == expected);

    // Belt-and-braces: no served tool name references the session-only
    // vocabulary (chunk/commit/session) at all.
    for (const auto& name : served) {
        INFO("tool: " << name);
        CHECK(name.find("upload_chunk") == std::string::npos);
        CHECK(name.find("upload_session") == std::string::npos);
        CHECK(name.find("commit_upload") == std::string::npos);
        CHECK(name.find("cancel_upload") == std::string::npos);
        CHECK(name.find("open_upload") == std::string::npos);
    }
}
