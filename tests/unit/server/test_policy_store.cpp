/**
 * test_policy_store.cpp -- Unit tests for PolicyStore (ADR-0056, Postgres)
 *
 * Covers: fail-closed construction, Fragment CRUD, Policy CRUD, compliance
 * tracking, cache invalidation, YAML parsing edge cases, cascading deletes,
 * the ADR-0009/ADR-0056 migrate_from_sqlite backfill contract (fingerprint
 * idempotency, sourceless-never-blocks-a-holder, the fix_attempt_count
 * ALTER-wart legacy-column tolerance, partial-schema fail-closed), and
 * claim_due_policies (the ADR-0056 headline multi-replica dispatch design) —
 * single-instance coverage here; the two-instance dispatch-dedup regression
 * test lives in test_policy_evaluator.cpp alongside the evaluator that
 * drives it.
 *
 * Born-on-Postgres migrated store (ADR-0012 §1, split posture — see
 * policy_store.hpp). PG-gated: skips when YUZU_TEST_POSTGRES_DSN is unset,
 * fails when set but broken (test_helpers.hpp skip-vs-fail contract).
 * Store-behaviour cases use the pre-migrated PgTestTemplate variant
 * (docs/postgres-store-playbook.md step 7); the construction/backfill cases
 * use YUZU_REQUIRE_PG_DB, per that macro's plain-migration-test carve-out.
 */

#include "policy_store.hpp"

#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "sqlite_raii.hpp"
#include "store_errors.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>
#include <sqlite3.h>

#include <chrono>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <vector>

using namespace yuzu::server;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;

// ---- YAML helpers ----------------------------------------------------------

static const std::string kCheckOnlyFragment = R"(
apiVersion: yuzu.io/v1alpha1
kind: PolicyFragment
displayName: Check Service Running
description: Verify a Windows service is running
spec:
  check:
    instruction: get_service_status
    compliance: "result.status == 'running'"
    parameters:
      service_name: "{{inputs.service}}"
)";

static const std::string kFullFragment = R"(
apiVersion: yuzu.io/v1alpha1
kind: PolicyFragment
id: frag-full-001
displayName: Full Fragment
description: Fragment with check, fix, and postCheck
spec:
  check:
    instruction: get_service_status
    compliance: "result.status == 'running'"
    parameters:
      service_name: "{{inputs.service}}"
  fix:
    instruction: start_service
    parameters:
      service_name: "{{inputs.service}}"
  postCheck:
    instruction: get_service_status
    compliance: "result.status == 'running'"
    parameters:
      service_name: "{{inputs.service}}"
)";

static const std::string kCheckOnlyNoFix = R"(
apiVersion: yuzu.io/v1alpha1
kind: PolicyFragment
id: frag-check-only
displayName: Check Only Fragment
description: A fragment with only a check section
spec:
  check:
    instruction: check_disk_space
    compliance: "result.free_gb > 10"
    parameters:
      drive: C
)";

// Returns a Policy YAML that references the given fragment ID
static std::string make_policy_yaml(const std::string& fragment_id,
                                     const std::string& name = "Test Policy") {
    return R"(
apiVersion: yuzu.io/v1alpha1
kind: Policy
displayName: )" +
           name + R"(
description: A test policy
fragment: )" +
           fragment_id + R"(
scope: "tags.env == 'production'"
inputs:
  service: WinRM
triggers:
  - type: interval
    interval_seconds: 300
  - type: file_change
    path: "C:\\config.yaml"
managementGroups:
  - "all-devices"
  - "windows-servers"
)";
}

namespace {

yuzu::test::PgTestTemplate policy_store_tpl{
    "policystore", [](const std::string& dsn) {
        PgPool pool{{.conninfo = dsn, .size = 1}};
        PolicyStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("policy_store template: failed to migrate");
    }};

// Legacy-fixture row shapes (mirror PolicyStore's public structs; a status
// row additionally carries fix_attempt_count, which PolicyAgentStatus does
// not expose — see the header note on that struct).
struct LegacyStatusRow {
    std::string policy_id;
    std::string agent_id;
    std::string status;
    int64_t last_check_at{0};
    int64_t last_fix_at{0};
    std::string check_result;
    int fix_attempt_count{0};
};

/// Writes a legacy SQLite `policies.db` fixture. `with_fix_attempt_count`
/// controls whether `policy_status` carries the G4-UHP-POL-003 column —
/// false exercises the pre-wart-vintage backfill tolerance path.
void write_legacy_policy_sqlite_db(const std::filesystem::path& path,
                                   const std::vector<PolicyFragment>& fragments,
                                   const std::vector<Policy>& policies,
                                   const std::vector<PolicyInput>& inputs,
                                   const std::vector<PolicyTrigger>& triggers,
                                   const std::vector<PolicyGroupBinding>& groups,
                                   const std::vector<LegacyStatusRow>& status_rows,
                                   bool with_fix_attempt_count = true) {
    SqliteDb db;
    REQUIRE(sqlite3_open(path.string().c_str(), db.addr()) == SQLITE_OK);
    std::string ddl =
        "CREATE TABLE policy_fragments (id TEXT PRIMARY KEY, name TEXT NOT NULL,"
        "  description TEXT NOT NULL DEFAULT '', yaml_source TEXT NOT NULL,"
        "  check_instruction TEXT, check_compliance TEXT,"
        "  check_parameters TEXT NOT NULL DEFAULT '{}', fix_instruction TEXT,"
        "  fix_parameters TEXT NOT NULL DEFAULT '{}', post_check_instruction TEXT,"
        "  post_check_compliance TEXT, post_check_parameters TEXT NOT NULL DEFAULT '{}',"
        "  created_at INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL DEFAULT 0);"
        "CREATE TABLE policies (id TEXT PRIMARY KEY, name TEXT NOT NULL,"
        "  description TEXT NOT NULL DEFAULT '', yaml_source TEXT NOT NULL,"
        "  fragment_id TEXT NOT NULL, scope_expression TEXT, enabled INTEGER NOT NULL DEFAULT 1,"
        "  created_at INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL DEFAULT 0);"
        "CREATE TABLE policy_inputs (policy_id TEXT NOT NULL, key TEXT NOT NULL,"
        "  value TEXT NOT NULL, PRIMARY KEY(policy_id, key));"
        "CREATE TABLE policy_triggers (id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  policy_id TEXT NOT NULL, trigger_type TEXT NOT NULL,"
        "  config_json TEXT NOT NULL DEFAULT '{}');"
        "CREATE TABLE policy_groups (policy_id TEXT NOT NULL, group_id TEXT NOT NULL,"
        "  PRIMARY KEY(policy_id, group_id));"
        "CREATE TABLE policy_status (policy_id TEXT NOT NULL, agent_id TEXT NOT NULL,"
        "  status TEXT NOT NULL DEFAULT 'unknown', last_check_at INTEGER NOT NULL DEFAULT 0,"
        "  last_fix_at INTEGER NOT NULL DEFAULT 0, check_result TEXT NOT NULL DEFAULT ''";
    if (with_fix_attempt_count)
        ddl += ", fix_attempt_count INTEGER NOT NULL DEFAULT 0";
    ddl += ", PRIMARY KEY(policy_id, agent_id));";
    REQUIRE(sqlite3_exec(db.get(), ddl.c_str(), nullptr, nullptr, nullptr) == SQLITE_OK);

    for (const auto& f : fragments) {
        SqliteStmt s;
        REQUIRE(sqlite3_prepare_v2(
                    db.get(),
                    "INSERT INTO policy_fragments (id, name, description, yaml_source, "
                    "check_instruction, check_compliance, check_parameters, fix_instruction, "
                    "fix_parameters, post_check_instruction, post_check_compliance, "
                    "post_check_parameters, created_at, updated_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    -1, s.addr(), nullptr) == SQLITE_OK);
        sqlite3_bind_text(s.get(), 1, f.id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s.get(), 2, f.name.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s.get(), 3, f.description.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s.get(), 4, f.yaml_source.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s.get(), 5, f.check_instruction.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s.get(), 6, f.check_compliance.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s.get(), 7, f.check_parameters.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s.get(), 8, f.fix_instruction.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s.get(), 9, f.fix_parameters.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s.get(), 10, f.post_check_instruction.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s.get(), 11, f.post_check_compliance.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s.get(), 12, f.post_check_parameters.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(s.get(), 13, f.created_at);
        sqlite3_bind_int64(s.get(), 14, f.updated_at);
        REQUIRE(sqlite3_step(s.get()) == SQLITE_DONE);
    }
    for (const auto& p : policies) {
        SqliteStmt s;
        REQUIRE(sqlite3_prepare_v2(db.get(),
                                   "INSERT INTO policies (id, name, description, yaml_source, "
                                   "fragment_id, scope_expression, enabled, created_at, "
                                   "updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
                                   -1, s.addr(), nullptr) == SQLITE_OK);
        sqlite3_bind_text(s.get(), 1, p.id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s.get(), 2, p.name.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s.get(), 3, p.description.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s.get(), 4, p.yaml_source.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s.get(), 5, p.fragment_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s.get(), 6, p.scope_expression.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(s.get(), 7, p.enabled ? 1 : 0);
        sqlite3_bind_int64(s.get(), 8, p.created_at);
        sqlite3_bind_int64(s.get(), 9, p.updated_at);
        REQUIRE(sqlite3_step(s.get()) == SQLITE_DONE);
    }
    for (const auto& i : inputs) {
        SqliteStmt s;
        REQUIRE(sqlite3_prepare_v2(db.get(),
                                   "INSERT INTO policy_inputs (policy_id, key, value) "
                                   "VALUES (?,?,?)",
                                   -1, s.addr(), nullptr) == SQLITE_OK);
        sqlite3_bind_text(s.get(), 1, i.policy_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s.get(), 2, i.key.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s.get(), 3, i.value.c_str(), -1, SQLITE_TRANSIENT);
        REQUIRE(sqlite3_step(s.get()) == SQLITE_DONE);
    }
    for (const auto& t : triggers) {
        SqliteStmt s;
        REQUIRE(sqlite3_prepare_v2(db.get(),
                                   "INSERT INTO policy_triggers (policy_id, trigger_type, "
                                   "config_json) VALUES (?,?,?)",
                                   -1, s.addr(), nullptr) == SQLITE_OK);
        sqlite3_bind_text(s.get(), 1, t.policy_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s.get(), 2, t.trigger_type.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s.get(), 3, t.config_json.c_str(), -1, SQLITE_TRANSIENT);
        REQUIRE(sqlite3_step(s.get()) == SQLITE_DONE);
    }
    for (const auto& g : groups) {
        SqliteStmt s;
        REQUIRE(sqlite3_prepare_v2(db.get(),
                                   "INSERT INTO policy_groups (policy_id, group_id) VALUES (?,?)",
                                   -1, s.addr(), nullptr) == SQLITE_OK);
        sqlite3_bind_text(s.get(), 1, g.policy_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s.get(), 2, g.group_id.c_str(), -1, SQLITE_TRANSIENT);
        REQUIRE(sqlite3_step(s.get()) == SQLITE_DONE);
    }
    for (const auto& r : status_rows) {
        SqliteStmt s;
        std::string sql =
            "INSERT INTO policy_status (policy_id, agent_id, status, last_check_at, "
            "last_fix_at, check_result";
        sql += with_fix_attempt_count ? ", fix_attempt_count) VALUES (?,?,?,?,?,?,?)"
                                      : ") VALUES (?,?,?,?,?,?)";
        REQUIRE(sqlite3_prepare_v2(db.get(), sql.c_str(), -1, s.addr(), nullptr) == SQLITE_OK);
        sqlite3_bind_text(s.get(), 1, r.policy_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s.get(), 2, r.agent_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s.get(), 3, r.status.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(s.get(), 4, r.last_check_at);
        sqlite3_bind_int64(s.get(), 5, r.last_fix_at);
        sqlite3_bind_text(s.get(), 6, r.check_result.c_str(), -1, SQLITE_TRANSIENT);
        if (with_fix_attempt_count)
            sqlite3_bind_int(s.get(), 7, r.fix_attempt_count);
        REQUIRE(sqlite3_step(s.get()) == SQLITE_DONE);
    }
}

} // namespace

// ============================================================================
// Construction fail-closed
// ============================================================================

TEST_CASE("PolicyStore reports !is_open on a migration failure", "[policy_store][pg]") {
    YUZU_REQUIRE_PG_DB(db);
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult s{PQexec(conn.get(), "CREATE SCHEMA policy_store")};
        REQUIRE(s.ok());
        PgResult t{PQexec(conn.get(), "CREATE TABLE policy_store.policy_fragments (bogus int)")};
        REQUIRE(t.ok());
    }
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    PolicyStore store{pool};
    CHECK_FALSE(store.is_open());
}

TEST_CASE("PolicyStore reports !is_open on an unreachable pool", "[policy_store]") {
    PgPool pool{{.conninfo = "=quohth4eeQu5 garbage =", .size = 2}};
    REQUIRE_FALSE(pool.valid());
    PolicyStore store{pool};
    CHECK_FALSE(store.is_open());
}

// ============================================================================
// Fragment CRUD
// ============================================================================

TEST_CASE("PolicyStore: open against Postgres", "[policy_store][pg][db]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};
    REQUIRE(store.is_open());
}

TEST_CASE("PolicyStore: create fragment from YAML", "[policy_store][pg][fragment]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto result = store.create_fragment(kCheckOnlyFragment);
    REQUIRE(result.has_value());
    CHECK(!result.value().empty());

    auto frag = store.get_fragment(result.value());
    REQUIRE(frag.has_value());
    REQUIRE(frag->has_value());
    CHECK((*frag)->name == "Check Service Running");
    CHECK((*frag)->description == "Verify a Windows service is running");
    CHECK((*frag)->check_instruction == "get_service_status");
    CHECK((*frag)->check_compliance == "result.status == 'running'");
    CHECK((*frag)->created_at > 0);
    CHECK((*frag)->updated_at > 0);
}

TEST_CASE("PolicyStore: create fragment with explicit ID", "[policy_store][pg][fragment]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto result = store.create_fragment(kFullFragment);
    REQUIRE(result.has_value());
    CHECK(result.value() == "frag-full-001");

    auto frag = store.get_fragment("frag-full-001");
    REQUIRE(frag.has_value());
    REQUIRE(frag->has_value());
    CHECK((*frag)->name == "Full Fragment");
}

TEST_CASE("PolicyStore: query fragments", "[policy_store][pg][fragment]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    (void)store.create_fragment(kCheckOnlyFragment);
    (void)store.create_fragment(kFullFragment);
    (void)store.create_fragment(kCheckOnlyNoFix);

    auto all = store.query_fragments();
    REQUIRE(all.has_value());
    REQUIRE(all->size() == 3);

    FragmentQuery q;
    q.name_filter = "Check";
    auto filtered = store.query_fragments(q);
    REQUIRE(filtered.has_value());
    REQUIRE(filtered->size() == 2); // "Check Service Running" and "Check Only Fragment"

    FragmentQuery q2;
    q2.limit = 1;
    auto limited = store.query_fragments(q2);
    REQUIRE(limited.has_value());
    REQUIRE(limited->size() == 1);
}

TEST_CASE("PolicyStore: delete fragment", "[policy_store][pg][fragment]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto result = store.create_fragment(kCheckOnlyFragment);
    REQUIRE(result.has_value());

    CHECK(store.delete_fragment(result.value()) == true);
    auto gone = store.get_fragment(result.value());
    REQUIRE(gone.has_value());
    CHECK(*gone == std::nullopt);

    // Second delete returns false
    CHECK(store.delete_fragment(result.value()) == false);
}

TEST_CASE("PolicyStore: create fragment with duplicate ID", "[policy_store][pg][fragment]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto r1 = store.create_fragment(kFullFragment);
    REQUIRE(r1.has_value());
    CHECK(r1.value() == "frag-full-001");

    // Attempt duplicate — fragment has both duplicate id and duplicate
    // displayName. The #396 name guard fires first (and is more informative
    // than the id PK-conflict), so the error carries the "conflict:" prefix
    // routes use to map to HTTP 409.
    auto r2 = store.create_fragment(kFullFragment);
    REQUIRE(!r2.has_value());
    CHECK(is_conflict_error(r2.error()));
}

TEST_CASE("PolicyStore: create fragment with empty YAML", "[policy_store][pg][fragment]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto result = store.create_fragment("");
    REQUIRE(!result.has_value());
    CHECK(result.error() == "yaml_source is required");
}

TEST_CASE("PolicyStore: create fragment with wrong kind", "[policy_store][pg][fragment]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto result = store.create_fragment("kind: Policy\nname: oops\n");
    REQUIRE(!result.has_value());
    CHECK(result.error().find("kind must be 'PolicyFragment'") != std::string::npos);
    CHECK(result.error().find("apiVersion: yuzu.io/v1alpha1") != std::string::npos);
    CHECK(result.error().find("docs/user-manual/policy-engine.md") != std::string::npos);
}

TEST_CASE("PolicyStore: create fragment with missing kind", "[policy_store][pg][fragment]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto result = store.create_fragment("name: no-kind\ndescription: missing kind field\n");
    REQUIRE(!result.has_value());
    CHECK(result.error().find("kind must be 'PolicyFragment'") != std::string::npos);
    CHECK(result.error().find("apiVersion: yuzu.io/v1alpha1") != std::string::npos);
    CHECK(result.error().find("docs/user-manual/policy-engine.md") != std::string::npos);
}

TEST_CASE("PolicyStore: fragment with check only (no fix, no postCheck)",
          "[policy_store][pg][fragment][yaml]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto result = store.create_fragment(kCheckOnlyNoFix);
    REQUIRE(result.has_value());

    auto frag = store.get_fragment(result.value());
    REQUIRE(frag.has_value());
    REQUIRE(frag->has_value());
    CHECK((*frag)->check_instruction == "check_disk_space");
    CHECK((*frag)->check_compliance == "result.free_gb > 10");
    CHECK((*frag)->fix_instruction.empty());
    CHECK((*frag)->fix_parameters == "{}");
    CHECK((*frag)->post_check_instruction.empty());
    CHECK((*frag)->post_check_parameters == "{}");
}

TEST_CASE("PolicyStore: fragment with all three sections", "[policy_store][pg][fragment][yaml]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto result = store.create_fragment(kFullFragment);
    REQUIRE(result.has_value());

    auto frag = store.get_fragment("frag-full-001");
    REQUIRE(frag.has_value());
    REQUIRE(frag->has_value());
    CHECK((*frag)->check_instruction == "get_service_status");
    CHECK((*frag)->check_compliance == "result.status == 'running'");
    CHECK((*frag)->fix_instruction == "start_service");
    CHECK((*frag)->post_check_instruction == "get_service_status");
    CHECK((*frag)->post_check_compliance == "result.status == 'running'");
}

TEST_CASE("PolicyStore: cannot delete fragment referenced by a policy",
          "[policy_store][pg][fragment]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag_result = store.create_fragment(kFullFragment);
    REQUIRE(frag_result.has_value());

    auto yaml = make_policy_yaml(frag_result.value());
    auto pol_result = store.create_policy(yaml);
    REQUIRE(pol_result.has_value());

    CHECK(store.delete_fragment(frag_result.value()) == false);

    auto still_there = store.get_fragment(frag_result.value());
    REQUIRE(still_there.has_value());
    CHECK(still_there->has_value());
}

// ============================================================================
// Policy CRUD
// ============================================================================

TEST_CASE("PolicyStore: create policy from YAML", "[policy_store][pg][policy]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());

    auto yaml = make_policy_yaml(frag.value(), "My Service Policy");
    auto result = store.create_policy(yaml);
    REQUIRE(result.has_value());
    CHECK(!result.value().empty());

    auto pol = store.get_policy(result.value());
    REQUIRE(pol.has_value());
    REQUIRE(pol->has_value());
    CHECK((*pol)->name == "My Service Policy");
    CHECK((*pol)->description == "A test policy");
    CHECK((*pol)->fragment_id == frag.value());
    CHECK((*pol)->enabled == true);
    CHECK((*pol)->created_at > 0);

    REQUIRE((*pol)->inputs.size() == 1);
    CHECK((*pol)->inputs[0].key == "service");
    CHECK((*pol)->inputs[0].value == "WinRM");

    REQUIRE((*pol)->triggers.size() == 2);
    bool has_interval = false, has_file_change = false;
    for (const auto& t : (*pol)->triggers) {
        if (t.trigger_type == "interval")
            has_interval = true;
        if (t.trigger_type == "file_change")
            has_file_change = true;
    }
    CHECK(has_interval);
    CHECK(has_file_change);

    REQUIRE((*pol)->management_groups.size() == 2);
    CHECK((*pol)->management_groups[0] == "all-devices");
    CHECK((*pol)->management_groups[1] == "windows-servers");
}

TEST_CASE("PolicyStore: scope.selector mapping lowers to an expression (PR-E)",
          "[policy_store][pg][policy][scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};
    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());

    std::string yaml = R"(
apiVersion: yuzu.io/v1alpha1
kind: Policy
displayName: Selector Policy
fragment: )" + frag.value() +
                       R"(
scope:
  selector:
    platform: Windows
    tags:
      - prod
)";
    auto result = store.create_policy(yaml);
    REQUIRE(result.has_value());
    auto pol = store.get_policy(result.value());
    REQUIRE(pol.has_value());
    REQUIRE(pol->has_value());
    CHECK((*pol)->scope_expression == "ostype == \"windows\" AND EXISTS tag:prod");
}

TEST_CASE("PolicyStore: scope.fromResultSet is rejected for policies (deferred to PR-E2)",
          "[policy_store][pg][policy][scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};
    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());

    std::string yaml = R"(
apiVersion: yuzu.io/v1alpha1
kind: Policy
displayName: RS Policy
fragment: )" + frag.value() +
                       R"(
scope:
  fromResultSet: rs_abc
)";
    auto result = store.create_policy(yaml);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().find("fromResultSet") != std::string::npos);
}

TEST_CASE("PolicyStore: scalar scope.fromResultSet is also rejected (#1221 MEDIUM-1)",
          "[policy_store][pg][policy][scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};
    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());

    std::string yaml = R"(
apiVersion: yuzu.io/v1alpha1
kind: Policy
displayName: Scalar RS Policy
fragment: )" + frag.value() +
                       R"(
scope: from_result_set:rs_abc
)";
    auto result = store.create_policy(yaml);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().find("fromResultSet") != std::string::npos);

    std::string yaml2 = R"(
apiVersion: yuzu.io/v1alpha1
kind: Policy
displayName: Composed RS Policy
fragment: )" + frag.value() +
                        R"(
scope: ostype == "windows" AND from_result_set:rs_abc
)";
    auto result2 = store.create_policy(yaml2);
    REQUIRE_FALSE(result2.has_value());
    CHECK(result2.error().find("fromResultSet") != std::string::npos);
}

TEST_CASE("PolicyStore: inline flow-mapping scope is rejected (UP-6)",
          "[policy_store][pg][policy][scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};
    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());

    std::string yaml = R"(
apiVersion: yuzu.io/v1alpha1
kind: Policy
displayName: Inline Policy
fragment: )" + frag.value() +
                       R"(
scope: {selector: {platform: windows}}
)";
    auto result = store.create_policy(yaml);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().find("inline flow-mapping") != std::string::npos);
}

TEST_CASE("PolicyStore: query policies with filters", "[policy_store][pg][policy]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());

    (void)store.create_policy(make_policy_yaml(frag.value(), "Alpha Policy"));
    (void)store.create_policy(make_policy_yaml(frag.value(), "Beta Policy"));
    (void)store.create_policy(make_policy_yaml(frag.value(), "Gamma Policy"));

    auto all = store.query_policies();
    REQUIRE(all.has_value());
    REQUIRE(all->size() == 3);

    PolicyQuery q;
    q.name_filter = "Alpha";
    auto filtered = store.query_policies(q);
    REQUIRE(filtered.has_value());
    REQUIRE(filtered->size() == 1);
    CHECK((*filtered)[0].name == "Alpha Policy");

    PolicyQuery q2;
    q2.fragment_filter = frag.value();
    auto by_frag = store.query_policies(q2);
    REQUIRE(by_frag.has_value());
    CHECK(by_frag->size() == 3);

    PolicyQuery q3;
    q3.limit = 2;
    auto limited = store.query_policies(q3);
    REQUIRE(limited.has_value());
    CHECK(limited->size() == 2);
}

TEST_CASE("PolicyStore: enable and disable policy", "[policy_store][pg][policy]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());

    auto pol_result = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol_result.has_value());

    auto pol = store.get_policy(pol_result.value());
    REQUIRE(pol.has_value());
    REQUIRE(pol->has_value());
    CHECK((*pol)->enabled == true);

    auto disable_r = store.disable_policy(pol_result.value());
    REQUIRE(disable_r.has_value());

    pol = store.get_policy(pol_result.value());
    REQUIRE(pol.has_value());
    REQUIRE(pol->has_value());
    CHECK((*pol)->enabled == false);

    PolicyQuery q;
    q.enabled_only = true;
    auto enabled = store.query_policies(q);
    REQUIRE(enabled.has_value());
    CHECK(enabled->empty());

    auto enable_r = store.enable_policy(pol_result.value());
    REQUIRE(enable_r.has_value());

    pol = store.get_policy(pol_result.value());
    REQUIRE(pol.has_value());
    REQUIRE(pol->has_value());
    CHECK((*pol)->enabled == true);
}

TEST_CASE("PolicyStore: enable/disable nonexistent policy", "[policy_store][pg][policy]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto r = store.enable_policy("does-not-exist");
    REQUIRE(!r.has_value());
    CHECK(r.error() == "policy not found");

    auto r2 = store.disable_policy("does-not-exist");
    REQUIRE(!r2.has_value());
    CHECK(r2.error() == "policy not found");
}

TEST_CASE("PolicyStore: delete policy cascades", "[policy_store][pg][policy]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());

    auto pol_result = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol_result.has_value());

    (void)store.update_agent_status(pol_result.value(), "agent-1", "compliant");
    (void)store.update_agent_status(pol_result.value(), "agent-2", "non_compliant");

    CHECK(store.delete_policy(pol_result.value()) == true);

    auto gone_pol = store.get_policy(pol_result.value());
    REQUIRE(gone_pol.has_value());
    CHECK(*gone_pol == std::nullopt);

    auto gone_s1 = store.get_agent_status(pol_result.value(), "agent-1");
    REQUIRE(gone_s1.has_value());
    CHECK(*gone_s1 == std::nullopt);
    auto gone_s2 = store.get_agent_status(pol_result.value(), "agent-2");
    REQUIRE(gone_s2.has_value());
    CHECK(*gone_s2 == std::nullopt);

    auto cs = store.get_compliance_summary(pol_result.value());
    REQUIRE(cs.has_value());
    CHECK(cs->total == 0);

    CHECK(store.delete_policy(pol_result.value()) == false);
}

TEST_CASE("PolicyStore: create policy with empty YAML", "[policy_store][pg][policy]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto r = store.create_policy("");
    REQUIRE(!r.has_value());
    CHECK(r.error() == "yaml_source is required");
}

TEST_CASE("PolicyStore: create policy with wrong kind", "[policy_store][pg][policy]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto r = store.create_policy("kind: PolicyFragment\nname: wrong\n");
    REQUIRE(!r.has_value());
    CHECK(r.error().find("kind must be 'Policy'") != std::string::npos);
    CHECK(r.error().find("apiVersion: yuzu.io/v1alpha1") != std::string::npos);
    CHECK(r.error().find("docs/user-manual/policy-engine.md") != std::string::npos);
}

TEST_CASE("PolicyStore: create policy with missing kind", "[policy_store][pg][policy]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto r = store.create_policy("name: no-kind\ndescription: missing kind field\n");
    REQUIRE(!r.has_value());
    CHECK(r.error().find("kind must be 'Policy'") != std::string::npos);
    CHECK(r.error().find("apiVersion: yuzu.io/v1alpha1") != std::string::npos);
    CHECK(r.error().find("docs/user-manual/policy-engine.md") != std::string::npos);
}

TEST_CASE("PolicyStore: create policy with missing fragment", "[policy_store][pg][policy]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto yaml = make_policy_yaml("nonexistent-fragment-id");
    auto r = store.create_policy(yaml);
    REQUIRE(!r.has_value());
    CHECK(r.error().find("not found") != std::string::npos);
}

TEST_CASE("PolicyStore: create policy without fragment field", "[policy_store][pg][policy]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    std::string yaml = R"(
apiVersion: yuzu.io/v1alpha1
kind: Policy
displayName: No Fragment
description: missing fragment field
)";
    auto r = store.create_policy(yaml);
    REQUIRE(!r.has_value());
    CHECK(r.error().find("fragment") != std::string::npos);
}

// ============================================================================
// Degrade behaviour — detail-query failures (adversarial review, round 2)
// ============================================================================

TEST_CASE("PolicyStore: get_policy/query_policies degrade on a detail-table failure, "
          "never a partial policy",
          "[policy_store][pg][failclosed]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto yaml = make_policy_yaml(frag.value(), "Detail-Degrade Policy");
    auto pol = store.create_policy(yaml);
    REQUIRE(pol.has_value());

    // Sanity: the policy has real details before the table is dropped.
    auto before = store.get_policy(pol.value());
    REQUIRE(before.has_value());
    REQUIRE(before->has_value());
    REQUIRE((*before)->triggers.size() == 2);

    // OWN clone: drops the triggers table out from under the live store —
    // a reproducible stand-in for a transient connection loss / botched
    // migration (same mechanism test_tag_store.cpp uses).
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult r{PQexec(conn.get(), "DROP TABLE policy_store.policy_triggers CASCADE")};
        REQUIRE(r.ok());
    }

    CHECK_FALSE(store.get_policy(pol.value()).has_value());
    CHECK_FALSE(store.query_policies().has_value());
}

// ============================================================================
// Compliance tracking
// ============================================================================

TEST_CASE("PolicyStore: update and get agent status", "[policy_store][pg][compliance]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol.has_value());

    auto r = store.update_agent_status(pol.value(), "agent-1", "compliant", "{\"status\":\"ok\"}");
    REQUIRE(r.has_value());

    auto status = store.get_agent_status(pol.value(), "agent-1");
    REQUIRE(status.has_value());
    REQUIRE(status->has_value());
    CHECK((*status)->policy_id == pol.value());
    CHECK((*status)->agent_id == "agent-1");
    CHECK((*status)->status == "compliant");
    CHECK((*status)->check_result == "{\"status\":\"ok\"}");
    CHECK((*status)->last_check_at > 0);
}

TEST_CASE("PolicyStore: update agent status overwrites", "[policy_store][pg][compliance]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol.has_value());

    (void)store.update_agent_status(pol.value(), "agent-1", "unknown");
    (void)store.update_agent_status(pol.value(), "agent-1", "compliant");

    auto status = store.get_agent_status(pol.value(), "agent-1");
    REQUIRE(status.has_value());
    REQUIRE(status->has_value());
    CHECK((*status)->status == "compliant");
}

TEST_CASE("PolicyStore: update agent status with invalid status", "[policy_store][pg][compliance]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto r = store.update_agent_status("pol-1", "agent-1", "garbage");
    REQUIRE(!r.has_value());
    CHECK(r.error().find("invalid status") != std::string::npos);
}

TEST_CASE("PolicyStore: update agent status with empty IDs", "[policy_store][pg][compliance]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto r1 = store.update_agent_status("", "agent-1", "compliant");
    REQUIRE(!r1.has_value());

    auto r2 = store.update_agent_status("pol-1", "", "compliant");
    REQUIRE(!r2.has_value());
}

TEST_CASE("PolicyStore: fix retry cap forces error after 3 fixing transitions",
          "[policy_store][pg][compliance]") {
    // ADR-0056: the retry-cap check folds into the UPSERT itself — this is
    // the regression test for that fold (previously a separate pre-check
    // SELECT, now a CASE inside the same statement).
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol.has_value());

    // Seed the row via a non-'fixing' write first (the fresh-INSERT branch
    // always starts fix_attempt_count at 0 regardless of status, so seeding
    // with 'fixing' directly would consume one attempt "for free" outside
    // the increment CASE — matches the evaluator's own remediate() flow,
    // which always writes a check verdict before any fix is ever attempted).
    REQUIRE(store.update_agent_status(pol.value(), "agent-1", "non_compliant").has_value());

    for (int i = 0; i < 3; ++i) {
        auto r = store.update_agent_status(pol.value(), "agent-1", "fixing");
        REQUIRE(r.has_value());
        auto s = store.get_agent_status(pol.value(), "agent-1");
        REQUIRE(s.has_value());
        REQUIRE(s->has_value());
        CHECK((*s)->status == "fixing");
    }
    // 4th attempt exceeds the cap (kMaxFixAttempts=3) and is forced to error.
    auto r = store.update_agent_status(pol.value(), "agent-1", "fixing");
    REQUIRE(r.has_value());
    auto s = store.get_agent_status(pol.value(), "agent-1");
    REQUIRE(s.has_value());
    REQUIRE(s->has_value());
    CHECK((*s)->status == "error");

    // A compliant result resets the counter — fixing is allowed again.
    REQUIRE(store.update_agent_status(pol.value(), "agent-1", "compliant").has_value());
    REQUIRE(store.update_agent_status(pol.value(), "agent-1", "fixing").has_value());
    auto s2 = store.get_agent_status(pol.value(), "agent-1");
    REQUIRE(s2.has_value());
    REQUIRE(s2->has_value());
    CHECK((*s2)->status == "fixing");
}

TEST_CASE("PolicyStore: get compliance summary", "[policy_store][pg][compliance]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol.has_value());

    (void)store.update_agent_status(pol.value(), "agent-1", "compliant");
    (void)store.update_agent_status(pol.value(), "agent-2", "compliant");
    (void)store.update_agent_status(pol.value(), "agent-3", "non_compliant");
    (void)store.update_agent_status(pol.value(), "agent-4", "unknown");
    (void)store.update_agent_status(pol.value(), "agent-5", "fixing");
    (void)store.update_agent_status(pol.value(), "agent-6", "error");

    auto cs = store.get_compliance_summary(pol.value());
    REQUIRE(cs.has_value());
    CHECK(cs->policy_id == pol.value());
    CHECK(cs->compliant == 2);
    CHECK(cs->non_compliant == 1);
    CHECK(cs->unknown == 1);
    CHECK(cs->fixing == 1);
    CHECK(cs->error == 1);
    CHECK(cs->total == 6);
}

TEST_CASE("PolicyStore: get compliance summary for empty policy",
          "[policy_store][pg][compliance]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto cs = store.get_compliance_summary("nonexistent");
    REQUIRE(cs.has_value());
    CHECK(cs->policy_id == "nonexistent");
    CHECK(cs->total == 0);
    CHECK(cs->compliant == 0);
}

TEST_CASE("PolicyStore: get fleet compliance", "[policy_store][pg][compliance]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol.has_value());

    (void)store.update_agent_status(pol.value(), "agent-1", "compliant");
    (void)store.update_agent_status(pol.value(), "agent-2", "compliant");
    (void)store.update_agent_status(pol.value(), "agent-3", "non_compliant");
    (void)store.update_agent_status(pol.value(), "agent-4", "compliant");

    auto fc = store.get_fleet_compliance();
    REQUIRE(fc.has_value());
    CHECK(fc->total_checks == 4);
    CHECK(fc->compliant == 3);
    CHECK(fc->non_compliant == 1);
    // 3/4 = 75%
    CHECK(fc->compliance_pct > 74.9);
    CHECK(fc->compliance_pct < 75.1);
}

TEST_CASE("PolicyStore: get fleet compliance with no data", "[policy_store][pg][compliance]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto fc = store.get_fleet_compliance();
    REQUIRE(fc.has_value());
    CHECK(fc->total_checks == 0);
    CHECK(fc->compliance_pct == 0.0);
}

TEST_CASE("PolicyStore: fleet compliance cache is invalidated on the store's "
          "own writes (adversarial review K7, 2026-08-24)",
          "[policy_store][pg][compliance]") {
    // Regression for the eighth-correction fix: get_fleet_compliance()'s 60s
    // TTL cache was never cleared by update_agent_status/invalidate_policy/
    // invalidate_all_policies, so a status change could read back through
    // the aggregate as stale for up to a minute (ADR-0012 §4 rule 2). This
    // pins that a write immediately followed by a read sees the new value,
    // not the cached one — both calls land well inside the 60s TTL, so a
    // pass here is only possible if the write actually invalidated the
    // cache rather than the TTL happening to have expired.
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol.has_value());

    REQUIRE(store.update_agent_status(pol.value(), "agent-1", "compliant").has_value());

    // Populate the cache with the all-compliant picture.
    auto fc1 = store.get_fleet_compliance();
    REQUIRE(fc1.has_value());
    CHECK(fc1->compliant == 1);
    CHECK(fc1->non_compliant == 0);

    // The store's own write should invalidate that cache entry.
    REQUIRE(store.update_agent_status(pol.value(), "agent-1", "non_compliant").has_value());

    auto fc2 = store.get_fleet_compliance();
    REQUIRE(fc2.has_value());
    CHECK(fc2->compliant == 0);
    CHECK(fc2->non_compliant == 1);
}

TEST_CASE("PolicyStore: get policy agent statuses", "[policy_store][pg][compliance]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol.has_value());

    (void)store.update_agent_status(pol.value(), "agent-1", "compliant");
    (void)store.update_agent_status(pol.value(), "agent-2", "non_compliant");

    auto statuses = store.get_policy_agent_statuses(pol.value());
    REQUIRE(statuses.has_value());
    REQUIRE(statuses->size() == 2);
    CHECK((*statuses)[0].agent_id == "agent-1");
    CHECK((*statuses)[0].status == "compliant");
    CHECK((*statuses)[1].agent_id == "agent-2");
    CHECK((*statuses)[1].status == "non_compliant");
}

TEST_CASE("PolicyStore: fixing status updates last_fix_at", "[policy_store][pg][compliance]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol.has_value());

    (void)store.update_agent_status(pol.value(), "agent-1", "non_compliant");
    auto s1 = store.get_agent_status(pol.value(), "agent-1");
    REQUIRE(s1.has_value());
    REQUIRE(s1->has_value());
    CHECK((*s1)->last_fix_at == 0);

    (void)store.update_agent_status(pol.value(), "agent-1", "fixing");
    auto s2 = store.get_agent_status(pol.value(), "agent-1");
    REQUIRE(s2.has_value());
    REQUIRE(s2->has_value());
    CHECK((*s2)->last_fix_at > 0);
}

// ============================================================================
// Cache invalidation
// ============================================================================

TEST_CASE("PolicyStore: invalidate policy resets statuses", "[policy_store][pg][invalidation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol.has_value());

    (void)store.update_agent_status(pol.value(), "agent-1", "compliant");
    (void)store.update_agent_status(pol.value(), "agent-2", "non_compliant");
    (void)store.update_agent_status(pol.value(), "agent-3", "error");

    auto r = store.invalidate_policy(pol.value());
    REQUIRE(r.has_value());
    CHECK(r.value() == 3);

    for (const char* agent : {"agent-1", "agent-2", "agent-3"}) {
        auto s = store.get_agent_status(pol.value(), agent);
        REQUIRE(s.has_value());
        REQUIRE(s->has_value());
        CHECK((*s)->status == "unknown");
    }
}

TEST_CASE("PolicyStore: invalidate policy clears a capped fix_attempt_count "
          "(adversarial review K2, 2026-08-24)",
          "[policy_store][pg][invalidation]") {
    // Regression for the eighth-correction fix: invalidate_policy() only
    // reset `status` to 'unknown', leaving fix_attempt_count at the cap —
    // remediate() dispatches the fix before marking 'fixing' (gov UP-7), so
    // the fix genuinely runs, but the very next update_agent_status('fixing')
    // immediately flipped straight to 'error' because the stale counter was
    // still >= kMaxFixAttempts, misrepresenting a real remediation attempt
    // as already-failed.
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol.has_value());

    // Drive fix_attempt_count to the cap, same as the sibling cap test above.
    REQUIRE(store.update_agent_status(pol.value(), "agent-1", "non_compliant").has_value());
    for (int i = 0; i < 3; ++i)
        REQUIRE(store.update_agent_status(pol.value(), "agent-1", "fixing").has_value());
    auto capped = store.get_agent_status(pol.value(), "agent-1");
    REQUIRE(capped.has_value());
    REQUIRE(capped->has_value());
    CHECK((*capped)->status == "fixing"); // 3rd attempt, still under the cap

    // One more 'fixing' write confirms the cap is live before invalidation.
    REQUIRE(store.update_agent_status(pol.value(), "agent-1", "fixing").has_value());
    auto pre = store.get_agent_status(pol.value(), "agent-1");
    REQUIRE(pre.has_value());
    REQUIRE(pre->has_value());
    CHECK((*pre)->status == "error");

    auto inv = store.invalidate_policy(pol.value());
    REQUIRE(inv.has_value());

    // The next remediation's 'fixing' write must NOT immediately flip back
    // to 'error' — that would mean invalidation didn't actually reset the
    // lifecycle, only the visible status field.
    REQUIRE(store.update_agent_status(pol.value(), "agent-1", "fixing").has_value());
    auto post = store.get_agent_status(pol.value(), "agent-1");
    REQUIRE(post.has_value());
    REQUIRE(post->has_value());
    CHECK((*post)->status == "fixing");
}

TEST_CASE("PolicyStore: invalidate nonexistent policy returns 0",
          "[policy_store][pg][invalidation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto r = store.invalidate_policy("does-not-exist");
    REQUIRE(r.has_value());
    CHECK(r.value() == 0);
}

TEST_CASE("PolicyStore: invalidate empty policy ID", "[policy_store][pg][invalidation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto r = store.invalidate_policy("");
    REQUIRE(!r.has_value());
    CHECK(r.error().find("required") != std::string::npos);
}

TEST_CASE("PolicyStore: invalidate all policies", "[policy_store][pg][invalidation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());

    auto pol1 = store.create_policy(make_policy_yaml(frag.value(), "Policy A"));
    auto pol2 = store.create_policy(make_policy_yaml(frag.value(), "Policy B"));
    REQUIRE(pol1.has_value());
    REQUIRE(pol2.has_value());

    (void)store.update_agent_status(pol1.value(), "agent-1", "compliant");
    (void)store.update_agent_status(pol1.value(), "agent-2", "non_compliant");
    (void)store.update_agent_status(pol2.value(), "agent-3", "compliant");

    auto r = store.invalidate_all_policies();
    REQUIRE(r.has_value());
    CHECK(r.value() == 3);

    auto s1 = store.get_agent_status(pol1.value(), "agent-1");
    REQUIRE(s1.has_value());
    REQUIRE(s1->has_value());
    CHECK((*s1)->status == "unknown");

    auto s3 = store.get_agent_status(pol2.value(), "agent-3");
    REQUIRE(s3.has_value());
    REQUIRE(s3->has_value());
    CHECK((*s3)->status == "unknown");
}

TEST_CASE("PolicyStore: invalidate all with no data returns 0",
          "[policy_store][pg][invalidation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto r = store.invalidate_all_policies();
    REQUIRE(r.has_value());
    CHECK(r.value() == 0);
}

// ============================================================================
// Policy YAML parsing edge cases
// ============================================================================

TEST_CASE("PolicyStore: policy with multiple triggers and groups",
          "[policy_store][pg][policy][yaml]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());

    std::string yaml = R"(
apiVersion: yuzu.io/v1alpha1
kind: Policy
displayName: Multi Trigger Policy
description: Policy with many triggers and groups
fragment: )" + frag.value() + R"(
scope: "tags.env == 'prod'"
inputs:
  service: Spooler
  timeout: "60"
triggers:
  - type: interval
    interval_seconds: 600
  - type: file_change
    path: "C:\\config.yaml"
  - type: event_log
    event_source: System
    event_id: "7036"
managementGroups:
  - "all-devices"
  - "windows-servers"
  - "us-east-region"
)";

    auto result = store.create_policy(yaml);
    REQUIRE(result.has_value());

    auto pol = store.get_policy(result.value());
    REQUIRE(pol.has_value());
    REQUIRE(pol->has_value());

    REQUIRE((*pol)->inputs.size() == 2);
    REQUIRE((*pol)->triggers.size() == 3);
    REQUIRE((*pol)->management_groups.size() == 3);
}

TEST_CASE("PolicyStore: get nonexistent fragment returns nullopt",
          "[policy_store][pg][fragment]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};
    auto r = store.get_fragment("does-not-exist");
    REQUIRE(r.has_value());
    CHECK(*r == std::nullopt);
}

TEST_CASE("PolicyStore: get nonexistent policy returns nullopt", "[policy_store][pg][policy]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};
    auto r = store.get_policy("does-not-exist");
    REQUIRE(r.has_value());
    CHECK(*r == std::nullopt);
}

TEST_CASE("PolicyStore: get nonexistent agent status returns nullopt",
          "[policy_store][pg][compliance]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};
    auto r = store.get_agent_status("pol", "agent");
    REQUIRE(r.has_value());
    CHECK(*r == std::nullopt);
}

// ── Duplicate-name guard (#396) ──────────────────────────────────────────

TEST_CASE("PolicyStore: duplicate fragment name rejected with conflict prefix",
          "[policy_store][pg][fragment][duplicate]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto first = store.create_fragment(kCheckOnlyNoFix);
    REQUIRE(first.has_value());

    auto second = store.create_fragment(kCheckOnlyNoFix);
    REQUIRE_FALSE(second.has_value());
    CHECK(is_conflict_error(second.error()));

    auto fragments = store.query_fragments({});
    REQUIRE(fragments.has_value());
    int matches = 0;
    for (const auto& f : *fragments)
        if (f.name == "Check Only Fragment")
            ++matches;
    CHECK(matches == 1);
}

// ============================================================================
// Backfill (ADR-0009 / ADR-0056)
// ============================================================================

TEST_CASE("PolicyStore::migrate_from_sqlite: no legacy file is idempotent",
          "[policy_store][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto missing = yuzu::test::unique_temp_path("yuzu_test_polstore_missing") / "policies.db";
    CHECK(store.migrate_from_sqlite(missing));
    CHECK(store.migrate_from_sqlite(missing)); // second call is a no-op success
}

TEST_CASE("migrate_from_sqlite: a sourceless boot never blocks a later boot's real legacy data",
          "[policy_store][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto missing_path =
        yuzu::test::unique_temp_path("yuzu_test_polstore_sourceless") / "policies.db";
    REQUIRE(store.migrate_from_sqlite(missing_path));

    PolicyFragment frag;
    frag.id = "holder-frag";
    frag.name = "Holder Fragment";
    frag.yaml_source = "kind: PolicyFragment";
    frag.created_at = 100;
    frag.updated_at = 100;
    auto holder_path = yuzu::test::unique_temp_path("yuzu_test_polstore_holder") / "policies.db";
    std::filesystem::create_directories(holder_path.parent_path());
    write_legacy_policy_sqlite_db(holder_path, {frag}, {}, {}, {}, {}, {});

    REQUIRE(store.migrate_from_sqlite(holder_path));

    auto got = store.get_fragment("holder-frag");
    REQUIRE(got.has_value());
    REQUIRE(got->has_value());
    CHECK((*got)->name == "Holder Fragment");
}

TEST_CASE("migrate_from_sqlite copies a populated legacy snapshot across all tables",
          "[policy_store][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    PolicyFragment frag;
    frag.id = "bfrag-1";
    frag.name = "Backfilled Fragment";
    frag.yaml_source = "kind: PolicyFragment";
    frag.check_instruction = "get_service_status";
    frag.check_compliance = "result.status == 'running'";
    frag.check_parameters = "{}";
    frag.fix_parameters = "{}";
    frag.post_check_parameters = "{}";
    frag.created_at = 1000;
    frag.updated_at = 1000;

    Policy pol;
    pol.id = "bpol-1";
    pol.name = "Backfilled Policy";
    pol.yaml_source = "kind: Policy";
    pol.fragment_id = frag.id;
    pol.scope_expression = "ostype == \"windows\"";
    pol.enabled = true;
    pol.created_at = 1001;
    pol.updated_at = 1001;

    PolicyInput inp;
    inp.policy_id = pol.id;
    inp.key = "service";
    inp.value = "Spooler";

    PolicyTrigger trg;
    trg.policy_id = pol.id;
    trg.trigger_type = "interval";
    trg.config_json = R"({"interval_seconds":600})";

    PolicyGroupBinding grp;
    grp.policy_id = pol.id;
    grp.group_id = "all-devices";

    LegacyStatusRow status;
    status.policy_id = pol.id;
    status.agent_id = "agent-1";
    status.status = "compliant";
    status.last_check_at = 1002;
    status.check_result = "{}";
    status.fix_attempt_count = 0;

    auto legacy_path =
        yuzu::test::unique_temp_path("yuzu_test_polstore_populated") / "policies.db";
    std::filesystem::create_directories(legacy_path.parent_path());
    write_legacy_policy_sqlite_db(legacy_path, {frag}, {pol}, {inp}, {trg}, {grp}, {status});

    REQUIRE(store.migrate_from_sqlite(legacy_path));

    auto got_frag = store.get_fragment(frag.id);
    REQUIRE(got_frag.has_value());
    REQUIRE(got_frag->has_value());
    CHECK((*got_frag)->name == "Backfilled Fragment");

    auto got_pol = store.get_policy(pol.id);
    REQUIRE(got_pol.has_value());
    REQUIRE(got_pol->has_value());
    CHECK((*got_pol)->name == "Backfilled Policy");
    REQUIRE((*got_pol)->inputs.size() == 1);
    CHECK((*got_pol)->inputs[0].value == "Spooler");
    REQUIRE((*got_pol)->triggers.size() == 1);
    REQUIRE((*got_pol)->management_groups.size() == 1);
    CHECK((*got_pol)->management_groups[0] == "all-devices");

    auto got_status = store.get_agent_status(pol.id, "agent-1");
    REQUIRE(got_status.has_value());
    REQUIRE(got_status->has_value());
    CHECK((*got_status)->status == "compliant");

    // Second call against the same populated file is a no-op (fingerprint-gated).
    REQUIRE(store.migrate_from_sqlite(legacy_path));
    auto frags = store.query_fragments();
    REQUIRE(frags.has_value());
    CHECK(frags->size() == 1);
}

TEST_CASE("migrate_from_sqlite never rewinds a status Postgres has already advanced past",
          "[policy_store][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    PolicyFragment frag;
    frag.id = "bfrag-guard-1";
    frag.name = "Guard Fragment";
    frag.yaml_source = "kind: PolicyFragment";
    frag.check_instruction = "get_service_status";
    frag.check_compliance = "result.status == 'running'";
    frag.check_parameters = "{}";
    frag.fix_parameters = "{}";
    frag.post_check_parameters = "{}";
    frag.created_at = 1000;
    frag.updated_at = 1000;

    Policy pol;
    pol.id = "bpol-guard-1";
    pol.name = "Guard Policy";
    pol.yaml_source = "kind: Policy";
    pol.fragment_id = frag.id;
    pol.scope_expression = "ostype == \"windows\"";
    pol.enabled = true;
    pol.created_at = 1001;
    pol.updated_at = 1001;

    LegacyStatusRow status;
    status.policy_id = pol.id;
    status.agent_id = "agent-1";
    status.status = "compliant";
    status.last_check_at = 1002; // fake, far-past epoch
    status.check_result = "{}";
    status.fix_attempt_count = 0;

    auto legacy_path =
        yuzu::test::unique_temp_path("yuzu_test_polstore_guard") / "policies.db";
    std::filesystem::create_directories(legacy_path.parent_path());
    write_legacy_policy_sqlite_db(legacy_path, {frag}, {pol}, {}, {}, {}, {status});

    REQUIRE(store.migrate_from_sqlite(legacy_path));
    auto got = store.get_agent_status(pol.id, "agent-1");
    REQUIRE(got.has_value());
    REQUIRE(got->has_value());
    CHECK((*got)->status == "compliant");

    // Postgres advances past the legacy snapshot via ordinary live traffic
    // (real wall-clock last_check_at, far later than the legacy 1002).
    REQUIRE(store.update_agent_status(pol.id, "agent-1", "non_compliant"));
    auto advanced = store.get_agent_status(pol.id, "agent-1");
    REQUIRE(advanced.has_value());
    REQUIRE(advanced->has_value());
    CHECK((*advanced)->status == "non_compliant");
    int64_t advanced_last_check = (*advanced)->last_check_at;

    // Re-running the SAME legacy backfill (e.g. a restart while the legacy
    // file is still present) must NOT rewind live compliance data back to
    // the stale snapshot — the direction-aware WHERE guard
    // (last_check_at < EXCLUDED.last_check_at) makes this a no-op.
    REQUIRE(store.migrate_from_sqlite(legacy_path));
    auto after = store.get_agent_status(pol.id, "agent-1");
    REQUIRE(after.has_value());
    REQUIRE(after->has_value());
    CHECK((*after)->status == "non_compliant");
    CHECK((*after)->last_check_at == advanced_last_check);
}

TEST_CASE("migrate_from_sqlite fails closed on a legacy-ahead status row (adversarial review)",
          "[policy_store][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    PolicyFragment frag;
    frag.id = "bfrag-legacy-ahead-1";
    frag.name = "Legacy-Ahead Fragment";
    frag.yaml_source = "kind: PolicyFragment";
    frag.check_instruction = "get_service_status";
    frag.check_compliance = "result.status == 'running'";
    frag.check_parameters = "{}";
    frag.fix_parameters = "{}";
    frag.post_check_parameters = "{}";
    frag.created_at = 1000;
    frag.updated_at = 1000;

    Policy pol;
    pol.id = "bpol-legacy-ahead-1";
    pol.name = "Legacy-Ahead Policy";
    pol.yaml_source = "kind: Policy";
    pol.fragment_id = frag.id;
    pol.scope_expression = "ostype == \"windows\"";
    pol.enabled = true;
    pol.created_at = 1001;
    pol.updated_at = 1001;

    // First backfill: identity only, no status row — lands the policy in
    // Postgres so update_agent_status (FK'd to policies) can write to it.
    auto legacy_path =
        yuzu::test::unique_temp_path("yuzu_test_polstore_legacy_ahead") / "policies.db";
    std::filesystem::create_directories(legacy_path.parent_path());
    write_legacy_policy_sqlite_db(legacy_path, {frag}, {pol}, {}, {}, {}, {});
    REQUIRE(store.migrate_from_sqlite(legacy_path));

    // Postgres accumulates live evaluator status via ordinary traffic.
    REQUIRE(store.update_agent_status(pol.id, "agent-1", "compliant"));
    auto seeded = store.get_agent_status(pol.id, "agent-1");
    REQUIRE(seeded.has_value());
    REQUIRE(seeded->has_value());
    CHECK((*seeded)->status == "compliant");
    const int64_t seeded_last_check = (*seeded)->last_check_at;

    // A second legacy file (SAME fragment/policy content — same fingerprint,
    // so the identity block is skipped as already-processed; only the
    // status merge runs) carries a status row whose last_check_at is far
    // ahead of what Postgres just wrote — simulating an independently
    // advanced or restored legacy snapshot.
    LegacyStatusRow ahead_status;
    ahead_status.policy_id = pol.id;
    ahead_status.agent_id = "agent-1";
    ahead_status.status = "non_compliant";
    ahead_status.last_check_at = seeded_last_check + 1'000'000; // far ahead
    ahead_status.check_result = "{}";
    ahead_status.fix_attempt_count = 0;

    auto legacy_path2 =
        yuzu::test::unique_temp_path("yuzu_test_polstore_legacy_ahead2") / "policies.db";
    std::filesystem::create_directories(legacy_path2.parent_path());
    write_legacy_policy_sqlite_db(legacy_path2, {frag}, {pol}, {}, {}, {}, {ahead_status});

    // Must fail closed — never silently overwrite live post-cutover status
    // with an independently-advanced or restored legacy snapshot.
    CHECK_FALSE(store.migrate_from_sqlite(legacy_path2));

    auto after = store.get_agent_status(pol.id, "agent-1");
    REQUIRE(after.has_value());
    REQUIRE(after->has_value());
    CHECK((*after)->status == "compliant");
    CHECK((*after)->last_check_at == seeded_last_check);
}

TEST_CASE("migrate_from_sqlite fails closed when a differently-fingerprinted legacy file "
          "diverges from an already-landed backfill (adversarial review)",
          "[policy_store][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    PolicyFragment frag_a;
    frag_a.id = "bfrag-holder-1";
    frag_a.name = "Holder Fragment A";
    frag_a.yaml_source = "kind: PolicyFragment";
    frag_a.check_instruction = "get_service_status";
    frag_a.check_compliance = "result.status == 'running'";
    frag_a.check_parameters = "{}";
    frag_a.fix_parameters = "{}";
    frag_a.post_check_parameters = "{}";
    frag_a.created_at = 1000;
    frag_a.updated_at = 1000;

    Policy pol_a;
    pol_a.id = "bpol-holder-1";
    pol_a.name = "Holder Policy A";
    pol_a.yaml_source = "kind: Policy";
    pol_a.fragment_id = frag_a.id;
    pol_a.scope_expression = "ostype == \"windows\"";
    pol_a.enabled = true;
    pol_a.created_at = 1001;
    pol_a.updated_at = 1001;

    PolicyTrigger trg_a;
    trg_a.policy_id = pol_a.id;
    trg_a.trigger_type = "interval";
    trg_a.config_json = R"({"interval_seconds":600})";

    auto path_a = yuzu::test::unique_temp_path("yuzu_test_polstore_holder_a") / "policies.db";
    std::filesystem::create_directories(path_a.parent_path());
    write_legacy_policy_sqlite_db(path_a, {frag_a}, {pol_a}, {}, {trg_a}, {}, {});
    REQUIRE(store.migrate_from_sqlite(path_a));

    // A second, DIFFERENT legacy file — different fragment content (so a
    // different fingerprint), simulating a sibling replica with genuinely
    // different legacy content for the same store. Must be refused, not
    // silently merged (which would otherwise no-op the fragment/policy
    // identity rows and, worse, APPEND a second, duplicate trigger row for
    // pol_a since policy_triggers has no conflict target).
    PolicyFragment frag_b = frag_a;
    frag_b.description = "diverged content changes the fingerprint";

    PolicyTrigger trg_b;
    trg_b.policy_id = pol_a.id;
    trg_b.trigger_type = "interval";
    trg_b.config_json = R"({"interval_seconds":900})";

    auto path_b = yuzu::test::unique_temp_path("yuzu_test_polstore_holder_b") / "policies.db";
    std::filesystem::create_directories(path_b.parent_path());
    write_legacy_policy_sqlite_db(path_b, {frag_b}, {pol_a}, {}, {trg_b}, {}, {});

    CHECK_FALSE(store.migrate_from_sqlite(path_b));

    // The original trigger must be the ONLY one — no duplicate/appended row
    // from the refused second file.
    auto got_pol = store.get_policy(pol_a.id);
    REQUIRE(got_pol.has_value());
    REQUIRE(got_pol->has_value());
    REQUIRE((*got_pol)->triggers.size() == 1);
    CHECK((*got_pol)->triggers[0].config_json == trg_a.config_json);
}

TEST_CASE("migrate_from_sqlite tolerates a legacy file predating the fix_attempt_count "
          "ALTER-wart column (G4-UHP-POL-003)",
          "[policy_store][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    PolicyFragment frag;
    frag.id = "prewart-frag";
    frag.name = "Pre-Wart Fragment";
    frag.yaml_source = "kind: PolicyFragment";
    frag.check_parameters = "{}";
    frag.fix_parameters = "{}";
    frag.post_check_parameters = "{}";
    frag.created_at = 1;
    frag.updated_at = 1;

    Policy pol;
    pol.id = "prewart-pol";
    pol.name = "Pre-Wart Policy";
    pol.yaml_source = "kind: Policy";
    pol.fragment_id = frag.id;
    pol.enabled = true;
    pol.created_at = 2;
    pol.updated_at = 2;

    LegacyStatusRow status;
    status.policy_id = pol.id;
    status.agent_id = "agent-1";
    status.status = "fixing";
    status.last_check_at = 3;
    status.last_fix_at = 3;
    status.check_result = "{}";
    // fix_attempt_count deliberately not carried — the fixture DDL omits the
    // column entirely (with_fix_attempt_count=false below).

    auto legacy_path =
        yuzu::test::unique_temp_path("yuzu_test_polstore_prewart") / "policies.db";
    std::filesystem::create_directories(legacy_path.parent_path());
    write_legacy_policy_sqlite_db(legacy_path, {frag}, {pol}, {}, {}, {}, {status},
                                  /*with_fix_attempt_count=*/false);

    REQUIRE(store.migrate_from_sqlite(legacy_path));

    auto got = store.get_agent_status(pol.id, "agent-1");
    REQUIRE(got.has_value());
    REQUIRE(got->has_value());
    CHECK((*got)->status == "fixing");

    // fix_attempt_count defaulted to 0 (the same value the SQLite ALTER's
    // own `DEFAULT 0` would have produced) — a further 3 "fixing" calls
    // must still be allowed before the retry cap forces 'error'.
    for (int i = 0; i < 3; ++i)
        REQUIRE(store.update_agent_status(pol.id, "agent-1", "fixing").has_value());
    REQUIRE(store.update_agent_status(pol.id, "agent-1", "fixing").has_value());
    auto after = store.get_agent_status(pol.id, "agent-1");
    REQUIRE(after.has_value());
    REQUIRE(after->has_value());
    CHECK((*after)->status == "error");
}

TEST_CASE("migrate_from_sqlite fails closed on a legacy file with a partial schema",
          "[policy_store][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto legacy_path = yuzu::test::unique_temp_path("yuzu_test_polstore_partial") / "policies.db";
    std::filesystem::create_directories(legacy_path.parent_path());
    SqliteDb legacy;
    REQUIRE(sqlite3_open(legacy_path.string().c_str(), legacy.addr()) == SQLITE_OK);
    // Only policy_fragments exists — the shipped store always creates all
    // five tables together, so this is corruption, not a real upgrade
    // artifact.
    REQUIRE(sqlite3_exec(legacy.get(),
                        "CREATE TABLE policy_fragments (id TEXT PRIMARY KEY, name TEXT);",
                        nullptr, nullptr, nullptr) == SQLITE_OK);
    legacy.close();

    CHECK_FALSE(store.migrate_from_sqlite(legacy_path));
}

// ============================================================================
// claim_due_policies (ADR-0056) — single-instance coverage
// ============================================================================

TEST_CASE("claim_due_policies claims a due policy once, then not again within the interval",
          "[policy_store][pg][claim]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    std::string yaml = R"(
apiVersion: yuzu.io/v1alpha1
kind: Policy
displayName: Claim Test Policy
fragment: )" + frag.value() + R"(
scope: "tags.env == 'prod'"
triggers:
  - type: interval
    interval_seconds: 3600
)";
    auto pol = store.create_policy(yaml);
    REQUIRE(pol.has_value());

    int64_t t0 = 1000000;
    auto claimed1 = store.claim_due_policies(t0, 3600, 1800);
    REQUIRE(claimed1.has_value());
    REQUIRE(claimed1->size() == 1);
    CHECK((*claimed1)[0].id == pol.value());

    // A second claim moments later (still within the 3600s interval) claims
    // nothing — the WHERE-on-conflict guard is the atomic check-and-claim.
    auto claimed2 = store.claim_due_policies(t0 + 10, 3600, 1800);
    REQUIRE(claimed2.has_value());
    CHECK(claimed2->empty());

    // After the interval elapses, it is due again.
    auto claimed3 = store.claim_due_policies(t0 + 3601, 3600, 1800);
    REQUIRE(claimed3.has_value());
    REQUIRE(claimed3->size() == 1);
}

TEST_CASE("claim_due_policies does not claim a disabled policy",
          "[policy_store][pg][claim]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol.has_value());
    REQUIRE(store.disable_policy(pol.value()).has_value());

    auto claimed = store.claim_due_policies(1000000, 3600, 1800);
    REQUIRE(claimed.has_value());
    CHECK(claimed->empty());
}

TEST_CASE("claim_due_policies sweeps a stale 'fixing' row back to 'unknown'",
          "[policy_store][pg][claim]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PolicyStore store{pool};

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol.has_value());
    REQUIRE(store.update_agent_status(pol.value(), "agent-1", "fixing").has_value());

    // update_agent_status stamps last_fix_at from the REAL wall clock (it
    // has no injectable NowFn, unlike claim_due_policies) — t0 must be
    // real-clock-relative or the staleness comparison is meaningless.
    int64_t t0 = std::chrono::duration_cast<std::chrono::seconds>(
                     std::chrono::system_clock::now().time_since_epoch())
                     .count();
    // Within the staleness window: untouched.
    auto claimed1 = store.claim_due_policies(t0, 3600, 1800);
    REQUIRE(claimed1.has_value());
    auto s1 = store.get_agent_status(pol.value(), "agent-1");
    REQUIRE(s1.has_value());
    REQUIRE(s1->has_value());
    CHECK((*s1)->status == "fixing");

    // Past the staleness window: swept to 'unknown'.
    auto claimed2 = store.claim_due_policies(t0 + 1801, 3600, 1800);
    REQUIRE(claimed2.has_value());
    auto s2 = store.get_agent_status(pol.value(), "agent-1");
    REQUIRE(s2.has_value());
    REQUIRE(s2->has_value());
    CHECK((*s2)->status == "unknown");
}
