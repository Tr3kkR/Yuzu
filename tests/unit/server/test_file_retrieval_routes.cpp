// file_retrieval_routes.cpp end-to-end coverage over TestRouteSink (PR1.6a,
// CC-06 server-side fix): the operator mint/list/revoke surface, the agent
// session-open/chunk/status/commit/cancel surface, the TLS gate, and the
// frozen error envelope's reason set as actually emitted on the wire.
// Exercises the REAL UploadGrantStore against Postgres (YUZU_REQUIRE_PG_DB_TPL)
// — the store has no interface seam to mock, so this is the genuine
// end-to-end path, not a store double. Each TEST_CASE opens its own
// pre-migrated clone (per the playbook's per-test-clone contract for
// store-BEHAVIOUR-plus-mutation tests) and builds a fresh sink over it —
// no shared Catch2 fixture class, since `YUZU_REQUIRE_PG_DB_TPL`'s SKIP
// must run as a direct statement in the test body, not in a constructor.

#include <catch2/catch_test_macros.hpp>

#include "file_retrieval_routes.hpp"
#include "test_route_sink.hpp"
#include "upload_grant_store.hpp"

#include "pg/pg_pool.hpp"

#include "../test_helpers.hpp"

#include <nlohmann/json.hpp>

#include <filesystem>
#include <memory>
#include <stdexcept>
#include <string>

using yuzu::server::Deps;
using yuzu::server::UploadGrantListAuthorization;
using yuzu::server::UploadGrantListDecision;
using yuzu::server::UploadGrantStore;
using yuzu::server::pg::PgPool;
using yuzu::server::test::TestRouteSink;

namespace {

yuzu::test::PgTestTemplate routes_tpl{"uploadgrantroutes", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    UploadGrantStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("upload_grant routes template: store failed to migrate");
}};

/// Deps builder shared by every test case: "always admit" operator auth by
/// default, TLS on, and a clock the test controls through `*clock`. Callers
/// override individual fields on the returned struct for denial cases.
Deps make_deps(UploadGrantStore& store, const std::filesystem::path& blob_root,
               std::shared_ptr<std::int64_t> clock) {
    Deps deps;
    deps.auth_fn = [](const httplib::Request&, httplib::Response&) {
        return std::optional<yuzu::server::auth::Session>{
            yuzu::server::auth::Session{.username = "operator-1"}};
    };
    deps.perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                      const std::string&) { return true; };
    deps.list_read_fn = [](const std::string&) {
        return UploadGrantListAuthorization{UploadGrantListDecision::kAdmitAll, {}};
    };
    deps.audit_fn = [](const httplib::Request&, const std::string&, const std::string&,
                       const std::string&, const std::string&, const std::string&) { return true; };
    deps.store = &store;
    deps.blob_root = blob_root;
    deps.tls_enabled = true;
    deps.now_fn = [clock]() { return *clock; };
    return deps;
}

nlohmann::json body_json(const std::unique_ptr<httplib::Response>& res) {
    REQUIRE(res != nullptr);
    auto parsed = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(parsed.is_discarded());
    return parsed;
}

std::string content_range(std::int64_t start, std::int64_t end, std::int64_t total) {
    return "bytes " + std::to_string(start) + "-" + std::to_string(end) + "/" +
          std::to_string(total);
}

std::string mint_and_open(TestRouteSink& sink, const std::string& agent_id,
                          std::int64_t declared_max_size, std::string& out_upload_id,
                          std::optional<std::int64_t> ttl_secs = std::nullopt) {
    nlohmann::json body = {{"agent_id", agent_id}, {"declared_max_size", declared_max_size}};
    if (ttl_secs)
        body["ttl_secs"] = *ttl_secs;
    auto minted = body_json(sink.dispatch("POST", "/api/v1/upload-grants", body.dump()));
    const std::string grant_cred =
        minted["grant_id"].get<std::string>() + "." + minted["grant_secret"].get<std::string>();
    auto opened = body_json(sink.dispatch("POST", "/api/v1/uploads", "", "application/json",
                                          {{"X-Yuzu-Upload-Grant", grant_cred}}));
    out_upload_id = opened["upload_id"].get<std::string>();
    return out_upload_id + "." + opened["session_secret"].get<std::string>();
}

} // namespace

// ── Operator routes ─────────────────────────────────────────────────────

TEST_CASE("mint returns grant_id + grant_secret once, 201", "[server][routes][upload]") {
    YUZU_REQUIRE_PG_DB_TPL(db, routes_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    UploadGrantStore store{pool};
    REQUIRE(store.is_open());
    yuzu::test::TempDir blob_dir{"yuzu_test_upload_blobs_"};
    TestRouteSink sink;
    yuzu::server::register_file_retrieval_routes(
        sink, make_deps(store, blob_dir.path, std::make_shared<std::int64_t>(1000)));

    auto res = sink.dispatch(
        "POST", "/api/v1/upload-grants",
        nlohmann::json{{"agent_id", "agent-1"}, {"declared_max_size", 100}}.dump());
    REQUIRE(res != nullptr);
    CHECK(res->status == 201);
    auto j = body_json(res);
    CHECK_FALSE(j["grant_id"].get<std::string>().empty());
    CHECK(j["grant_secret"].get<std::string>().size() == 64);
}

TEST_CASE("mint denies when perm_fn refuses", "[server][routes][upload]") {
    YUZU_REQUIRE_PG_DB_TPL(db, routes_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    UploadGrantStore store{pool};
    REQUIRE(store.is_open());
    yuzu::test::TempDir blob_dir{"yuzu_test_upload_blobs_"};

    auto deps = make_deps(store, blob_dir.path, std::make_shared<std::int64_t>(1000));
    deps.perm_fn = [](const httplib::Request&, httplib::Response& res, const std::string&,
                      const std::string&) {
        res.status = 403;
        return false;
    };
    TestRouteSink sink;
    yuzu::server::register_file_retrieval_routes(sink, deps);

    auto res = sink.dispatch(
        "POST", "/api/v1/upload-grants",
        nlohmann::json{{"agent_id", "agent-1"}, {"declared_max_size", 100}}.dump());
    REQUIRE(res != nullptr);
    CHECK(res->status == 403);
}

TEST_CASE("list honours kDenyAll / kAdmitAll / kAdmitScoped visibility", "[server][routes][upload]") {
    YUZU_REQUIRE_PG_DB_TPL(db, routes_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    UploadGrantStore store{pool};
    REQUIRE(store.is_open());
    yuzu::test::TempDir blob_dir{"yuzu_test_upload_blobs_"};
    auto clock = std::make_shared<std::int64_t>(1000);

    TestRouteSink admit_all_sink;
    yuzu::server::register_file_retrieval_routes(admit_all_sink,
                                                 make_deps(store, blob_dir.path, clock));
    REQUIRE(admit_all_sink
                .dispatch("POST", "/api/v1/upload-grants",
                         nlohmann::json{{"agent_id", "agent-A"}, {"declared_max_size", 100}}.dump())
                ->status == 201);
    REQUIRE(admit_all_sink
                .dispatch("POST", "/api/v1/upload-grants",
                         nlohmann::json{{"agent_id", "agent-B"}, {"declared_max_size", 100}}.dump())
                ->status == 201);

    SECTION("kAdmitAll (default) sees everything") {
        auto res = admit_all_sink.dispatch("GET", "/api/v1/upload-grants");
        REQUIRE(res->status == 200);
        CHECK(body_json(res)["data"].size() >= 2);
    }

    SECTION("kDenyAll -> 403") {
        auto deps = make_deps(store, blob_dir.path, clock);
        deps.list_read_fn = [](const std::string&) {
            return UploadGrantListAuthorization{UploadGrantListDecision::kDenyAll, {}};
        };
        TestRouteSink deny_sink;
        yuzu::server::register_file_retrieval_routes(deny_sink, deps);
        auto res = deny_sink.dispatch("GET", "/api/v1/upload-grants");
        REQUIRE(res != nullptr);
        CHECK(res->status == 403);
    }

    SECTION("kAdmitScoped filters to the visible agent set") {
        auto deps = make_deps(store, blob_dir.path, clock);
        deps.list_read_fn = [](const std::string&) {
            return UploadGrantListAuthorization{UploadGrantListDecision::kAdmitScoped, {"agent-A"}};
        };
        TestRouteSink scoped_sink;
        yuzu::server::register_file_retrieval_routes(scoped_sink, deps);
        auto res = scoped_sink.dispatch("GET", "/api/v1/upload-grants");
        REQUIRE(res->status == 200);
        auto j = body_json(res);
        REQUIRE(j["data"].size() >= 1);
        for (auto& row : j["data"])
            CHECK(row["agent_id"] == "agent-A");
    }
}

TEST_CASE("revoke: 204 then 404 on replay", "[server][routes][upload]") {
    YUZU_REQUIRE_PG_DB_TPL(db, routes_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    UploadGrantStore store{pool};
    REQUIRE(store.is_open());
    yuzu::test::TempDir blob_dir{"yuzu_test_upload_blobs_"};
    TestRouteSink sink;
    yuzu::server::register_file_retrieval_routes(
        sink, make_deps(store, blob_dir.path, std::make_shared<std::int64_t>(1000)));

    auto minted = body_json(sink.dispatch(
        "POST", "/api/v1/upload-grants",
        nlohmann::json{{"agent_id", "agent-1"}, {"declared_max_size", 100}}.dump()));
    auto grant_id = minted["grant_id"].get<std::string>();

    auto res1 = sink.dispatch("DELETE", "/api/v1/upload-grants/" + grant_id);
    REQUIRE(res1 != nullptr);
    CHECK(res1->status == 204);

    auto res2 = sink.dispatch("DELETE", "/api/v1/upload-grants/" + grant_id);
    REQUIRE(res2 != nullptr);
    CHECK(res2->status == 404);
}

// ── Agent surface: TLS gate ──────────────────────────────────────────────

TEST_CASE("every agent route 400s tls_required when TLS is not enabled",
          "[server][routes][upload]") {
    YUZU_REQUIRE_PG_DB_TPL(db, routes_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    UploadGrantStore store{pool};
    REQUIRE(store.is_open());
    yuzu::test::TempDir blob_dir{"yuzu_test_upload_blobs_"};

    auto deps = make_deps(store, blob_dir.path, std::make_shared<std::int64_t>(1000));
    deps.tls_enabled = false; // the point of this test
    TestRouteSink sink;
    yuzu::server::register_file_retrieval_routes(sink, deps);

    auto assert_tls_required = [](const std::unique_ptr<httplib::Response>& res) {
        REQUIRE(res != nullptr);
        CHECK(res->status == 400);
        auto j = nlohmann::json::parse(res->body, nullptr, false);
        REQUIRE_FALSE(j.is_discarded());
        CHECK(j["error"]["reason"] == "tls_required");
    };

    assert_tls_required(sink.dispatch("POST", "/api/v1/uploads"));
    assert_tls_required(sink.dispatch("PUT", "/api/v1/uploads/" + std::string(32, 'a') + "/chunk"));
    assert_tls_required(sink.dispatch("GET", "/api/v1/uploads/" + std::string(32, 'a')));
    assert_tls_required(
        sink.dispatch("POST", "/api/v1/uploads/" + std::string(32, 'a') + "/commit"));
    assert_tls_required(sink.dispatch("DELETE", "/api/v1/uploads/" + std::string(32, 'a')));
}

// ── Agent surface: session open ──────────────────────────────────────────

TEST_CASE("session open: success, then a replay is grant_already_redeemed",
          "[server][routes][upload]") {
    YUZU_REQUIRE_PG_DB_TPL(db, routes_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    UploadGrantStore store{pool};
    REQUIRE(store.is_open());
    yuzu::test::TempDir blob_dir{"yuzu_test_upload_blobs_"};
    TestRouteSink sink;
    yuzu::server::register_file_retrieval_routes(
        sink, make_deps(store, blob_dir.path, std::make_shared<std::int64_t>(1000)));

    auto minted = body_json(sink.dispatch(
        "POST", "/api/v1/upload-grants",
        nlohmann::json{{"agent_id", "agent-1"}, {"declared_max_size", 12}}.dump()));
    const std::string grant_cred =
        minted["grant_id"].get<std::string>() + "." + minted["grant_secret"].get<std::string>();

    auto opened = sink.dispatch("POST", "/api/v1/uploads", "", "application/json",
                                {{"X-Yuzu-Upload-Grant", grant_cred}});
    REQUIRE(opened != nullptr);
    REQUIRE(opened->status == 201);
    auto oj = body_json(opened);
    CHECK_FALSE(oj["upload_id"].get<std::string>().empty());
    CHECK(oj["session_secret"].get<std::string>().size() == 64);
    CHECK(oj["offset"] == 0);

    auto replay = sink.dispatch("POST", "/api/v1/uploads", "", "application/json",
                                {{"X-Yuzu-Upload-Grant", grant_cred}});
    REQUIRE(replay != nullptr);
    CHECK(replay->status == 409);
    CHECK(body_json(replay)["error"]["reason"] == "grant_already_redeemed");
}

TEST_CASE("session open with a wrong secret is grant_unknown, 401", "[server][routes][upload]") {
    YUZU_REQUIRE_PG_DB_TPL(db, routes_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    UploadGrantStore store{pool};
    REQUIRE(store.is_open());
    yuzu::test::TempDir blob_dir{"yuzu_test_upload_blobs_"};
    TestRouteSink sink;
    yuzu::server::register_file_retrieval_routes(
        sink, make_deps(store, blob_dir.path, std::make_shared<std::int64_t>(1000)));

    auto minted = body_json(sink.dispatch(
        "POST", "/api/v1/upload-grants",
        nlohmann::json{{"agent_id", "agent-1"}, {"declared_max_size", 12}}.dump()));
    const std::string bad_cred = minted["grant_id"].get<std::string>() + "." + std::string(64, 'f');

    auto res = sink.dispatch("POST", "/api/v1/uploads", "", "application/json",
                             {{"X-Yuzu-Upload-Grant", bad_cred}});
    REQUIRE(res != nullptr);
    CHECK(res->status == 401);
    CHECK(body_json(res)["error"]["reason"] == "grant_unknown");
}

// ── Agent surface: chunk / status / commit / cancel ──────────────────────

TEST_CASE("chunk + commit happy path, then a wrong-hash commit is hash_mismatch and terminal",
          "[server][routes][upload]") {
    YUZU_REQUIRE_PG_DB_TPL(db, routes_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    UploadGrantStore store{pool};
    REQUIRE(store.is_open());
    yuzu::test::TempDir blob_dir{"yuzu_test_upload_blobs_"};
    TestRouteSink sink;
    yuzu::server::register_file_retrieval_routes(
        sink, make_deps(store, blob_dir.path, std::make_shared<std::int64_t>(1000)));

    const std::string payload = "hello upload world!"; // 20 bytes
    std::string upload_id;
    const std::string session_cred =
        mint_and_open(sink, "agent-1", static_cast<std::int64_t>(payload.size()), upload_id);

    auto chunk_res = sink.dispatch(
        "PUT", "/api/v1/uploads/" + upload_id + "/chunk", payload, "application/octet-stream",
        {{"X-Yuzu-Upload-Session", session_cred},
         {"Content-Range", content_range(0, static_cast<std::int64_t>(payload.size()) - 1,
                                         static_cast<std::int64_t>(payload.size()))}});
    REQUIRE(chunk_res != nullptr);
    REQUIRE(chunk_res->status == 200);
    CHECK(body_json(chunk_res)["offset"] == static_cast<std::int64_t>(payload.size()));

    auto status_res = sink.dispatch("GET", "/api/v1/uploads/" + upload_id, "", "application/json",
                                    {{"X-Yuzu-Upload-Session", session_cred}});
    REQUIRE(status_res->status == 200);
    auto sj = body_json(status_res);
    CHECK(sj["state"] == "open");
    CHECK(sj["offset"] == static_cast<std::int64_t>(payload.size()));

    // Deliberately wrong hash — must 422 and terminate.
    auto bad_commit = sink.dispatch("POST", "/api/v1/uploads/" + upload_id + "/commit",
                                    nlohmann::json{{"sha256", std::string(64, '0')}}.dump(),
                                    "application/json",
                                    {{"X-Yuzu-Upload-Session", session_cred}});
    REQUIRE(bad_commit != nullptr);
    CHECK(bad_commit->status == 422);
    CHECK(body_json(bad_commit)["error"]["reason"] == "hash_mismatch");

    // Terminal now — even a subsequent commit attempt is session_terminal.
    auto retry = sink.dispatch("POST", "/api/v1/uploads/" + upload_id + "/commit",
                               nlohmann::json{{"sha256", std::string(64, '0')}}.dump(),
                               "application/json", {{"X-Yuzu-Upload-Session", session_cred}});
    REQUIRE(retry != nullptr);
    CHECK(retry->status == 409);
    CHECK(body_json(retry)["error"]["reason"] == "session_terminal");
}

TEST_CASE("commit succeeds with the correct sha256 and returns actual_size", "[server][routes][upload]") {
    YUZU_REQUIRE_PG_DB_TPL(db, routes_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    UploadGrantStore store{pool};
    REQUIRE(store.is_open());
    yuzu::test::TempDir blob_dir{"yuzu_test_upload_blobs_"};
    TestRouteSink sink;
    yuzu::server::register_file_retrieval_routes(
        sink, make_deps(store, blob_dir.path, std::make_shared<std::int64_t>(1000)));

    const std::string payload = "abc"; // SHA-256("abc") is a well-known test vector
    const std::string sha256_abc =
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    std::string upload_id;
    const std::string session_cred =
        mint_and_open(sink, "agent-1", static_cast<std::int64_t>(payload.size()), upload_id);

    auto chunk_res =
        sink.dispatch("PUT", "/api/v1/uploads/" + upload_id + "/chunk", payload,
                      "application/octet-stream",
                      {{"X-Yuzu-Upload-Session", session_cred}, {"Content-Range", content_range(0, 2, 3)}});
    REQUIRE(chunk_res->status == 200);

    auto commit_res = sink.dispatch("POST", "/api/v1/uploads/" + upload_id + "/commit",
                                    nlohmann::json{{"sha256", sha256_abc}}.dump(),
                                    "application/json",
                                    {{"X-Yuzu-Upload-Session", session_cred}});
    REQUIRE(commit_res != nullptr);
    REQUIRE(commit_res->status == 200);
    auto cj = body_json(commit_res);
    CHECK(cj["state"] == "committed");
    CHECK(cj["actual_size"] == 3);
    CHECK(cj["sha256"] == sha256_abc);
}

TEST_CASE("chunk offset_mismatch carries the authoritative offset", "[server][routes][upload]") {
    YUZU_REQUIRE_PG_DB_TPL(db, routes_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    UploadGrantStore store{pool};
    REQUIRE(store.is_open());
    yuzu::test::TempDir blob_dir{"yuzu_test_upload_blobs_"};
    TestRouteSink sink;
    yuzu::server::register_file_retrieval_routes(
        sink, make_deps(store, blob_dir.path, std::make_shared<std::int64_t>(1000)));

    std::string upload_id;
    const std::string session_cred = mint_and_open(sink, "agent-1", 100, upload_id);

    auto res = sink.dispatch("PUT", "/api/v1/uploads/" + upload_id + "/chunk", "xxxxx",
                             "application/octet-stream",
                             {{"X-Yuzu-Upload-Session", session_cred},
                              {"Content-Range", content_range(5, 9, 100)}});
    REQUIRE(res != nullptr);
    CHECK(res->status == 409);
    auto j = body_json(res);
    CHECK(j["error"]["reason"] == "offset_mismatch");
    CHECK(j["error"]["offset"] == 0);
}

TEST_CASE("an oversized chunk is rejected by its Content-Range alone (no large body sent)",
          "[server][routes][upload]") {
    YUZU_REQUIRE_PG_DB_TPL(db, routes_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    UploadGrantStore store{pool};
    REQUIRE(store.is_open());
    yuzu::test::TempDir blob_dir{"yuzu_test_upload_blobs_"};
    TestRouteSink sink;
    yuzu::server::register_file_retrieval_routes(
        sink, make_deps(store, blob_dir.path, std::make_shared<std::int64_t>(1000)));

    auto minted = body_json(sink.dispatch(
        "POST", "/api/v1/upload-grants",
        nlohmann::json{{"agent_id", "agent-1"}, {"declared_max_size", 100000000}}.dump()));
    const std::string grant_cred =
        minted["grant_id"].get<std::string>() + "." + minted["grant_secret"].get<std::string>();
    auto opened = body_json(sink.dispatch("POST", "/api/v1/uploads", "", "application/json",
                                          {{"X-Yuzu-Upload-Grant", grant_cred}}));
    const std::string upload_id = opened["upload_id"].get<std::string>();
    const std::string session_cred = upload_id + "." + opened["session_secret"].get<std::string>();
    const std::int64_t chunk_max = opened["chunk_max_bytes"].get<std::int64_t>();

    // The cap check runs against the PARSED Content-Range before the body
    // length is even compared — a tiny actual body proves the route
    // rejects on the declared range alone, no multi-megabyte payload needed.
    auto res = sink.dispatch(
        "PUT", "/api/v1/uploads/" + upload_id + "/chunk", "x", "application/octet-stream",
        {{"X-Yuzu-Upload-Session", session_cred},
         {"Content-Range", content_range(0, chunk_max, chunk_max + 1)}});
    REQUIRE(res != nullptr);
    CHECK(res->status == 413);
    CHECK(body_json(res)["error"]["reason"] == "chunk_too_large");
}

TEST_CASE("exceeding the grant's declared size terminates the session, size_exceeded",
          "[server][routes][upload]") {
    YUZU_REQUIRE_PG_DB_TPL(db, routes_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    UploadGrantStore store{pool};
    REQUIRE(store.is_open());
    yuzu::test::TempDir blob_dir{"yuzu_test_upload_blobs_"};
    TestRouteSink sink;
    yuzu::server::register_file_retrieval_routes(
        sink, make_deps(store, blob_dir.path, std::make_shared<std::int64_t>(1000)));

    std::string upload_id;
    const std::string session_cred = mint_and_open(sink, "agent-1", 10, upload_id);

    const std::string payload(20, 'z'); // declared max is only 10
    auto res = sink.dispatch("PUT", "/api/v1/uploads/" + upload_id + "/chunk", payload,
                             "application/octet-stream",
                             {{"X-Yuzu-Upload-Session", session_cred},
                              {"Content-Range", content_range(0, 19, 20)}});
    REQUIRE(res != nullptr);
    CHECK(res->status == 413);
    CHECK(body_json(res)["error"]["reason"] == "size_exceeded");

    auto status_res = sink.dispatch("GET", "/api/v1/uploads/" + upload_id, "", "application/json",
                                    {{"X-Yuzu-Upload-Session", session_cred}});
    REQUIRE(status_res->status == 200);
    CHECK(body_json(status_res)["state"] == "cancelled");
}

TEST_CASE("cancel discards the partial blob and reports 204", "[server][routes][upload]") {
    YUZU_REQUIRE_PG_DB_TPL(db, routes_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    UploadGrantStore store{pool};
    REQUIRE(store.is_open());
    yuzu::test::TempDir blob_dir{"yuzu_test_upload_blobs_"};
    TestRouteSink sink;
    yuzu::server::register_file_retrieval_routes(
        sink, make_deps(store, blob_dir.path, std::make_shared<std::int64_t>(1000)));

    auto minted = body_json(sink.dispatch(
        "POST", "/api/v1/upload-grants",
        nlohmann::json{{"agent_id", "agent-1"}, {"declared_max_size", 100}}.dump()));
    const std::string grant_cred =
        minted["grant_id"].get<std::string>() + "." + minted["grant_secret"].get<std::string>();
    auto opened = body_json(sink.dispatch("POST", "/api/v1/uploads", "", "application/json",
                                          {{"X-Yuzu-Upload-Grant", grant_cred}}));
    const std::string upload_id = opened["upload_id"].get<std::string>();
    const std::string session_cred = upload_id + "." + opened["session_secret"].get<std::string>();

    auto chunk_res = sink.dispatch("PUT", "/api/v1/uploads/" + upload_id + "/chunk", "abcde",
                                   "application/octet-stream",
                                   {{"X-Yuzu-Upload-Session", session_cred},
                                    {"Content-Range", content_range(0, 4, 100)}});
    REQUIRE(chunk_res->status == 200);
    auto blob_path = blob_dir.path / "standard" / minted["grant_id"].get<std::string>();
    CHECK(std::filesystem::exists(blob_path));

    auto cancel_res = sink.dispatch("DELETE", "/api/v1/uploads/" + upload_id, "", "application/json",
                                    {{"X-Yuzu-Upload-Session", session_cred}});
    REQUIRE(cancel_res != nullptr);
    CHECK(cancel_res->status == 204);
    CHECK_FALSE(std::filesystem::exists(blob_path));

    auto second = sink.dispatch("DELETE", "/api/v1/uploads/" + upload_id, "", "application/json",
                                {{"X-Yuzu-Upload-Session", session_cred}});
    REQUIRE(second != nullptr);
    CHECK(second->status == 409);
    CHECK(body_json(second)["error"]["reason"] == "session_terminal");
}

TEST_CASE("any request after expiry is 410 expired, even a status poll", "[server][routes][upload]") {
    YUZU_REQUIRE_PG_DB_TPL(db, routes_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    UploadGrantStore store{pool};
    REQUIRE(store.is_open());
    yuzu::test::TempDir blob_dir{"yuzu_test_upload_blobs_"};
    auto clock = std::make_shared<std::int64_t>(1000);
    TestRouteSink sink;
    yuzu::server::register_file_retrieval_routes(sink, make_deps(store, blob_dir.path, clock));

    auto minted = body_json(sink.dispatch(
        "POST", "/api/v1/upload-grants",
        nlohmann::json{{"agent_id", "agent-1"}, {"declared_max_size", 100}, {"ttl_secs", 10}}
            .dump()));
    const std::string grant_cred =
        minted["grant_id"].get<std::string>() + "." + minted["grant_secret"].get<std::string>();
    auto opened = body_json(sink.dispatch("POST", "/api/v1/uploads", "", "application/json",
                                          {{"X-Yuzu-Upload-Grant", grant_cred}}));
    const std::string upload_id = opened["upload_id"].get<std::string>();
    const std::string session_cred = upload_id + "." + opened["session_secret"].get<std::string>();

    *clock = opened["expires_at"].get<std::int64_t>() + 1; // one second past expiry

    auto res = sink.dispatch("GET", "/api/v1/uploads/" + upload_id, "", "application/json",
                             {{"X-Yuzu-Upload-Session", session_cred}});
    REQUIRE(res != nullptr);
    CHECK(res->status == 410);
    CHECK(body_json(res)["error"]["reason"] == "expired");
}
