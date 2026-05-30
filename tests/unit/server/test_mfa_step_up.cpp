/**
 * test_mfa_step_up.cpp — unit tests for the `require_mfa_step_up`
 * helper added by PR2 of the TOTP MFA ladder (SOC 2 CC6.6).
 *
 * Drives every branch of the gate decision tree:
 *
 *   - escape hatch (window_secs <= 0)
 *   - bearer-credential bypass (auth_source == api_token / mcp_token)
 *   - non-enrolled user bypass (mfa_status->enrolled == false)
 *   - no-proof session (mfa_verified_at == 0) → 401
 *   - fresh proof within window → pass
 *   - stale proof beyond window → 401
 *   - 401 envelope shape (code, message, correlation_id, remediation,
 *     meta.api_version, meta.mfa_step_up_required, meta.challenge_url)
 *   - audit capture (action, result, target_type, target_id, detail)
 *   - empty audit_fn does not crash
 *
 * The helper does not touch httplib::Server; we construct synthetic
 * Request + Response objects directly and assert post-call state.
 */

#include "../../../server/core/src/mfa_step_up.hpp"
#include "../../../server/core/src/totp.hpp"

#include <yuzu/server/auth.hpp>
#include <yuzu/server/auth_db.hpp>

#include "../test_helpers.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace yuzu::server;
using yuzu::server::auth::AuthManager;
using yuzu::server::auth::Role;

namespace {

struct AuditCapture {
    std::string action;
    std::string result;
    std::string target_type;
    std::string target_id;
    std::string detail;
};

struct StepUpFixture {
    fs::path data_dir;
    std::unique_ptr<AuthDB> db;
    std::vector<AuditCapture> audits;
    StepUpAuditFn audit_fn;

    StepUpFixture() {
        data_dir = yuzu::test::unique_temp_path("mfa-stepup-");
        fs::create_directories(data_dir);
        db = std::make_unique<AuthDB>(data_dir, /*cleanup_interval_secs=*/0);
        REQUIRE(db->initialize().has_value());

        // Seed alice (MFA-enrolled) + bob (not enrolled).
        auto salt_a = AuthManager::random_bytes(16);
        auto hash_a = AuthManager::pbkdf2_sha256("pw", salt_a, 1000);
        REQUIRE(db->upsert_user("alice", hash_a, AuthManager::bytes_to_hex(salt_a),
                                Role::admin)
                    .has_value());
        auto salt_b = AuthManager::random_bytes(16);
        auto hash_b = AuthManager::pbkdf2_sha256("pw", salt_b, 1000);
        REQUIRE(db->upsert_user("bob", hash_b, AuthManager::bytes_to_hex(salt_b),
                                Role::user)
                    .has_value());

        // Enroll alice in MFA so mfa_status->enrolled == true.
        auto init = db->mfa_init_enrollment("alice", "Yuzu");
        REQUIRE(init.has_value());
        auto bytes = mfa::base32_decode(init->secret_base32);
        REQUIRE(bytes.has_value());
        std::string raw(reinterpret_cast<const char*>(bytes->data()), bytes->size());
        auto code = mfa::generate(raw, mfa::current_counter(std::chrono::system_clock::now()));
        REQUIRE(db->mfa_verify_enrollment("alice", code).has_value());

        audit_fn = [this](const httplib::Request&, const std::string& action,
                          const std::string& result, const std::string& target_type,
                          const std::string& target_id, const std::string& detail) -> bool {
            audits.push_back({action, result, target_type, target_id, detail});
            return true;
        };
    }

    ~StepUpFixture() {
        db.reset();
        std::error_code ec;
        fs::remove_all(data_dir, ec);
    }

    auth::Session make_session(const std::string& user, const std::string& source,
                               std::chrono::steady_clock::time_point verified_at = {}) {
        auth::Session s;
        s.username = user;
        s.role = (user == "alice") ? Role::admin : Role::user;
        s.expires_at = std::chrono::steady_clock::now() + std::chrono::hours(1);
        s.auth_source = source;
        s.mfa_verified_at = verified_at;
        return s;
    }
};

} // namespace

TEST_CASE_METHOD(StepUpFixture,
                 "require_mfa_step_up: window_secs <= 0 returns true (escape hatch)",
                 "[mfa][stepup]") {
    httplib::Request req;
    httplib::Response res;
    res.status = 200;
    auto session = make_session("alice", "local");

    CHECK(require_mfa_step_up(req, res, session, *db, /*window_secs=*/0, audit_fn,
                              "POST /api/v1/whatever"));
    CHECK(res.status == 200);
    CHECK(res.body.empty());
    CHECK(audits.empty());

    CHECK(require_mfa_step_up(req, res, session, *db, /*window_secs=*/-1, audit_fn,
                              "POST /api/v1/whatever"));
    CHECK(audits.empty());
}

TEST_CASE_METHOD(StepUpFixture,
                 "require_mfa_step_up: api_token / mcp_token principals bypass the gate",
                 "[mfa][stepup]") {
    httplib::Request req;
    httplib::Response res;
    res.status = 200;

    auto api = make_session("alice", "api_token");
    CHECK(require_mfa_step_up(req, res, api, *db, /*window_secs=*/300, audit_fn,
                              "POST /api/v1/tokens"));
    CHECK(audits.empty());

    auto mcp = make_session("alice", "mcp_token");
    CHECK(require_mfa_step_up(req, res, mcp, *db, /*window_secs=*/300, audit_fn,
                              "POST /api/v1/tokens"));
    CHECK(audits.empty());
}

TEST_CASE_METHOD(StepUpFixture,
                 "require_mfa_step_up: non-enrolled user (bob) bypasses the gate",
                 "[mfa][stepup]") {
    httplib::Request req;
    httplib::Response res;
    res.status = 200;
    auto session = make_session("bob", "local");

    CHECK(require_mfa_step_up(req, res, session, *db, /*window_secs=*/300, audit_fn,
                              "POST /api/v1/tokens"));
    CHECK(res.status == 200);
    CHECK(res.body.empty());
    CHECK(audits.empty());
}

TEST_CASE_METHOD(StepUpFixture,
                 "require_mfa_step_up: MFA-enrolled session with no proof yields 401",
                 "[mfa][stepup]") {
    httplib::Request req;
    httplib::Response res;
    res.status = 200;
    // mfa_verified_at is default-constructed (epoch 0) → "no proof yet".
    auto session = make_session("alice", "local");

    CHECK_FALSE(require_mfa_step_up(req, res, session, *db, /*window_secs=*/300, audit_fn,
                                    "POST /api/v1/tokens"));
    CHECK(res.status == 401);

    auto body = nlohmann::json::parse(res.body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    CHECK(body["error"]["code"] == 401);
    CHECK(body["error"]["message"] == "MFA step-up required");
    CHECK(body["error"].contains("correlation_id"));
    CHECK(body["error"]["remediation"].get<std::string>().find("/login/mfa/stepup") !=
          std::string::npos);
    CHECK(body["meta"]["api_version"] == "v1");
    CHECK(body["meta"]["mfa_step_up_required"] == true);
    CHECK(body["meta"]["challenge_url"] == "/login/mfa/stepup");

    REQUIRE(audits.size() == 1);
    CHECK(audits[0].action == "mfa.step_up.required");
    CHECK(audits[0].result == "error");
    CHECK(audits[0].target_type == "Endpoint");
    CHECK(audits[0].target_id == "POST /api/v1/tokens");
    CHECK(audits[0].detail.find("user=alice") != std::string::npos);
    CHECK(audits[0].detail.find("age_secs=-1") != std::string::npos); // sentinel
    CHECK(audits[0].detail.find("window_secs=300") != std::string::npos);
}

TEST_CASE_METHOD(StepUpFixture,
                 "require_mfa_step_up: fresh proof within window passes the gate",
                 "[mfa][stepup]") {
    httplib::Request req;
    httplib::Response res;
    res.status = 200;
    auto session = make_session("alice", "local", std::chrono::steady_clock::now());

    CHECK(require_mfa_step_up(req, res, session, *db, /*window_secs=*/300, audit_fn,
                              "POST /api/v1/tokens"));
    CHECK(res.status == 200);
    CHECK(res.body.empty());
    CHECK(audits.empty());
}

TEST_CASE_METHOD(StepUpFixture, "require_mfa_step_up: stale proof beyond window yields 401",
                 "[mfa][stepup]") {
    httplib::Request req;
    httplib::Response res;
    res.status = 200;
    // 600 s old; window is 300 s → stale.
    auto session = make_session("alice", "local",
                                std::chrono::steady_clock::now() - std::chrono::seconds(600));

    CHECK_FALSE(require_mfa_step_up(req, res, session, *db, /*window_secs=*/300, audit_fn,
                                    "POST /api/v1/tokens"));
    CHECK(res.status == 401);

    auto body = nlohmann::json::parse(res.body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    CHECK(body["meta"]["mfa_step_up_required"] == true);

    REQUIRE(audits.size() == 1);
    CHECK(audits[0].action == "mfa.step_up.required");
    // age_secs should be ~600 (allow a small wobble for scheduler jitter).
    auto age_pos = audits[0].detail.find("age_secs=");
    REQUIRE(age_pos != std::string::npos);
    int age = std::stoi(audits[0].detail.substr(age_pos + 9));
    CHECK(age >= 600);
    CHECK(age < 610);
}

TEST_CASE_METHOD(StepUpFixture,
                 "require_mfa_step_up: mfa_status store error fails CLOSED (UP-4)",
                 "[mfa][stepup]") {
    // Tear down auth_db so mfa_status() returns an error → helper must
    // emit a 401 with the mfa_status_unavailable detail, not silently
    // bypass the gate. Governance Gate 4 unhappy-path UP-4 / qe Gate 3
    // BLOCKING.
    httplib::Request req;
    httplib::Response res;
    res.status = 200;
    // alice was enrolled in the fixture; we now drop her row to simulate
    // a deleted-mid-request user. mfa_status() returns an error.
    REQUIRE(db->remove_user("alice").has_value());
    auto session = make_session("alice", "local", std::chrono::steady_clock::now());

    CHECK_FALSE(require_mfa_step_up(req, res, session, *db, /*window_secs=*/300, audit_fn,
                                    "POST /api/v1/tokens"));
    CHECK(res.status == 401);
    auto body = nlohmann::json::parse(res.body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    CHECK(body["meta"]["mfa_step_up_required"] == true);
    CHECK(body["error"]["remediation"].get<std::string>().find("auth_db unavailable") !=
          std::string::npos);

    REQUIRE(audits.size() == 1);
    CHECK(audits[0].action == "mfa.step_up.required");
    CHECK(audits[0].result == "error");
    CHECK(audits[0].detail.find("mfa_status_unavailable") != std::string::npos);
    CHECK(audits[0].detail.find("fail-closed") != std::string::npos);
}

TEST_CASE_METHOD(StepUpFixture,
                 "require_mfa_step_up: empty audit_fn does not crash on the deny path",
                 "[mfa][stepup]") {
    httplib::Request req;
    httplib::Response res;
    res.status = 200;
    auto session = make_session("alice", "local");

    StepUpAuditFn empty_audit; // default-constructed std::function is empty
    CHECK_FALSE(require_mfa_step_up(req, res, session, *db, /*window_secs=*/300, empty_audit,
                                    "POST /api/v1/tokens"));
    CHECK(res.status == 401);
    // Body still constructed correctly.
    auto body = nlohmann::json::parse(res.body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    CHECK(body["meta"]["mfa_step_up_required"] == true);
}

TEST_CASE_METHOD(StepUpFixture, "require_mfa_step_up: OIDC sessions are subject to step-up",
                 "[mfa][stepup]") {
    httplib::Request req;
    httplib::Response res;
    res.status = 200;
    // OIDC session, no proof recorded — must require step-up just like local.
    auto session = make_session("alice", "oidc");

    CHECK_FALSE(require_mfa_step_up(req, res, session, *db, /*window_secs=*/300, audit_fn,
                                    "POST /api/v1/tokens"));
    CHECK(res.status == 401);
    REQUIRE(audits.size() == 1);
    CHECK(audits[0].action == "mfa.step_up.required");
}

TEST_CASE_METHOD(StepUpFixture,
                 "require_mfa_step_up: per-call correlation_id is unique across calls",
                 "[mfa][stepup]") {
    httplib::Request req;
    auto session = make_session("alice", "local");

    httplib::Response res1;
    res1.status = 200;
    require_mfa_step_up(req, res1, session, *db, 300, audit_fn, "POST /api/v1/tokens");
    httplib::Response res2;
    res2.status = 200;
    require_mfa_step_up(req, res2, session, *db, 300, audit_fn, "POST /api/v1/tokens");

    auto b1 = nlohmann::json::parse(res1.body);
    auto b2 = nlohmann::json::parse(res2.body);
    CHECK(b1["error"]["correlation_id"].get<std::string>() !=
          b2["error"]["correlation_id"].get<std::string>());
}
