/**
 * test_updater_signature.cpp — the OTA signature gate, driven end to end
 * through Updater::check_and_apply over a real gRPC channel.
 *
 * WHY THIS EXISTS AND WHY IT IS NOT A UNIT TEST. A mutation that deletes the
 * signature check from `check_and_apply` outright — `if (false)` around the
 * whole block — left the entire agent suite green, because nothing anywhere
 * drove the download path. Verifying the verifier in isolation proves the
 * primitive works; it does not prove the updater calls it, and that gap is the
 * one that actually ships an unverified binary.
 *
 * So this stands up a test-local AgentService serving a small payload plus a
 * real detached CMS signature over it, and asserts on what check_and_apply
 * DOES. The payload is a few bytes, the server is in-process on an ephemeral
 * loopback port, and no update is ever applied to anything but a temp file.
 */

#include <yuzu/agent/updater.hpp>

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>

#include <grpcpp/grpcpp.h>

#include <fstream>
#include <string>

#include "agent.grpc.pb.h"
#include "cms_test_fixtures.hpp"
#include "test_helpers.hpp"

using yuzu::agent::UpdateConfig;
using yuzu::agent::Updater;
using namespace yuzu::test::cms;

namespace {

namespace pb = ::yuzu::agent::v1;

std::string read_file(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    REQUIRE(in);
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

std::string sha256_hex_of(const std::string& data) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    ssl_ptr<EVP_MD_CTX> ctx{EVP_MD_CTX_new()};
    REQUIRE(ctx);
    REQUIRE(EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) == 1);
    REQUIRE(EVP_DigestUpdate(ctx.get(), data.data(), data.size()) == 1);
    REQUIRE(EVP_DigestFinal_ex(ctx.get(), md, &len) == 1);
    std::string hex;
    static const char* k = "0123456789abcdef";
    for (unsigned i = 0; i < len; ++i) {
        hex += k[md[i] >> 4];
        hex += k[md[i] & 0x0F];
    }
    return hex;
}

/// Serves one fixed payload, with a signature the test chooses.
class FakeUpdateService final : public pb::AgentService::Service {
  public:
    std::string payload;
    std::string signature; // empty = the package is unsigned
    std::string version{"9.9.9"};

    grpc::Status CheckForUpdate(grpc::ServerContext*, const pb::CheckForUpdateRequest*,
                                pb::CheckForUpdateResponse* resp) override {
        resp->set_update_available(true);
        resp->set_latest_version(version);
        resp->set_sha256(sha256_hex_of(payload));
        resp->set_mandatory(false);
        resp->set_eligible(true);
        resp->set_file_size(static_cast<int64_t>(payload.size()));
        if (!signature.empty())
            resp->set_update_signature(signature);
        return grpc::Status::OK;
    }

    grpc::Status DownloadUpdate(grpc::ServerContext*, const pb::DownloadUpdateRequest*,
                                grpc::ServerWriter<pb::DownloadUpdateChunk>* writer) override {
        pb::DownloadUpdateChunk chunk;
        chunk.set_data(payload);
        chunk.set_offset(0);
        chunk.set_total_size(static_cast<int64_t>(payload.size()));
        writer->Write(chunk);
        return grpc::Status::OK;
    }
};

struct Harness {
    FakeUpdateService svc;
    std::unique_ptr<grpc::Server> server;
    std::unique_ptr<pb::AgentService::Stub> stub;
    int port{0};

    void start() {
        grpc::ServerBuilder b;
        b.AddListeningPort("127.0.0.1:0", grpc::InsecureServerCredentials(), &port);
        b.RegisterService(&svc);
        server = b.BuildAndStart();
        REQUIRE(server);
        REQUIRE(port != 0);
        stub = pb::AgentService::NewStub(grpc::CreateChannel(
            "127.0.0.1:" + std::to_string(port), grpc::InsecureChannelCredentials()));
    }
    ~Harness() {
        if (server)
            server->Shutdown(std::chrono::system_clock::now() + std::chrono::seconds(5));
    }
};

/// A throwaway "installed agent binary" for the updater to replace.
struct FakeExe {
    fs::path dir;
    fs::path path;
    FakeExe() {
        dir = yuzu::test::unique_temp_path("yuzu_test_upd_sig_");
        fs::create_directories(dir);
        path = dir / "yuzu-agent-fake";
        std::ofstream(path, std::ios::binary) << "old-binary";
    }
    ~FakeExe() {
        std::error_code ec;
        fs::remove_all(dir, ec);
    }
};

UpdateConfig cfg_with(const fs::path& bundle, bool require,
                      yuzu::MetricsRegistry* m = nullptr) {
    UpdateConfig c;
    c.enabled = true;
    c.signature_trust_bundle = bundle;
    c.require_signature = require;
    c.metrics = m;
    return c;
}

double refused(yuzu::MetricsRegistry& m, const char* reason) {
    return m.counter("yuzu_agent_ota_signature_refused_total", {{"reason", reason}}).value();
}

} // namespace

TEST_CASE("updater: a correctly signed package is applied", "[updater][signing][grpc]") {
    auto f = build_signing_fixtures();
    FakeExe exe;
    Harness h;
    h.svc.payload = read_file(f.artifact_file);
    h.svc.signature = read_file(f.sig_file);
    h.start();

    Updater updater(cfg_with(f.trust_bundle, /*require=*/true), "test-agent", "0.1.0", "linux",
                    "x86_64", exe.path);
    auto r = updater.check_and_apply(h.stub.get());
    REQUIRE(r.has_value());
    CHECK(*r); // applied → the caller restarts
}

TEST_CASE("updater: a package signed by a FOREIGN CA is refused", "[updater][signing][grpc]") {
    // THE MUTATION THIS FILE EXISTS FOR. With the signature check removed from
    // check_and_apply, this package applies happily: its SHA-256 matches, because
    // the server computed the hash over the bytes it served. Only the signature
    // distinguishes it.
    auto f = build_signing_fixtures();
    FakeExe exe;
    Harness h;
    h.svc.payload = read_file(f.artifact_file);
    h.svc.signature = read_file(f.sig_file);
    h.start();

    // Same package, same valid signature — but the agent trusts a different CA.
    yuzu::MetricsRegistry metrics;
    Updater updater(cfg_with(f.other_trust_bundle, /*require=*/false, &metrics), "test-agent",
                    "0.1.0", "linux", "x86_64", exe.path);
    auto r = updater.check_and_apply(h.stub.get());
    REQUIRE_FALSE(r.has_value());
    CHECK(read_file(exe.path) == "old-binary"); // untouched
    // The refusal must be visible to something other than a local log line —
    // with no status RPC on this path, this counter is all an operator gets.
    CHECK(refused(metrics, "untrusted") == 1.0);
}

TEST_CASE("updater: a present-but-invalid signature is refused in BOTH modes",
          "[updater][signing][grpc]") {
    // THE CONTRACT THE DOCS ASSERT ON FIVE SURFACES: --update-require-signature
    // governs only whether an ABSENT signature is tolerated. A signature that is
    // PRESENT and does not verify is refused either way.
    //
    // Every other invalid-signature case here ran with require=false, so nothing
    // would have failed if require=true had bypassed verification entirely — a
    // gap an external reviewer found, not this suite.
    auto f = build_signing_fixtures();

    for (const bool require : {false, true}) {
        FakeExe exe;
        Harness h;
        h.svc.payload = read_file(f.artifact_file);
        h.svc.signature = read_file(f.sig_file);
        h.start();

        yuzu::MetricsRegistry metrics;
        // Signature is valid, but the agent trusts a different CA.
        Updater updater(cfg_with(f.other_trust_bundle, require, &metrics), "test-agent", "0.1.0",
                        "linux", "x86_64", exe.path);
        auto r = updater.check_and_apply(h.stub.get());
        INFO("require_signature=" << require);
        REQUIRE_FALSE(r.has_value());
        CHECK(read_file(exe.path) == "old-binary");
        CHECK(refused(metrics, "untrusted") == 1.0);
    }
}

TEST_CASE("updater: a tampered payload increments the INVALID refusal counter",
          "[updater][signing][grpc]") {
    // The `invalid` label had no assertion anywhere — only `missing` and
    // `untrusted` did — so the reason an operator would see for the commonest
    // real failure (a signature over different bytes) was unverified.
    auto f = build_signing_fixtures();
    FakeExe exe;
    Harness h;
    h.svc.payload = read_file(f.artifact_file) + "-tampered";
    h.svc.signature = read_file(f.sig_file);
    h.start();

    yuzu::MetricsRegistry metrics;
    Updater updater(cfg_with(f.trust_bundle, /*require=*/true, &metrics), "test-agent", "0.1.0",
                    "linux", "x86_64", exe.path);
    auto r = updater.check_and_apply(h.stub.get());
    REQUIRE_FALSE(r.has_value());
    CHECK(refused(metrics, "invalid") == 1.0);
    CHECK(refused(metrics, "untrusted") == 0.0); // classified, not lumped together
}

TEST_CASE("updater: a tampered payload is refused even with a real signature",
          "[updater][signing][grpc]") {
    auto f = build_signing_fixtures();
    FakeExe exe;
    Harness h;
    h.svc.payload = read_file(f.artifact_file) + "-tampered";
    h.svc.signature = read_file(f.sig_file); // signature covers the ORIGINAL bytes
    h.start();

    Updater updater(cfg_with(f.trust_bundle, false), "test-agent", "0.1.0", "linux", "x86_64",
                    exe.path);
    auto r = updater.check_and_apply(h.stub.get());
    REQUIRE_FALSE(r.has_value());
    CHECK(read_file(exe.path) == "old-binary");
}

TEST_CASE("updater: an unsigned package is refused only when require is set",
          "[updater][signing][grpc]") {
    auto f = build_signing_fixtures();

    SECTION("require on → refused") {
        FakeExe exe;
        Harness h;
        h.svc.payload = read_file(f.artifact_file);
        h.svc.signature.clear();
        h.start();
        yuzu::MetricsRegistry metrics;
        Updater updater(cfg_with(f.trust_bundle, /*require=*/true, &metrics), "test-agent", "0.1.0",
                        "linux", "x86_64", exe.path);
        auto r = updater.check_and_apply(h.stub.get());
        REQUIRE_FALSE(r.has_value());
        CHECK(read_file(exe.path) == "old-binary");
        CHECK(refused(metrics, "missing") == 1.0);
    }

    SECTION("require off → applied, transitional mode") {
        FakeExe exe;
        Harness h;
        h.svc.payload = read_file(f.artifact_file);
        h.svc.signature.clear();
        h.start();
        Updater updater(cfg_with(f.trust_bundle, /*require=*/false), "test-agent", "0.1.0", "linux",
                        "x86_64", exe.path);
        auto r = updater.check_and_apply(h.stub.get());
        REQUIRE(r.has_value());
        CHECK(*r);
    }
}

TEST_CASE("updater: with no trust bundle configured, signatures are not checked at all",
          "[updater][signing][grpc]") {
    // The default posture. A package carrying a signature from an unrelated CA
    // still applies, because the operator has not opted in — this pins that
    // "unset bundle" really does mean off, rather than accidentally enforcing.
    auto f = build_signing_fixtures();
    FakeExe exe;
    Harness h;
    h.svc.payload = read_file(f.artifact_file);
    h.svc.signature = read_file(f.sig_file);
    h.start();

    Updater updater(cfg_with(fs::path{}, /*require=*/false), "test-agent", "0.1.0", "linux",
                    "x86_64", exe.path);
    auto r = updater.check_and_apply(h.stub.get());
    REQUIRE(r.has_value());
    CHECK(*r);
}
