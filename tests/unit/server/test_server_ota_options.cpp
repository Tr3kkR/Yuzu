/**
 * test_server_ota_options.cpp — the operator-facing contract for the OTA and
 * gRPC bound knobs (#913, #911): flag names, defaults, env spellings,
 * validation, and the MiB->bytes derivation handed to gRPC.
 *
 * WHY. These options are the only way an operator tunes the OTA bounds, and
 * every service-level test drives the setters directly — so a misspelled
 * `envname()`, a default drifted from the documented one, a binding pointed at
 * the wrong `Config` field, or a dropped validator would ship silently with the
 * whole suite green. A gate-1 review flagged that. The values asserted below are
 * the same ones published in `docs/user-manual/server-admin.md` and the
 * changelog fragment, so a change here forces a decision about the docs.
 *
 * Parsing runs IN PROCESS against a real `CLI::App` — deliberately not a
 * subprocess, since the test-efficiency discipline rules process creation out of
 * the unit suites.
 */

#include "grpc_bounds_rules.hpp"
#include "server_ota_options.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdlib> // setenv/unsetenv (POSIX), _putenv_s (MSVC)
#include <string>
#include <vector>

using yuzu::server::Config;
using yuzu::server::grpc_bounds_from_config;
using yuzu::server::register_ota_options;

namespace {

// Parses argv into a fresh Config. Returns false if CLI11 rejected the input.
bool parse(const std::vector<std::string>& args, Config& cfg) {
    CLI::App app{"test"};
    register_ota_options(app, cfg);
    std::vector<const char*> argv;
    argv.push_back("yuzu-server");
    for (const auto& a : args)
        argv.push_back(a.c_str());
    try {
        app.parse(static_cast<int>(argv.size()), const_cast<char**>(argv.data()));
        return true;
    } catch (const CLI::ParseError&) {
        return false;
    }
}

// RAII environment override so an env-driven case cannot leak into its
// neighbours.
//
// PLATFORM SPLIT IS LOAD-BEARING: `setenv`/`unsetenv` are POSIX and the MSVC CRT
// supplies neither, so an unconditional call fails to COMPILE on the required
// Windows leg — this file is added to `yuzu_server_tests` for every platform.
// Windows uses `_putenv_s`, where assigning an empty value is the documented way
// to remove a variable. Same split, same reason, as
// tests/unit/test_subprocess_runner.cpp's `_WIN32` section.
struct ScopedEnv {
    std::string name;
    explicit ScopedEnv(const std::string& n, const std::string& v) : name(n) {
#ifdef _WIN32
        (void)_putenv_s(name.c_str(), v.c_str());
#else
        ::setenv(name.c_str(), v.c_str(), 1);
#endif
    }
    ~ScopedEnv() {
#ifdef _WIN32
        (void)_putenv_s(name.c_str(), "");
#else
        ::unsetenv(name.c_str());
#endif
    }
};

} // namespace

TEST_CASE("OTA options: defaults match the documented values", "[ota][options]") {
    Config cfg;
    REQUIRE(parse({}, cfg));
    // These are the defaults published in server-admin.md and the changelog.
    CHECK(cfg.ota_max_concurrent_per_peer == 2);
    CHECK(cfg.ota_rate_capacity == 20.0);
    CHECK(cfg.ota_rate_refill_per_min == 1.0);
    CHECK(cfg.ota_transfer_deadline_secs == 900);
    CHECK(cfg.ota_chunk_write_deadline_secs == 30);
    CHECK(cfg.ota_max_peers_tracked == 50000);
    CHECK(cfg.grpc_max_concurrent_streams == 128);
    CHECK(cfg.grpc_max_resource_memory_mb == 512);
}

TEST_CASE("OTA options: each flag binds to its own Config field", "[ota][options]") {
    // Every value distinct, so a binding pointed at the wrong field cannot pass
    // by coincidence — the failure mode a copy-paste registration produces.
    Config cfg;
    REQUIRE(parse({"--ota-max-concurrent-per-peer=7", "--ota-rate-capacity=11",
                   "--ota-rate-refill-per-min=3", "--ota-transfer-deadline-secs=123",
                   "--ota-chunk-write-deadline-secs=45", "--ota-max-peers-tracked=999",
                   "--grpc-max-concurrent-streams=64", "--grpc-max-resource-memory-mb=256"},
                  cfg));
    CHECK(cfg.ota_max_concurrent_per_peer == 7);
    CHECK(cfg.ota_rate_capacity == 11.0);
    CHECK(cfg.ota_rate_refill_per_min == 3.0);
    CHECK(cfg.ota_transfer_deadline_secs == 123);
    CHECK(cfg.ota_chunk_write_deadline_secs == 45);
    CHECK(cfg.ota_max_peers_tracked == 999);
    CHECK(cfg.grpc_max_concurrent_streams == 64);
    CHECK(cfg.grpc_max_resource_memory_mb == 256);
}

TEST_CASE("OTA options: env var spellings are exactly as documented", "[ota][options]") {
    // A typo here is invisible at runtime — the server just silently keeps the
    // default while the operator believes they configured it.
    {
        Config cfg;
        ScopedEnv e{"YUZU_OTA_MAX_CONCURRENT_PER_PEER", "9"};
        REQUIRE(parse({}, cfg));
        CHECK(cfg.ota_max_concurrent_per_peer == 9);
    }
    {
        Config cfg;
        ScopedEnv e{"YUZU_OTA_CHUNK_WRITE_DEADLINE_SECS", "77"};
        REQUIRE(parse({}, cfg));
        CHECK(cfg.ota_chunk_write_deadline_secs == 77);
    }
    {
        Config cfg;
        ScopedEnv e{"YUZU_OTA_MAX_PEERS_TRACKED", "4242"};
        REQUIRE(parse({}, cfg));
        CHECK(cfg.ota_max_peers_tracked == 4242);
    }
    {
        Config cfg;
        ScopedEnv e{"YUZU_GRPC_MAX_RESOURCE_MEMORY_MB", "2048"};
        REQUIRE(parse({}, cfg));
        CHECK(cfg.grpc_max_resource_memory_mb == 2048);
    }
}

TEST_CASE("OTA options: an explicit flag wins over the environment", "[ota][options]") {
    Config cfg;
    ScopedEnv e{"YUZU_OTA_MAX_CONCURRENT_PER_PEER", "9"};
    REQUIRE(parse({"--ota-max-concurrent-per-peer=3"}, cfg));
    CHECK(cfg.ota_max_concurrent_per_peer == 3);
}

TEST_CASE("OTA options: non-positive values are rejected at parse time", "[ota][options]") {
    // Zero does not "disable" these bounds — it configures a server that refuses
    // every OTA pull, or accepts no streams at all. Failing at startup is the
    // difference between an error an operator can read and a silent outage.
    Config cfg;
    CHECK_FALSE(parse({"--ota-max-concurrent-per-peer=0"}, cfg));
    CHECK_FALSE(parse({"--ota-max-concurrent-per-peer=-1"}, cfg));
    CHECK_FALSE(parse({"--ota-rate-capacity=0"}, cfg));
    CHECK_FALSE(parse({"--ota-transfer-deadline-secs=0"}, cfg));
    CHECK_FALSE(parse({"--ota-chunk-write-deadline-secs=-5"}, cfg));
    CHECK_FALSE(parse({"--ota-max-peers-tracked=0"}, cfg));
    CHECK_FALSE(parse({"--grpc-max-concurrent-streams=0"}, cfg));
    CHECK_FALSE(parse({"--grpc-max-resource-memory-mb=-1"}, cfg));
}

TEST_CASE("gRPC bounds: MiB converts to bytes without overflowing", "[ota][options]") {
    Config cfg;
    cfg.grpc_max_resource_memory_mb = 512;
    cfg.grpc_max_concurrent_streams = 128;
    auto b = grpc_bounds_from_config(cfg);
    CHECK(b.max_concurrent_streams == 128);
    CHECK(b.resource_quota_bytes == 512ULL * 1024ULL * 1024ULL);

    // The case the widening exists for: `mb * 1024 * 1024` evaluated in int
    // overflows above ~2048 MiB. A large deployment configuring 4096 MiB would
    // otherwise wrap negative and convert to an enormous size_t, silently
    // removing the very bound it was raising.
    cfg.grpc_max_resource_memory_mb = 4096;
    b = grpc_bounds_from_config(cfg);
    CHECK(b.resource_quota_bytes == 4096ULL * 1024ULL * 1024ULL);
    CHECK(b.resource_quota_bytes > 0);

    cfg.grpc_max_resource_memory_mb = 8192;
    b = grpc_bounds_from_config(cfg);
    CHECK(b.resource_quota_bytes == 8192ULL * 1024ULL * 1024ULL);
}

TEST_CASE("gRPC bounds: a non-positive config is clamped, never zero", "[ota][options]") {
    // CLI11 rejects these, but Config can also be built in code (and a future
    // config-file loader would not go through CLI11), so the derivation clamps
    // rather than trusting its input. A zero quota would configure a server that
    // accepts nothing.
    Config cfg;
    cfg.grpc_max_concurrent_streams = 0;
    cfg.grpc_max_resource_memory_mb = 0;
    const auto b = grpc_bounds_from_config(cfg);
    CHECK(b.max_concurrent_streams >= yuzu::server::kMinConcurrentStreams);
    CHECK(b.resource_quota_bytes >= yuzu::server::kMinResourceQuotaBytes);
}
