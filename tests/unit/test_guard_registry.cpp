/**
 * test_guard_registry.cpp — RegistryGuard enforcement (write-back) behaviour.
 *
 * Proves the enforce path restores a drifted value via a single in-process
 * registry syscall (RegSetValueExW) — NO shell, NO subprocess — and that audit
 * mode observes without writing. Windows-only (the guard is a no-op elsewhere);
 * exercises a real HKCU scratch key the running user can always write.
 */

#include <yuzu/agent/guard_registry.hpp>

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <string>

using namespace yuzu::agent;

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

namespace {

// A scratch HKCU key the running user can always create/write — a sub-subkey of
// the demo key so it never collides with the live demo's HKCU\SOFTWARE\YuzuTest.
constexpr const wchar_t* kSubKeyW = L"SOFTWARE\\YuzuTest\\GuardEnforceTest";
constexpr const char* kSubKeyA = "SOFTWARE\\YuzuTest\\GuardEnforceTest";

void set_dword(const wchar_t* name, DWORD v) {
    HKEY k{};
    if (RegCreateKeyExW(HKEY_CURRENT_USER, kSubKeyW, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &k,
                        nullptr) == ERROR_SUCCESS) {
        RegSetValueExW(k, name, 0, REG_DWORD, reinterpret_cast<const BYTE*>(&v), sizeof(v));
        RegCloseKey(k);
    }
}

DWORD get_dword(const wchar_t* name) {
    HKEY k{};
    if (RegOpenKeyExW(HKEY_CURRENT_USER, kSubKeyW, 0, KEY_READ, &k) != ERROR_SUCCESS)
        return 0xFFFFFFFFu;
    DWORD v = 0, sz = sizeof(v), type = 0;
    RegQueryValueExW(k, name, nullptr, &type, reinterpret_cast<BYTE*>(&v), &sz);
    RegCloseKey(k);
    return v;
}

void cleanup() { RegDeleteKeyW(HKEY_CURRENT_USER, kSubKeyW); }

// Arm `guard`, block up to 5s for the first drift report, then stop.
RegistryDrift run_once(RegistryGuard& guard, std::mutex& m, std::condition_variable& cv,
                       bool& got, RegistryDrift& captured) {
    REQUIRE(guard.start());
    {
        std::unique_lock lk(m);
        REQUIRE(cv.wait_for(lk, std::chrono::seconds(5), [&] { return got; }));
    }
    guard.stop();
    return captured;
}

} // namespace

TEST_CASE("RegistryGuard enforce: restores a drifted DWORD via RegSetValueExW",
          "[guardian][guard][enforce][registry]") {
    set_dword(L"Flag", 0); // currently WRONG (expected 1)

    RegistryGuard::Config cfg;
    cfg.rule_id = "enforce-test";
    cfg.rule_name = "enforce flag";
    cfg.hive = "HKCU";
    cfg.key = kSubKeyA;
    cfg.value_name = "Flag";
    cfg.value_type = "REG_DWORD";
    cfg.expected = "1";
    cfg.enforce = true;

    std::mutex m;
    std::condition_variable cv;
    RegistryDrift captured;
    bool got = false;
    RegistryGuard guard(std::move(cfg), [&](const RegistryDrift& d) {
        std::lock_guard lk(m);
        captured = d;
        got = true;
        cv.notify_all();
    });

    // Arming runs an initial compare → detects 0 != 1 → enforces (writes 1 back)
    // BEFORE reporting, so by the time the sink fires the value is already fixed.
    auto d = run_once(guard, m, cv, got, captured);

    CHECK(get_dword(L"Flag") == 1u); // the syscall write restored it
    CHECK(d.detected_value == "0");
    CHECK(d.expected_value == "1");
    CHECK(d.remediation_attempted);
    CHECK(d.remediation_success);
    CHECK(d.remediation_action == "registry-write");
    INFO("remediation latency = " << d.remediation_latency_us << " us");
    CHECK(d.remediation_success); // (latency printed above on any failure)

    cleanup();
}

TEST_CASE("RegistryGuard audit: observes drift but does NOT write back",
          "[guardian][guard][audit][registry]") {
    set_dword(L"Flag2", 7); // WRONG (expected 1), but audit must leave it alone

    RegistryGuard::Config cfg;
    cfg.rule_id = "audit-test";
    cfg.hive = "HKCU";
    cfg.key = kSubKeyA;
    cfg.value_name = "Flag2";
    cfg.value_type = "REG_DWORD";
    cfg.expected = "1";
    cfg.enforce = false; // observe only

    std::mutex m;
    std::condition_variable cv;
    RegistryDrift captured;
    bool got = false;
    RegistryGuard guard(std::move(cfg), [&](const RegistryDrift& d) {
        std::lock_guard lk(m);
        captured = d;
        got = true;
        cv.notify_all();
    });

    auto d = run_once(guard, m, cv, got, captured);

    CHECK(d.detected_value == "7");
    CHECK_FALSE(d.remediation_attempted);
    CHECK(get_dword(L"Flag2") == 7u); // unchanged — audit never writes

    cleanup();
}

#else // ── Non-Windows: the guard is a no-op ─────────────────────────────────

TEST_CASE("RegistryGuard is a no-op off Windows", "[guardian][guard][registry]") {
    RegistryGuard::Config cfg;
    cfg.hive = "HKCU";
    cfg.enforce = true;
    RegistryGuard guard(std::move(cfg), [](const RegistryDrift&) {});
    CHECK_FALSE(guard.start());
}

#endif
