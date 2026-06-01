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
#include <thread>
#include <vector>

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

// ── Resilience harness (C1) ──────────────────────────────────────────────────
// A dedicated, quiet key tree so the guard's nearest-ancestor watch never sees
// unrelated churn from other processes (which would make the quiescence assertion
// flaky). The leaf `K` is the watched key; the parent stays put across K's
// delete/recreate so the ancestor we fall back to watching is always quiet.
constexpr const wchar_t* kResParentW = L"SOFTWARE\\YuzuGuardResilience";
constexpr const wchar_t* kResKeyW = L"SOFTWARE\\YuzuGuardResilience\\K";
constexpr const char* kResKeyA = "SOFTWARE\\YuzuGuardResilience\\K";

void res_make_parent() {
    HKEY k{};
    if (RegCreateKeyExW(HKEY_CURRENT_USER, kResParentW, 0, nullptr, 0, KEY_READ, nullptr, &k,
                        nullptr) == ERROR_SUCCESS)
        RegCloseKey(k);
}
void res_set_flag(DWORD v) {
    HKEY k{};
    if (RegCreateKeyExW(HKEY_CURRENT_USER, kResKeyW, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &k,
                        nullptr) == ERROR_SUCCESS) {
        RegSetValueExW(k, L"Flag", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&v), sizeof(v));
        RegCloseKey(k);
    }
}
DWORD res_get_flag() { // 0xFFFFFFFF = key/value absent
    HKEY k{};
    if (RegOpenKeyExW(HKEY_CURRENT_USER, kResKeyW, 0, KEY_READ, &k) != ERROR_SUCCESS)
        return 0xFFFFFFFFu;
    DWORD v = 0, sz = sizeof(v), type = 0;
    LONG rc = RegQueryValueExW(k, L"Flag", nullptr, &type, reinterpret_cast<BYTE*>(&v), &sz);
    RegCloseKey(k);
    return rc == ERROR_SUCCESS ? v : 0xFFFFFFFFu;
}
void res_delete_leaf() { RegDeleteKeyW(HKEY_CURRENT_USER, kResKeyW); } // removes K + its values
void res_cleanup() {
    RegDeleteKeyW(HKEY_CURRENT_USER, kResKeyW);
    RegDeleteKeyW(HKEY_CURRENT_USER, kResParentW);
}

// Captures EVERY drift (not just the first) so we can assert survival across a
// delete -> recreate cycle. wait_detected_after() waits for a drift carrying a
// given detected_value at or after a baseline index — robust to the 1s sink
// debounce and to the create-then-set race when a key is recreated.
struct DriftCollector {
    std::mutex m;
    std::condition_variable cv;
    std::vector<RegistryDrift> events;

    void operator()(const RegistryDrift& d) {
        std::lock_guard lk(m);
        events.push_back(d);
        cv.notify_all();
    }
    std::size_t size() {
        std::lock_guard lk(m);
        return events.size();
    }
    bool wait_detected_after(std::size_t from, const std::string& val,
                             std::chrono::milliseconds to) {
        std::unique_lock lk(m);
        return cv.wait_for(lk, to, [&] {
            for (std::size_t i = from; i < events.size(); ++i)
                if (events[i].detected_value == val) return true;
            return false;
        });
    }
    RegistryDrift find_detected(const std::string& val) { // most-recent matching drift
        std::lock_guard lk(m);
        for (auto it = events.rbegin(); it != events.rend(); ++it)
            if (it->detected_value == val) return *it;
        return {};
    }
};

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

TEST_CASE("RegistryGuard resilience: survives key deletion and re-detects after recreate",
          "[guardian][guard][registry][resilience]") {
    res_cleanup();        // clean slate
    res_make_parent();    // quiet ancestor that survives the leaf's delete/recreate
    res_set_flag(1);      // compliant (expected 1) — arming emits nothing

    RegistryGuard::Config cfg;
    cfg.rule_id = "resilience-test";
    cfg.rule_name = "resilience flag";
    cfg.hive = "HKCU";
    cfg.key = kResKeyA;
    cfg.value_name = "Flag";
    cfg.value_type = "REG_DWORD";
    cfg.expected = "1";
    cfg.enforce = false; // audit: observe only — no write-back to muddy the signal

    DriftCollector col;
    RegistryGuard guard(std::move(cfg), [&col](const RegistryDrift& d) { col(d); });
    REQUIRE(guard.start());

    using namespace std::chrono_literals;

    // (a) value drift while the key exists — baseline that the watch is live.
    res_set_flag(0);
    REQUIRE(col.wait_detected_after(0, "0", 5s));
    const auto n1 = col.size();
    std::this_thread::sleep_for(1200ms); // clear the 1s sink-debounce window

    // (b) delete the WHOLE key — the pre-C1 watch thread died at this point.
    res_delete_leaf();
    REQUIRE(col.wait_detected_after(n1, "<absent>", 5s));
    const auto n2 = col.size();
    std::this_thread::sleep_for(1200ms);

    // (c) recreate (compliant) so the guard re-arms on the new key, then drift it
    // again. ONLY a guard that SURVIVED the deletion and re-armed can report this
    // post-recreate drift — the C1 proof. (Re-detecting via a clean value change on
    // the re-armed key sidesteps the create-then-set race of recreate-with-drift.)
    res_set_flag(1);                     // recreate K, compliant (re-arm, ~no emit)
    std::this_thread::sleep_for(1200ms); // let the re-arm settle + clear debounce
    res_set_flag(0);                     // clean value drift on the re-armed key
    REQUIRE(col.wait_detected_after(n2, "0", 5s));

    guard.stop();
    res_cleanup();
}

TEST_CASE("RegistryGuard resilience: survives whole-chain delete + atomic recreate",
          "[guardian][guard][registry][resilience]") {
    res_cleanup();
    res_make_parent();
    res_set_flag(1); // K present, compliant

    RegistryGuard::Config cfg;
    cfg.rule_id = "wholechain-test";
    cfg.rule_name = "wholechain flag";
    cfg.hive = "HKCU";
    cfg.key = kResKeyA;
    cfg.value_name = "Flag";
    cfg.value_type = "REG_DWORD";
    cfg.expected = "1";
    cfg.enforce = false; // audit: observe only

    DriftCollector col;
    RegistryGuard guard(std::move(cfg), [&col](const RegistryDrift& d) { col(d); });
    REQUIRE(guard.start());
    using namespace std::chrono_literals;

    // Delete K AND its parent — the whole chain below HKCU\SOFTWARE is gone, so the
    // guard must walk PAST the dead parent to the nearest existing ancestor
    // (HKCU\SOFTWARE) to keep watching. That ancestor is busy, so assert
    // re-detection, not quiescence.
    res_cleanup();
    REQUIRE(col.wait_detected_after(0, "<absent>", 5s)); // detected via ancestor walk-up
    const auto n = col.size();
    std::this_thread::sleep_for(1200ms);

    // res_set_flag's RegCreateKeyExW recreates parent + K in ONE atomic call — the
    // multi-level create that reconcile()-from-scratch (not incremental descend)
    // exists to tolerate. Recreate compliant, let the guard re-arm, then drift it.
    res_set_flag(1);
    std::this_thread::sleep_for(1200ms);
    res_set_flag(0);
    REQUIRE(col.wait_detected_after(n, "0", 5s)); // re-detected despite whole-chain recreate

    guard.stop();
    res_cleanup();
}

TEST_CASE("RegistryGuard resilience: absent state is quiescent (no busy-spin)",
          "[guardian][guard][registry][resilience][quiescent]") {
    res_cleanup();
    res_make_parent();
    res_set_flag(0); // drift on arm so the first event proves the watch armed

    RegistryGuard::Config cfg;
    cfg.rule_id = "quiescent-test";
    cfg.hive = "HKCU";
    cfg.key = kResKeyA;
    cfg.value_name = "Flag";
    cfg.value_type = "REG_DWORD";
    cfg.expected = "1";
    cfg.enforce = false;

    DriftCollector col;
    RegistryGuard guard(std::move(cfg), [&col](const RegistryDrift& d) { col(d); });
    REQUIRE(guard.start());

    using namespace std::chrono_literals;
    REQUIRE(col.wait_detected_after(0, "0", 5s)); // armed + initial drift seen
    const auto n1 = col.size();
    std::this_thread::sleep_for(1200ms);          // clear debounce so absent emits

    res_delete_leaf();
    REQUIRE(col.wait_detected_after(n1, "<absent>", 5s)); // deletion detected
    const auto settled = col.size();

    // Key gone, the (quiet) ancestor armed → the thread must BLOCK on
    // WaitForMultipleObjects, not spin reconcile(). A spin would emit a fresh
    // absent drift every ~1s (the debounce window). Assert no new events arrive.
    std::this_thread::sleep_for(2500ms);
    CHECK(col.size() == settled);

    guard.stop();
    res_cleanup();
}

TEST_CASE("RegistryGuard enforce key-restore: recreates a deleted key + value (C2)",
          "[guardian][guard][registry][enforce][restore]") {
    res_cleanup();
    res_make_parent();
    res_set_flag(1); // key exists, compliant (expected 1)

    RegistryGuard::Config cfg;
    cfg.rule_id = "restore-test";
    cfg.rule_name = "restore flag";
    cfg.hive = "HKCU";
    cfg.key = kResKeyA;
    cfg.value_name = "Flag";
    cfg.value_type = "REG_DWORD";
    cfg.expected = "1";
    cfg.enforce = true; // enforce: must recreate the key when it's deleted

    DriftCollector col;
    RegistryGuard guard(std::move(cfg), [&col](const RegistryDrift& d) { col(d); });
    REQUIRE(guard.start());
    using namespace std::chrono_literals;

    // Delete the WHOLE key — enforce must RegCreateKeyExW it back + rewrite Flag.
    res_delete_leaf();
    REQUIRE(col.wait_detected_after(0, "<absent>", 5s));

    // Remediation runs inside emit() before the sink fires, so the key + value are
    // already restored by the time we observe the event.
    CHECK(res_get_flag() == 1u);
    auto d = col.find_detected("<absent>");
    CHECK(d.remediation_attempted);
    CHECK(d.remediation_success);
    CHECK(d.remediation_action == "registry-create");

    guard.stop();
    res_cleanup();
}

TEST_CASE("RegistryGuard audit: does NOT recreate a deleted key (C2 invariant)",
          "[guardian][guard][registry][audit][restore]") {
    res_cleanup();
    res_make_parent();
    res_set_flag(1); // key exists, compliant

    RegistryGuard::Config cfg;
    cfg.rule_id = "audit-norestore";
    cfg.hive = "HKCU";
    cfg.key = kResKeyA;
    cfg.value_name = "Flag";
    cfg.value_type = "REG_DWORD";
    cfg.expected = "1";
    cfg.enforce = false; // audit: observe only — must NOT recreate

    DriftCollector col;
    RegistryGuard guard(std::move(cfg), [&col](const RegistryDrift& d) { col(d); });
    REQUIRE(guard.start());
    using namespace std::chrono_literals;

    res_delete_leaf();
    REQUIRE(col.wait_detected_after(0, "<absent>", 5s)); // detects the deletion

    CHECK(res_get_flag() == 0xFFFFFFFFu);                // audit left the key gone
    CHECK_FALSE(col.find_detected("<absent>").remediation_attempted);

    guard.stop();
    res_cleanup();
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
