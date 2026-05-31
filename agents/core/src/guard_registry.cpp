/**
 * guard_registry.cpp — see guard_registry.hpp.
 *
 * Windows: open the key, RegNotifyChangeKeyValue + WaitForMultipleObjects (notify
 * event + a stop event) — the blocking form from design §5.1.1, not the polling
 * form trigger_engine.cpp uses. Re-read + compare on every change; report drift to
 * the sink. Non-Windows: no-op (start() returns false).
 */

#include <yuzu/agent/guard_registry.hpp>

#include <spdlog/spdlog.h>

#include <chrono>

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <charconv>
#include <cstring>
#include <vector>

namespace yuzu::agent {
namespace {

HKEY parse_hive(const std::string& hive) {
    if (hive == "HKLM") return HKEY_LOCAL_MACHINE;
    if (hive == "HKCU") return HKEY_CURRENT_USER;
    if (hive == "HKCR") return HKEY_CLASSES_ROOT;
    if (hive == "HKU") return HKEY_USERS;
    return nullptr;
}

std::wstring to_wide(const std::string& s) {
    if (s.empty()) return {};
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (len <= 0) return {};
    std::wstring w(static_cast<size_t>(len), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, w.data(), len);
    if (!w.empty() && w.back() == L'\0') w.pop_back(); // drop the NUL the API appends
    return w;
}

std::string from_wide(const wchar_t* w, int wlen) {
    if (!w || wlen <= 0) return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, w, wlen, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return {};
    std::string s(static_cast<size_t>(len), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, wlen, s.data(), len, nullptr, nullptr);
    return s;
}

// REG_NOTIFY_CHANGE_LAST_SET catches value writes; _NAME catches add/delete of the
// value itself. Subtree is FALSE — we watch this key's values only.
constexpr DWORD kNotifyFilter = REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET;

// Read the watched value and string-encode it per the G4 convention (DWORD/QWORD =
// decimal, SZ/EXPAND_SZ = literal). Returns "<absent>" when the value is missing,
// "<unsupported-type>" for types this MVP slice doesn't decode (forces a drift
// rather than a silent false-match).
std::string read_value(HKEY key, const std::string& value_name) {
    std::wstring wname = to_wide(value_name);
    const wchar_t* name = value_name.empty() ? nullptr : wname.c_str();
    DWORD type = 0;
    DWORD size = 0;
    if (RegQueryValueExW(key, name, nullptr, &type, nullptr, &size) != ERROR_SUCCESS)
        return "<absent>";
    std::vector<BYTE> buf(size ? size : 1);
    if (RegQueryValueExW(key, name, nullptr, &type, buf.data(), &size) != ERROR_SUCCESS)
        return "<absent>";
    switch (type) {
    case REG_DWORD: {
        DWORD v = 0;
        if (size >= sizeof(DWORD)) std::memcpy(&v, buf.data(), sizeof(DWORD));
        return std::to_string(v);
    }
    case REG_QWORD: {
        unsigned long long v = 0;
        if (size >= sizeof(v)) std::memcpy(&v, buf.data(), sizeof(v));
        return std::to_string(v);
    }
    case REG_SZ:
    case REG_EXPAND_SZ: {
        int wlen = static_cast<int>(size / sizeof(wchar_t));
        const auto* wp = reinterpret_cast<const wchar_t*>(buf.data());
        while (wlen > 0 && wp[wlen - 1] == L'\0') --wlen; // strip trailing NUL(s)
        return from_wide(wp, wlen);
    }
    default:
        return "<unsupported-type>";
    }
}

// Re-encode `expected` per value_type and write it to value_name — the inverse
// of read_value(). Used only in enforce mode. Returns true on a successful
// RegSetValueExW. The write is bounded to the rule's `expected`: a fixed-value
// restore, never an arbitrary-write primitive — value name, type, and content
// all come from the (server-authored, signature-carrying) rule, not from any
// runtime input. Unsupported types are refused rather than written as garbage.
bool write_value(HKEY key, const std::string& value_name, const std::string& value_type,
                 const std::string& expected) {
    if (!key)
        return false;
    std::wstring wname = to_wide(value_name);
    const wchar_t* name = value_name.empty() ? nullptr : wname.c_str();
    if (value_type == "REG_DWORD") {
        DWORD v = 0;
        auto [ptr, ec] = std::from_chars(expected.data(), expected.data() + expected.size(), v);
        if (ec != std::errc{}) return false;
        return RegSetValueExW(key, name, 0, REG_DWORD, reinterpret_cast<const BYTE*>(&v),
                              sizeof(v)) == ERROR_SUCCESS;
    }
    if (value_type == "REG_QWORD") {
        unsigned long long v = 0;
        auto [ptr, ec] = std::from_chars(expected.data(), expected.data() + expected.size(), v);
        if (ec != std::errc{}) return false;
        return RegSetValueExW(key, name, 0, REG_QWORD, reinterpret_cast<const BYTE*>(&v),
                              sizeof(v)) == ERROR_SUCCESS;
    }
    if (value_type == "REG_SZ" || value_type == "REG_EXPAND_SZ") {
        std::wstring w = to_wide(expected);
        const DWORD bytes = static_cast<DWORD>((w.size() + 1) * sizeof(wchar_t)); // include NUL
        const DWORD t = (value_type == "REG_EXPAND_SZ") ? REG_EXPAND_SZ : REG_SZ;
        return RegSetValueExW(key, name, 0, t, reinterpret_cast<const BYTE*>(w.c_str()), bytes) ==
               ERROR_SUCCESS;
    }
    return false; // unsupported type — refuse rather than write garbage
}

} // namespace

RegistryGuard::RegistryGuard(Config cfg, Sink sink) : cfg_(std::move(cfg)), sink_(std::move(sink)) {}

RegistryGuard::~RegistryGuard() { stop(); }

bool RegistryGuard::start() {
    if (!parse_hive(cfg_.hive)) {
        spdlog::warn("Guardian RegistryGuard[{}]: invalid hive '{}'", cfg_.rule_id, cfg_.hive);
        return false;
    }
    HANDLE evt = CreateEventW(nullptr, /*manualReset=*/FALSE, /*initial=*/FALSE, nullptr);
    if (!evt) return false;
    stop_event_ = evt;
    stop_.store(false, std::memory_order_release);
    thread_ = std::thread([this] { run(); });
    return true;
}

void RegistryGuard::stop() {
    if (thread_.joinable()) {
        stop_.store(true, std::memory_order_release);
        if (stop_event_) SetEvent(static_cast<HANDLE>(stop_event_));
        thread_.join();
    }
    if (stop_event_) {
        CloseHandle(static_cast<HANDLE>(stop_event_));
        stop_event_ = nullptr;
    }
}

void RegistryGuard::run() {
    HKEY root = parse_hive(cfg_.hive);
    std::wstring wkey = to_wide(cfg_.key);
    HKEY key = nullptr;

    auto emit = [&](const std::string& detected, std::uint64_t latency_us) {
        if (detected == cfg_.expected) return; // compliant
        RegistryDrift d;
        d.rule_id = cfg_.rule_id;
        d.rule_name = cfg_.rule_name;
        d.detected_value = detected;
        d.expected_value = cfg_.expected;
        d.detection_latency_us = latency_us;
        // Enforce mode: restore the expected value BEFORE reporting (so the
        // self-write's RegNotify wakeup re-reads expected==expected and emit()
        // short-circuits — no remediation loop). `key` is captured by reference
        // and valid for every emit() after the open; on the open-failure path
        // it is nullptr, where write_value() returns false (reported as a failed
        // attempt). Out of scope for the MVP: creating an absent KEY.
        if (cfg_.enforce) {
            d.remediation_attempted = true;
            d.remediation_action = "registry-write";
            const auto r0 = std::chrono::steady_clock::now();
            const bool ok = write_value(key, cfg_.value_name, cfg_.value_type, cfg_.expected);
            d.remediation_latency_us = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::steady_clock::now() - r0)
                    .count());
            d.remediation_success = ok;
            if (ok)
                spdlog::info("Guardian RegistryGuard[{}]: enforced {}\\{} [{}] {} -> {} ({}us)",
                             cfg_.rule_id, cfg_.hive, cfg_.key, cfg_.value_name, detected,
                             cfg_.expected, d.remediation_latency_us);
            else
                spdlog::warn("Guardian RegistryGuard[{}]: enforce write FAILED for {}\\{} [{}] "
                             "(detected={}, type={})",
                             cfg_.rule_id, cfg_.hive, cfg_.key, cfg_.value_name, detected,
                             cfg_.value_type);
        }
        if (sink_) sink_(d);
    };

    const REGSAM access = KEY_NOTIFY | KEY_READ | (cfg_.enforce ? KEY_SET_VALUE : 0);
    if (RegOpenKeyExW(root, wkey.c_str(), 0, access, &key) != ERROR_SUCCESS) {
        // For registry-value-equals, a missing key means the value is absent →
        // that is itself drift. Report once; we can't arm a watch on a key that
        // doesn't exist (reconciliation would re-check later — deferred).
        spdlog::warn("Guardian RegistryGuard[{}]: cannot open {}\\{} — reporting value absent",
                     cfg_.rule_id, cfg_.hive, cfg_.key);
        emit("<absent>", 0);
        return;
    }

    HANDLE notify = CreateEventW(nullptr, /*manualReset=*/FALSE, /*initial=*/FALSE, nullptr);
    spdlog::info("Guardian RegistryGuard[{}]: watching {}\\{} [{}] (expect {}={})", cfg_.rule_id,
                 cfg_.hive, cfg_.key, cfg_.value_type, cfg_.value_name, cfg_.expected);

    // Initial compare — catch drift that already existed when the guard started.
    emit(read_value(key, cfg_.value_name), 0);

    while (!stop_.load(std::memory_order_acquire)) {
        if (RegNotifyChangeKeyValue(key, /*subtree=*/FALSE, kNotifyFilter, notify,
                                    /*async=*/TRUE) != ERROR_SUCCESS) {
            spdlog::warn("Guardian RegistryGuard[{}]: RegNotifyChangeKeyValue failed", cfg_.rule_id);
            break;
        }
        HANDLE handles[2] = {notify, static_cast<HANDLE>(stop_event_)};
        DWORD r = WaitForMultipleObjects(2, handles, FALSE, INFINITE);
        if (r != WAIT_OBJECT_0) break; // stop event signaled, or wait failed
        const auto t0 = std::chrono::steady_clock::now();
        std::string detected = read_value(key, cfg_.value_name);
        const auto latency = std::chrono::duration_cast<std::chrono::microseconds>(
                                 std::chrono::steady_clock::now() - t0)
                                 .count();
        emit(detected, static_cast<std::uint64_t>(latency));
    }

    if (notify) CloseHandle(notify);
    RegCloseKey(key);
}

} // namespace yuzu::agent

#else // ── Non-Windows: no-op (no registry) ───────────────────────────────────

namespace yuzu::agent {

RegistryGuard::RegistryGuard(Config cfg, Sink sink) : cfg_(std::move(cfg)), sink_(std::move(sink)) {}
RegistryGuard::~RegistryGuard() {}
bool RegistryGuard::start() { return false; }
void RegistryGuard::stop() {}
void RegistryGuard::run() {}

} // namespace yuzu::agent

#endif
