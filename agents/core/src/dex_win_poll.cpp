#include "dex_win_poll.hpp"

#include <algorithm>
#include <string>
#include <utility>

namespace yuzu::agent::win {

// ── Pure decision functions (every platform — unit-tested off Windows) ───────

std::optional<SignalObservation> low_disk_observation(const DiskLevel& level,
                                                      const std::string& volume) {
    if (!level.valid || level.total_bytes == 0)
        return std::nullopt;
    constexpr std::uint64_t kFiveGiB = 5ULL * 1024 * 1024 * 1024;
    const std::uint64_t used =
        level.total_bytes - std::min(level.free_bytes, level.total_bytes);
    const int used_pct = static_cast<int>((used * 100) / level.total_bytes);
    if (used_pct < 90 && level.free_bytes >= kFiveGiB)
        return std::nullopt; // healthy
    SignalObservation o;
    o.obs_type = "storage.low";
    o.subject = volume.empty() ? "disk" : volume;
    o.reason = std::to_string(used_pct) + "% full";
    o.metric = static_cast<double>(used_pct);
    o.sentence = "Disk nearly full: " + o.reason + " (" +
                 std::to_string(level.free_bytes / (1024 * 1024)) + " MB free) on " + o.subject;
    return o;
}

std::optional<SignalObservation> battery_observation(const BatteryHealth& h) {
    if (!h.valid || h.designed_capacity == 0)
        return std::nullopt; // no battery / no ratio — never a failure
    const int pct = static_cast<int>(
        (static_cast<std::uint64_t>(h.full_charged_capacity) * 100) / h.designed_capacity);
    if (pct >= 80)
        return std::nullopt; // healthy (a fresh cell can even read above design)
    SignalObservation o;
    o.obs_type = "hw.error"; // generic Hardware obs_type — mirrors the macOS battery signal
    o.subject = "battery";
    o.reason = "capacity " + std::to_string(pct) + "%";
    o.metric = static_cast<double>(pct);
    o.sentence = "Battery health degraded: " + o.reason +
                 (h.cycle_count > 0 ? " (" + std::to_string(h.cycle_count) + " cycles)" : "");
    return o;
}

} // namespace yuzu::agent::win

// ── Win32 mechanism ──────────────────────────────────────────────────────────

#if defined(_WIN32)

#include "guard_win_handle.hpp" // <windows.h> + ScopedWinHandle RAII

#include <initguid.h>  // make the DEFINE_GUIDs below *definitions* (DECLSPEC_SELECTANY)
#include <batclass.h>  // GUID_DEVICE_BATTERY, IOCTL_BATTERY_*, BATTERY_INFORMATION
#include <setupapi.h>

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>

#include <spdlog/spdlog.h>

#pragma comment(lib, "setupapi.lib") // SetupDiGetClassDevsW / battery interface enum

namespace yuzu::agent::win {
namespace {

std::int64_t now_unix() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

struct DiskReading {
    std::string volume;
    DiskLevel level;
};

// Lettered fixed volumes only (GetLogicalDrives): EFI/recovery partitions carry
// no letter, so they can never read as "full" noise. A volume whose free-space
// query fails (BitLocker-locked, card reader posing as DRIVE_FIXED with no
// media) is skipped — never a signal.
std::vector<DiskReading> read_fixed_disks() {
    std::vector<DiskReading> out;
    const DWORD mask = ::GetLogicalDrives();
    for (int i = 0; i < 26; ++i) {
        if (!(mask & (1u << i)))
            continue;
        wchar_t root[] = L"A:\\";
        root[0] = static_cast<wchar_t>(L'A' + i);
        if (::GetDriveTypeW(root) != DRIVE_FIXED)
            continue;
        ULARGE_INTEGER free_caller{}, total{}, free_total{};
        if (!::GetDiskFreeSpaceExW(root, &free_caller, &total, &free_total))
            continue;
        DiskReading r;
        r.volume = std::string(1, static_cast<char>('A' + i)) + ":";
        r.level.valid = true;
        r.level.total_bytes = total.QuadPart;
        // Volume-wide free, not caller-quota free: the agent service's quota is
        // irrelevant to whether the *user's* disk is full.
        r.level.free_bytes = free_total.QuadPart;
        out.push_back(std::move(r));
    }
    return out;
}

// First system battery via the battery device interface + query IOCTLs (the
// canonical native source for DesignedCapacity / FullChargedCapacity /
// CycleCount — WMI not required). Battery query IOCTLs are FILE_READ_ACCESS, so
// GENERIC_READ suffices (least privilege). Desktop with no battery → valid
// stays false → never emits, mirroring the macOS parser contract.
BatteryHealth read_battery() {
    BatteryHealth h;
    HDEVINFO devs = ::SetupDiGetClassDevsW(&GUID_DEVICE_BATTERY, nullptr, nullptr,
                                           DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (devs == INVALID_HANDLE_VALUE)
        return h;
    SP_DEVICE_INTERFACE_DATA did{};
    did.cbSize = sizeof(did);
    if (::SetupDiEnumDeviceInterfaces(devs, nullptr, &GUID_DEVICE_BATTERY, 0, &did)) {
        DWORD needed = 0;
        ::SetupDiGetDeviceInterfaceDetailW(devs, &did, nullptr, 0, &needed, nullptr);
        if (needed >= sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W)) {
            std::vector<unsigned char> buf(needed);
            auto* detail = reinterpret_cast<SP_DEVICE_INTERFACE_DETAIL_DATA_W*>(buf.data());
            detail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);
            if (::SetupDiGetDeviceInterfaceDetailW(devs, &did, detail, needed, nullptr,
                                                   nullptr)) {
                detail::EventHandle bat{::CreateFileW(detail->DevicePath, GENERIC_READ,
                                                      FILE_SHARE_READ | FILE_SHARE_WRITE,
                                                      nullptr, OPEN_EXISTING,
                                                      FILE_ATTRIBUTE_NORMAL, nullptr)};
                if (bat) {
                    ULONG wait_ms = 0; // don't block waiting for a tag
                    ULONG tag = 0;
                    DWORD out_bytes = 0;
                    if (::DeviceIoControl(bat.get(), IOCTL_BATTERY_QUERY_TAG, &wait_ms,
                                          sizeof(wait_ms), &tag, sizeof(tag), &out_bytes,
                                          nullptr) &&
                        tag != 0) {
                        BATTERY_QUERY_INFORMATION bqi{};
                        bqi.BatteryTag = tag;
                        bqi.InformationLevel = BatteryInformation;
                        BATTERY_INFORMATION bi{};
                        if (::DeviceIoControl(bat.get(), IOCTL_BATTERY_QUERY_INFORMATION, &bqi,
                                              sizeof(bqi), &bi, sizeof(bi), &out_bytes,
                                              nullptr)) {
                            h.valid = true;
                            h.designed_capacity = bi.DesignedCapacity;
                            h.full_charged_capacity = bi.FullChargedCapacity;
                            h.cycle_count = bi.CycleCount;
                        }
                    }
                }
            }
        }
    }
    ::SetupDiDestroyDeviceInfoList(devs);
    return h;
}

/// Windows state poller. Lifetime is deliberately SIMPLE (the macOS engine's
/// rationale, not the EvtSubscribe one): this object owns its own thread, stop()
/// joins it, and the sink is set before the thread starts and cleared after the
/// join — no OS threadpool can outlive the object, so no leaked-shared_ptr
/// machinery is needed.
class WinStatePoller final : public IStatePoller {
public:
    ~WinStatePoller() override { stop(); }

    void start(SignalSink sink) override {
        if (thread_.joinable())
            return; // already running (idempotent)
        sink_ = std::move(sink);
        stopping_ = false;
        thread_ = std::thread([this] { run(); });
    }

    void stop() override {
        {
            std::lock_guard lk(mu_);
            stopping_ = true;
        }
        cv_.notify_all();
        if (thread_.joinable())
            thread_.join();
        sink_ = nullptr;
    }

private:
    void run() {
        // First poll 60 s after arm (never at-arm — arm-time work delays agent
        // startup), then each poll keeps its own cadence.
        {
            const std::int64_t now = now_unix();
            last_disk_poll_ = now - kDiskIntervalSeconds + kFirstPollDelaySeconds;
            last_battery_poll_ = now - kBatteryIntervalSeconds + kFirstPollDelaySeconds;
        }
        for (;;) {
            // Sleep until the EARLIEST next-due poll, not a fixed short tick —
            // ~6 thread wakes/hour instead of 60 (kind to the endpoint,
            // especially on battery). stop() interrupts the wait via the cv.
            // (std::min) — windows.h's min/max macros are in scope in this TU.
            const std::int64_t next = (std::min)(last_disk_poll_ + kDiskIntervalSeconds,
                                                 last_battery_poll_ + kBatteryIntervalSeconds);
            const auto wait_s =
                std::chrono::seconds((std::max)(next - now_unix(), std::int64_t{1}));
            {
                std::unique_lock lk(mu_);
                if (cv_.wait_for(lk, wait_s, [this] { return stopping_; }))
                    return;
            }
            const std::int64_t now = now_unix();
            if (now - last_disk_poll_ >= kDiskIntervalSeconds) {
                last_disk_poll_ = now;
                poll_disks();
            }
            if (now - last_battery_poll_ >= kBatteryIntervalSeconds) {
                last_battery_poll_ = now;
                poll_battery();
            }
        }
    }

    // Poll-and-diff latch discipline (the macOS engine's): emit on the
    // transition INTO a bad state, suppress while it persists, re-arm on
    // recovery — a disk that stays full must not re-fire every 10 minutes.
    void poll_disks() {
        for (const auto& r : read_fixed_disks()) {
            auto obs = low_disk_observation(r.level, r.volume);
            bool& reported = disk_low_reported_[r.volume];
            if (obs && !reported) {
                reported = true;
                emit(std::move(*obs));
            } else if (!obs) {
                reported = false;
            }
        }
    }

    void poll_battery() {
        auto obs = battery_observation(read_battery());
        if (obs && !battery_bad_reported_) {
            battery_bad_reported_ = true;
            emit(std::move(*obs));
        } else if (!obs) {
            battery_bad_reported_ = false;
        }
    }

    // Stamp platform + delivery time centrally (an empty platform would vanish
    // from the by-OS panel). The latch bounds emission, so no rate cap is needed.
    void emit(SignalObservation obs) {
        obs.platform = "windows";
        obs.timestamp_unix = now_unix();
        spdlog::info("dex_win_poll: observed {} subject='{}' reason={}", obs.obs_type,
                     obs.subject, obs.reason);
        try {
            sink_(obs);
        } catch (...) {
            // The sink does a network write — a failure there must not kill the
            // poll thread.
        }
    }

    static constexpr std::int64_t kFirstPollDelaySeconds = 60;
    static constexpr std::int64_t kDiskIntervalSeconds = 600;     // 10 min
    static constexpr std::int64_t kBatteryIntervalSeconds = 3600; // hourly

    std::mutex mu_;
    std::condition_variable cv_;
    bool stopping_ = false;
    std::thread thread_;
    SignalSink sink_; // set before the thread starts, cleared after join — stable in run()
    std::int64_t last_disk_poll_ = 0;
    std::int64_t last_battery_poll_ = 0;
    std::unordered_map<std::string, bool> disk_low_reported_; // per-volume latch
    bool battery_bad_reported_ = false;
};

} // namespace

std::unique_ptr<IStatePoller> make_win_state_poller() {
    return std::make_unique<WinStatePoller>();
}

} // namespace yuzu::agent::win

#else // !_WIN32 — no-op so the factory exists on every platform

namespace yuzu::agent::win {
namespace {
class NoopStatePoller final : public IStatePoller {
public:
    void start(SignalSink) override {}
    void stop() override {}
};
} // namespace

std::unique_ptr<IStatePoller> make_win_state_poller() {
    return std::make_unique<NoopStatePoller>();
}

} // namespace yuzu::agent::win

#endif
