/**
 * test_disk_actions_local_dispatcher.cpp — loads the ACTUAL built disk_actions
 * plugin (disk_actions.dylib / .so / .dll) via PluginHandle::load and drives it
 * through yuzu::agent::LocalDispatcher, exercising the real per-OS legs on the
 * build host.
 *
 * RUNS ON ALL THREE PLATFORMS, deliberately and from the outset. The sibling
 * plugin's dispatcher TU shipped as `#ifndef _WIN32`, justified only by a
 * "Windows legs are compile-verified only" stance — and that exclusion is
 * precisely why a Windows leg whose implementation had been compiled out
 * entirely passed CI: no test ever loaded the Windows plugin. LocalDispatcher
 * and PluginHandle are both platform-neutral, so nothing technical requires the
 * exclusion, and the assertions below are scoped individually where their
 * SEMANTICS are platform-specific rather than excluding a whole platform.
 *
 * Note what a row-shape assertion can and cannot catch: a leg that is compiled
 * out can still emit a perfectly well-formed row. That is why the
 * build-completeness assertion below exists — it fails when a leg reports that
 * its OWN SDK guard excluded its implementation, which shape and vocabulary
 * checks cannot see.
 */
#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>
#include <yuzu/plugin.hpp>

#include "local_dispatcher.hpp"

#include "disk_actions_legs.hpp"
#include "disk_actions_parsers.hpp"

#include <cstddef>
#include <cstdlib>
#include <filesystem>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace fs = std::filesystem;

namespace {

/// Escape-aware field split. yuzu::util::safe_output_field escapes a literal
/// '|' as '\|', so a naive split('|') overcounts fields on any row whose text
/// happens to contain a pipe.
std::vector<std::string> split_fields_escape_aware(const std::string& row) {
    std::vector<std::string> out;
    std::string cur;
    for (std::size_t i = 0; i < row.size(); ++i) {
        if (row[i] == '\\' && i + 1 < row.size() && row[i + 1] == '|') {
            cur += '|';
            ++i;
        } else if (row[i] == '|') {
            out.push_back(cur);
            cur.clear();
        } else {
            cur += row[i];
        }
    }
    out.push_back(cur);
    return out;
}

std::vector<std::string> captured_rows(const std::string& captured) {
    std::vector<std::string> out;
    std::istringstream ss(captured);
    std::string line;
    while (std::getline(ss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!line.empty()) out.push_back(line);
    }
    return out;
}

bool one_of(const std::string& v, const char* const* set, std::size_t n) {
    for (std::size_t i = 0; i < n; ++i)
        if (v == set[i]) return true;
    return false;
}

/// Under `meson test` (MESON_BUILD_ROOT is always set) a missing plugin means
/// the build is genuinely broken and must NOT report "All tests passed".
void require_plugin_or_skip() {
    if (std::getenv("MESON_BUILD_ROOT") != nullptr) {
        FAIL("disk_actions plugin library not found under meson test — the plugin did not build, "
             "or link_depends is not forcing it to build before this test runs");
    }
    WARN("disk_actions plugin library not found -- skipping the LocalDispatcher round-trip");
}

#if defined(_WIN32)
constexpr const char* kPluginExt = ".dll";
#elif defined(__APPLE__)
constexpr const char* kPluginExt = ".dylib";
#else
constexpr const char* kPluginExt = ".so";
#endif

fs::path find_disk_actions_plugin() {
    const std::string lib_name = std::string{"disk_actions"} + kPluginExt;
    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT"))
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "disk_actions" /
                                lib_name);
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "disk_actions" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "disk_actions" / lib_name);
    for (const char* b : {"build-macos", "build-linux", "build-windows"})
        candidates.emplace_back(fs::path{b} / "agents" / "plugins" / "disk_actions" / lib_name);
    for (const auto& c : candidates)
        if (std::error_code ec; fs::exists(c, ec)) return c;
    return {};
}

struct LoadedPlugin {
    yuzu::agent::PluginHandle handle;
    const YuzuPluginDescriptor* descriptor{nullptr};
    explicit operator bool() const { return descriptor != nullptr; }
};

std::optional<LoadedPlugin> load_disk_actions_plugin() {
    auto path = find_disk_actions_plugin();
    if (path.empty()) return std::nullopt;
    // PluginHandle::load returns std::expected<PluginHandle, LoadError>.
    auto loaded = yuzu::agent::PluginHandle::load(path);
    if (!loaded) return std::nullopt;
    const auto* d = loaded->descriptor();
    if (!d) return std::nullopt;
    return LoadedPlugin{std::move(*loaded), d};
}

// Fixed vocabularies, mirrored from disk_actions_legs.hpp. Deliberately spelled
// out rather than derived, so a silent change to the emitted token set fails
// here instead of passing by construction.
const char* kHealth[] = {"ok", "warning", "failing", "unknown", "unsupported"};
const char* kBus[] = {"nvme", "sata", "usb", "sas", "virtual", "unknown"};
const char* kMedia[] = {"ssd", "hdd", "unknown"};

} // namespace

TEST_CASE("disk_actions plugin: smart action row shape", "[disk_actions][actions]") {
    auto plugin = load_disk_actions_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "smart");
    CHECK(result.rc == 0); // a degraded read is never a failed command

    const auto rows = captured_rows(result.captured);
    // Every leg emits at least one row, including the honest unsupported one:
    // a consumer reading rows must never see silence and infer "no drives".
    REQUIRE_FALSE(rows.empty());

    for (const auto& r : rows) {
        const auto f = split_fields_escape_aware(r);
        REQUIRE(f.size() == 9);
        CHECK(f[0] == "smart");
        CHECK(one_of(f[3], kBus, std::size(kBus)));
        CHECK(one_of(f[4], kMedia, std::size(kMedia)));
        CHECK(one_of(f[5], kHealth, std::size(kHealth)));
    }
}

TEST_CASE("disk_actions plugin: volumes action row shape", "[disk_actions][actions]") {
    auto plugin = load_disk_actions_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "volumes");
    CHECK(result.rc == 0);

    const auto rows = captured_rows(result.captured);
    REQUIRE_FALSE(rows.empty());

    for (const auto& r : rows) {
        const auto f = split_fields_escape_aware(r);
        REQUIRE(f.size() == 7);
        CHECK(f[0] == "volume");
    }
}

// K2 / FV-3 (both external reviewers, independently): nothing asserted
// result_status, so every mark_result_* call could be deleted and the suite
// would stay green. LocalDispatcher::Result exposes the seam precisely so a
// test can prove it fires.
TEST_CASE("disk_actions: a degraded read reports through the typed status seam",
          "[disk_actions][status]") {
    auto plugin = load_disk_actions_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;

#if defined(__APPLE__)
    // The macOS smart leg is CONSTRAINED by construction: it reads identity and
    // capability but never health, and says so unconditionally after the walk.
    // If this ever reports clean, the leg has started claiming to know
    // something it does not.
    auto smart = dispatcher.run(plugin->descriptor, "smart");
    CHECK(smart.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(smart.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(smart.result_provenance == "macos:iokit");
#elif defined(__linux__)
    // K5 + spec F5: the Linux legs are not implemented, which is UNAVAILABLE
    // ("this platform cannot do this"), never CONSTRAINED ("partial data") --
    // there is no data at all.
    auto smart = dispatcher.run(plugin->descriptor, "smart");
    CHECK(smart.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
    CHECK(smart.result_provenance == "linux:smart");
    auto vols = dispatcher.run(plugin->descriptor, "volumes");
    CHECK(vols.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
    CHECK(vols.result_provenance == "linux:volumes");
#else
    // Windows: a healthy admin host reads every drive, so no degradation is
    // guaranteed. What IS guaranteed is that the status is never a value the
    // plugin cannot produce -- and that a degraded run always names a
    // provenance rather than degrading anonymously.
    auto smart = dispatcher.run(plugin->descriptor, "smart");
    const bool declared = smart.result_status == YUZU_RESULT_STATUS_UNDECLARED;
    const bool degraded = smart.result_status == YUZU_RESULT_STATUS_CONSTRAINED ||
                          smart.result_status == YUZU_RESULT_STATUS_PERMISSION_DENIED;
    CHECK((declared || degraded));
    if (degraded) CHECK_FALSE(smart.result_provenance.empty());
#endif
}

// K6: the macOS leg must never GUESS health. The fixed-vocabulary check alone
// permits `ok`, so a regression to a guessed value -- the exact dishonesty the
// spike ruling rejected -- would pass it.
#if defined(__APPLE__)
TEST_CASE("disk_actions: macOS never reports a health value it did not read",
          "[disk_actions][actions]") {
    auto plugin = load_disk_actions_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "smart");
    const auto rows = captured_rows(result.captured);
    REQUIRE_FALSE(rows.empty());
    for (const auto& r : rows) {
        const auto f = split_fields_escape_aware(r);
        REQUIRE(f.size() == 9);
        INFO("row: " << r);
        // Health attributes need a private Apple interface this plugin does
        // not use, so `unknown` is the only honest answer on this platform.
        CHECK(f[5] == "unknown");
    }
}

// K1 / FV-2 (both reviewers, independently): the APFS physical-store
// resolution is the anchor behaviour of this action and was shipped WRONG in
// an earlier revision of this very change -- `/` resolved to disk3, a
// synthesized AppleAPFSMedia container that is not hardware. Nothing asserted
// it, so the defect could return silently.
TEST_CASE("disk_actions: macOS resolves volumes to a real physical disk, not an APFS container",
          "[disk_actions][actions]") {
    auto plugin = load_disk_actions_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;

    // The set of whole physical disks, taken from the OTHER action rather than
    // hardcoded: smart enumerates IOBlockStorageDevice, which is by definition
    // physical hardware. A synthesized APFS container never appears there.
    std::set<std::string> physical;
    for (const auto& r : captured_rows(dispatcher.run(plugin->descriptor, "smart").captured)) {
        const auto f = split_fields_escape_aware(r);
        if (f.size() == 9 && f[1] != "-") physical.insert(f[1]);
    }
    REQUIRE_FALSE(physical.empty());

    const auto rows = captured_rows(dispatcher.run(plugin->descriptor, "volumes").captured);
    REQUIRE_FALSE(rows.empty());
    bool checked_any = false;
    for (const auto& r : rows) {
        const auto f = split_fields_escape_aware(r);
        REQUIRE(f.size() == 7);
        if (f[3] == "-") continue; // no backing device resolved; not this test's subject
        INFO("row: " << r);
        // THE assertion: the device column names a disk the physical
        // enumeration knows about. A synthesized container (diskN with no
        // IOBlockStorageDevice behind it) fails here, which is exactly the
        // pre-fix behaviour.
        CHECK(physical.count(f[3]) == 1);
        checked_any = true;
    }
    CHECK(checked_any);
}

// Adversarial review (2026-09-04, KMI-1/CDX-006): the macOS leg used bare
// `getmntinfo(3)`, whose process-owned static buffer may be overwritten or
// freed by a concurrent caller in another dylib. The fix moved it to
// `getmntinfo_r_np`, which hands the caller its own allocation.
//
// That fix is silently reversible in the worst way: if the replacement ever
// returns nothing, every row simply reports "-" for mount points, which is a
// LEGITIMATE value meaning "this volume serves no mount point". The action
// would keep passing every other test while the join it exists to produce
// quietly disappeared. The APFS anchor test above does not cover this -- it
// asserts the DEVICE column (the provider walk), not the mount-point column.
//
// So assert the mount side positively: a macOS host always mounts root.
TEST_CASE("disk_actions: macOS reports real mount points, not an empty join",
          "[disk_actions][actions]") {
    auto plugin = load_disk_actions_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;

    const auto rows = captured_rows(dispatcher.run(plugin->descriptor, "volumes").captured);
    REQUIRE_FALSE(rows.empty());

    bool saw_root_mount = false;
    for (const auto& r : rows) {
        const auto f = split_fields_escape_aware(r);
        REQUIRE(f.size() == 7);
        if (f[2] == "-") continue; // genuinely serves no mount point
        INFO("row: " << r);
        // Comma-delimited; the sentinels make this an exact element match, so
        // a mount point merely CONTAINING "/" cannot satisfy it.
        if (("," + f[2] + ",").find(",/,") != std::string::npos) saw_root_mount = true;
    }
    // If this fails, getmntinfo_r_np returned no usable entries and the
    // physical-to-logical join is empty on every row.
    CHECK(saw_root_mount);
}
#endif // __APPLE__

TEST_CASE("disk_actions plugin: an unknown action is refused, not silently ignored",
          "[disk_actions][actions]") {
    auto plugin = load_disk_actions_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "no_such_action");
    CHECK(result.rc != 0);
}

// ── pure formatter tests: no plugin load, no OS call ─────────────────────

TEST_CASE("disk_actions: an absent percentage renders as '-', never as 0",
          "[disk_actions][format]") {
    using namespace yuzu::disk_actions;
    // "we did not read this" and "this is zero" are different facts, and a
    // consumer keying on the column must be able to tell them apart.
    const auto absent = format_smart_row("d", "m", Bus::Nvme, Media::Ssd, Health::Unknown,
                                         std::nullopt, std::nullopt, "-");
    CHECK(absent == "smart|d|m|nvme|ssd|unknown|-|-|-");

    const auto zero = format_smart_row("d", "m", Bus::Nvme, Media::Ssd, Health::Ok,
                                       std::optional<std::uint8_t>{0},
                                       std::optional<std::uint8_t>{0}, "-");
    CHECK(zero == "smart|d|m|nvme|ssd|ok|0|0|-");
}

TEST_CASE("disk_actions: wear above 100% is reported as read, spare is clamped",
          "[disk_actions][format]") {
    using namespace yuzu::disk_actions;
    // The two percentage columns have DIFFERENT contracts and must not share a
    // formatter. Per the NVMe Base Specification, `Percentage Used` is allowed
    // to exceed 100 (a drive past its rated endurance) and saturates at 255,
    // while `Available Spare` is genuinely 0..100.
    //
    // This test previously asserted BOTH columns rendered "100", which pinned a
    // real defect: every drive between 101% and 255% wear was reported as
    // exactly 100, so a fleet view could not tell a drive at its rated limit
    // from one far beyond it, nor trend toward failure.
    const auto r = format_smart_row("d", "m", Bus::Nvme, Media::Ssd, Health::Warning,
                                    std::optional<std::uint8_t>{255},
                                    std::optional<std::uint8_t>{200}, "-");
    CHECK(r == "smart|d|m|nvme|ssd|warning|255|100|-");

    // The ordinary in-range case is unchanged, and a wear value just past the
    // rated limit survives intact rather than collapsing onto 100.
    const auto worn = format_smart_row("d", "m", Bus::Nvme, Media::Ssd, Health::Warning,
                                       std::optional<std::uint8_t>{101},
                                       std::optional<std::uint8_t>{7}, "-");
    CHECK(worn == "smart|d|m|nvme|ssd|warning|101|7|-");
}

TEST_CASE("disk_actions: untrusted fields cannot forge a column separator",
          "[disk_actions][format]") {
    using namespace yuzu::disk_actions;
    // A drive model is OS-supplied text. If it could inject a bare '|' it would
    // shift every later column for a positional consumer.
    const auto r = format_smart_row("dev", "EVIL|MODEL", Bus::Unknown, Media::Unknown,
                                    Health::Unknown, std::nullopt, std::nullopt, "-");
    const auto f = split_fields_escape_aware(r);
    REQUIRE(f.size() == 9);
    CHECK(f[2] == "EVIL|MODEL"); // round-trips through the escape, one field
}

TEST_CASE("disk_actions: the volume row carries the physical-to-logical join",
          "[disk_actions][format]") {
    using namespace yuzu::disk_actions;
    // The reason this action exists: which physical device backs which mount
    // points. Neither hardware.disks nor filesystem_posture.mounts answers it.
    const auto r = format_volume_row("disk0s2", "/,/System/Volumes/Data", "disk0", "apfs",
                                     std::optional<std::uint64_t>{494384795648}, "-");
    CHECK(r == "volume|disk0s2|/,/System/Volumes/Data|disk0|apfs|494384795648|-");
}

// ── pure NVMe decision tests (K4 / FV-1) ────────────────────────────────
//
// These exist because the decision a failing-drive alert keys on used to live
// in an anonymous namespace inside a _WIN32-only TU, where no test on any
// platform could reach it. Both external reviewers reported that a wrong
// bitmask or a shifted byte offset would ship green. The logic now lives in
// disk_actions_parsers.hpp and these run everywhere.

TEST_CASE("disk_actions: NVMe critical-warning bits map to the right verdict",
          "[disk_actions][nvme]") {
    using namespace yuzu::disk_actions;
    CHECK(nvme_verdict(0x00) == NvmeVerdict::Ok);
    // Bit 0 (spare below threshold) and bit 2 (reliability degraded) are the
    // two an operator must act on.
    CHECK(nvme_verdict(kNvmeWarnSpareBelowThreshold) == NvmeVerdict::Failing);
    CHECK(nvme_verdict(kNvmeWarnReliabilityDegraded) == NvmeVerdict::Failing);
    // Other defined warnings are real, but not "replace this drive now".
    CHECK(nvme_verdict(kNvmeWarnTemperature) == NvmeVerdict::Warning);
    CHECK(nvme_verdict(kNvmeWarnReadOnly) == NvmeVerdict::Warning);
    CHECK(nvme_verdict(kNvmeWarnVolatileMemoryBackupFailed) == NvmeVerdict::Warning);
    // A bit this code does not recognise is still a warning -- never Ok.
    // Treating an unknown warning as healthy is what makes a fleet view lie.
    CHECK(nvme_verdict(0x80) == NvmeVerdict::Warning);
    // Failing dominates when both classes are set.
    CHECK(nvme_verdict(kNvmeWarnSpareBelowThreshold | kNvmeWarnTemperature) ==
          NvmeVerdict::Failing);
}

TEST_CASE("disk_actions: the NVMe log-page offsets are pinned to their meaning",
          "[disk_actions][nvme]") {
    using namespace yuzu::disk_actions;
    std::array<std::byte, 512> page{};
    page[kNvmeCriticalWarningOffset] = std::byte{0x04}; // reliability degraded
    page[kNvmeAvailableSpareOffset] = std::byte{77};
    page[kNvmePercentageUsedOffset] = std::byte{42};

    const auto h = decode_nvme_health(page);
    REQUIRE(h.has_value());
    CHECK(h->critical_warning == 0x04);
    CHECK(h->available_spare == 77);
    CHECK(h->percentage_used == 42);
    CHECK(nvme_verdict(h->critical_warning) == NvmeVerdict::Failing);
}

TEST_CASE("disk_actions: a short NVMe reply is a failure to report, not a healthy zero",
          "[disk_actions][nvme]") {
    using namespace yuzu::disk_actions;
    // A device that answered with less than it promised must not decode to an
    // all-zero (i.e. perfectly healthy) reading.
    std::array<std::byte, kNvmeHealthMinBytes - 1> truncated{};
    CHECK_FALSE(decode_nvme_health(truncated).has_value());
    std::array<std::byte, kNvmeHealthMinBytes> exact{};
    CHECK(decode_nvme_health(exact).has_value());
}

TEST_CASE("disk_actions: the name-derived whole disk is WRONG for APFS, deliberately",
          "[disk_actions][nvme]") {
    using namespace yuzu::disk_actions;
    // Pins the distinction that the macOS leg exists to honour. For an
    // ordinary partition the string shortcut is right...
    CHECK(name_derived_whole_disk("disk0s2") == "disk0");
    CHECK(name_derived_whole_disk("disk0") == "disk0");
    // ...but for an APFS volume on a synthesized container it yields the
    // CONTAINER (disk3), which is not hardware. That is why the leg walks the
    // IOKit provider chain instead of trimming the name, and why a future
    // "simplification" back to string handling would reintroduce the defect.
    CHECK(name_derived_whole_disk("disk3s1s1") == "disk3");
}

// ── FV-4: escaping is a contract over EVERY untrusted field ─────────────
//
// The original test proved it for one field (`model`). A bare separator could
// regress in any other text column without failing anything.

TEST_CASE("disk_actions: every untrusted text field survives separator injection",
          "[disk_actions][format]") {
    using namespace yuzu::disk_actions;
    const std::string evil = "a|b";

    // smart: device (1), model (2), detail (8) are the untrusted text columns;
    // bus/media/health are fixed vocabularies and must NOT be escapable at all.
    {
        const auto f = split_fields_escape_aware(
            format_smart_row(evil, "m", Bus::Nvme, Media::Ssd, Health::Ok, std::nullopt,
                             std::nullopt, "d"));
        REQUIRE(f.size() == 9);
        CHECK(f[1] == evil);
    }
    {
        const auto f = split_fields_escape_aware(
            format_smart_row("dev", "m", Bus::Nvme, Media::Ssd, Health::Ok, std::nullopt,
                             std::nullopt, evil));
        REQUIRE(f.size() == 9);
        CHECK(f[8] == evil);
    }
    // volume: volume (1), mount_points (2), device (3), fstype (4), detail (6).
    for (int field = 1; field <= 6; ++field) {
        if (field == 5) continue; // total_bytes is numeric, not text
        const std::string v = field == 1 ? evil : "vol";
        const std::string m = field == 2 ? evil : "-";
        const std::string d = field == 3 ? evil : "-";
        const std::string t = field == 4 ? evil : "-";
        const std::string det = field == 6 ? evil : "-";
        const auto f = split_fields_escape_aware(format_volume_row(v, m, d, t, std::nullopt, det));
        INFO("injected into volume field " << field);
        REQUIRE(f.size() == 7);
        CHECK(f[field] == evil);
    }
}
