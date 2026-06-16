/// @file test_device_ui.cpp
/// Unit tests for the shared device-page PURE renderers (device_ui.cpp): the
/// fleet list, the Device-info / DEX / Guardian lenses. Data in, HTML out — no
/// store, no network.

#include "device_routes.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

using namespace yuzu::server;

TEST_CASE("device list: rows drill, filters echo, score badge", "[device][ui]") {
    DeviceRow d;
    d.agent_id = "agent-123456789abc";
    d.hostname = "WS-1";
    d.os = "windows";
    d.arch = "x86_64";
    d.agent_version = "0.12.0";
    d.online = true;
    d.last_seen = "now";
    d.dex_score = 82;
    const auto html = render_devices_list_fragment({d}, "", "all", "all", 1, 1);
    CHECK(html.find("WS-1") != std::string::npos);
    CHECK(html.find("/device?id=") != std::string::npos); // row drills to the device page
    CHECK(html.find(">82<") != std::string::npos);         // DEX score badge
    CHECK(html.find("Windows") != std::string::npos);
    // empty result set is an honest placeholder, not a crash
    CHECK(render_devices_list_fragment({}, "zzz", "all", "all", 0, 0).find("No devices match") !=
          std::string::npos);
}

TEST_CASE("device info lens: real fields; hardware honestly deferred", "[device][ui]") {
    DeviceRow d;
    d.agent_id = "a-1";
    d.hostname = "WS-1";
    d.os = "linux";
    d.arch = "x86_64";
    const auto html = render_device_info_fragment(d);
    CHECK(html.find("WS-1") != std::string::npos);
    CHECK(html.find("Identity") != std::string::npos);
    CHECK(html.find("inventory") != std::string::npos); // hardware/owner not fabricated
}

TEST_CASE("device DEX lens: score + signals + empty state", "[device][ui]") {
    std::vector<std::pair<std::string, std::int64_t>> sigs{{"process.crashed", 3}};
    const auto html = render_device_dex_lens("a-1", 71, sigs);
    CHECK(html.find("DEX experience") != std::string::npos);
    CHECK(html.find(">71<") != std::string::npos);
    CHECK(html.find("App crash") != std::string::npos); // dex_signal_label(process.crashed)
    const auto empty = render_device_dex_lens("a-1", 100, {});
    CHECK(empty.find("No DEX signals") != std::string::npos);
}

TEST_CASE("device Guardian lens: compliance summary + per-guard + empty", "[device][ui]") {
    std::vector<DeviceGuardRow> guards{{"Defender RTP", "compliant", "2026-06-16T10:00:00Z"},
                                       {"BitLocker", "drifted", "2026-06-16T10:00:00Z"}};
    const auto html = render_device_guardian_lens("a-1", guards);
    CHECK(html.find("Defender RTP") != std::string::npos);
    CHECK(html.find("Compliant") != std::string::npos); // summary tile label
    CHECK(html.find("50%") != std::string::npos);        // 1 of 2 compliant
    CHECK(html.find("drifted") != std::string::npos);    // state badge text
    CHECK(render_device_guardian_lens("a-1", {}).find("No guards evaluated") != std::string::npos);
}

TEST_CASE("device page: live-info button enabled online, disabled offline", "[device][ui]") {
    DeviceRow d;
    d.agent_id = "a-1";
    d.hostname = "WS-1";
    d.os = "windows";
    d.online = true;
    const auto on = render_device_page(d);
    CHECK(on.find("Get live info") != std::string::npos);
    // online → loads the live snapshot
    CHECK(on.find("/fragments/device/live?id=a-1") != std::string::npos);
    CHECK(on.find("device-live") != std::string::npos); // result mount present
    CHECK(on.find("disabled") == std::string::npos);    // button enabled

    d.online = false;
    const auto off = render_device_page(d);
    CHECK(off.find("disabled") != std::string::npos); // offline → disabled
    CHECK(off.find("device offline") != std::string::npos);
}

TEST_CASE("device live snapshot: state tiles + events + embedded live perf", "[device][ui]") {
    std::vector<DeviceLiveEvent> ev{
        {"Battery health", "battery", "capacity 76%", "2026-06-16T11:01:00Z"}};
    const auto html = render_device_live_snapshot("a-1", "capacity 76%", "2d 18h", ev);
    CHECK(html.find("Battery") != std::string::npos);
    CHECK(html.find("capacity 76%") != std::string::npos);
    CHECK(html.find("2d 18h") != std::string::npos); // uptime tile
    // embeds the existing (gated) live-perf dispatch, auto-loaded
    CHECK(html.find("/fragments/dex/device/perf?agent_id=a-1") != std::string::npos);
    CHECK(html.find("Recent events") != std::string::npos);
    // empty → honest "no events" (still embeds perf)
    CHECK(render_device_live_snapshot("a-1", "", "", {}).find("No recent DEX events") !=
          std::string::npos);
}
