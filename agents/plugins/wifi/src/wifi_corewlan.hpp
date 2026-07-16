/**
 * wifi_corewlan.hpp — macOS current-Wi-Fi-connection query via CoreWLAN.
 *
 * CoreWLAN is an Objective-C framework, so the implementation lives in the
 * sibling Objective-C++ translation unit `wifi_corewlan.mm` (the first `.mm`
 * TU in the tree). This header is plain C++ so `wifi_plugin.cpp` can call in
 * without itself being compiled as Objective-C++.
 *
 * Replaces the dead `airport -I` shell-out: the private `airport` binary was
 * removed in macOS 14 (Sonoma), so the old path returned nothing and the agent
 * always reported "Not connected" even while associated.
 *
 * Location Services caveat (macOS 14+): `ssid` and `bssid` are gated behind
 * Location Services authorisation. A background LaunchDaemon has no practical
 * way to obtain it, so on modern macOS those two fields are typically withheld
 * (returned nil) even for a live association. Everything else — power state,
 * association, RSSI, channel, security, interface name — is returned without
 * authorisation, so we can honestly report a connection and mark SSID/BSSID as
 * withheld rather than falsely claiming "Not connected". See docs/darwin-compat.md.
 */
#pragma once

#ifdef __APPLE__

#include <string>

namespace yuzu::wifi {

struct WifiConnection {
    bool power_on = false;        // Wi-Fi radio powered on
    bool associated = false;      // joined to a network (has a live channel)
    bool ssid_available = false;  // false → withheld by Location Services, NOT "hidden"
    std::string ssid;             // valid only when ssid_available
    std::string bssid;            // empty when withheld / not associated
    int rssi = 0;                 // dBm; 0 when not associated
    int channel = 0;              // 0 when not associated
    std::string security;         // human-readable; empty when unknown
    std::string interface;        // e.g. "en0"; empty when no Wi-Fi hardware
};

// Populates `out` from the default Wi-Fi interface via CoreWLAN.
// Returns false only when the host has no Wi-Fi interface at all; a powered-off
// or unassociated radio still returns true (with associated == false).
bool corewlan_current_connection(WifiConnection& out);

} // namespace yuzu::wifi

#endif // __APPLE__
