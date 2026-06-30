#pragma once

/// @file sync_source_installed_software.hpp
/// The `installed_software` daily-sync source (ADR-0016) — source #1 of the
/// agent sync framework. Collects the machine-wide installed-software inventory
/// by invoking the existing `installed_apps` plugin in-process (`LocalDispatcher`,
/// action `list`) and renders it into the canonical wire form the server
/// expects. NO per-user data (machine scope only — no PII).

#include "sync_scheduler.hpp"

#include <yuzu/plugin.h> // YuzuPluginDescriptor (C ABI) — typedef, so include not fwd-decl

#include <string>
#include <vector>

namespace yuzu::agent {

/// One machine-scope installed-software entry (mirror of the server's
/// SoftwareEntry; kept agent-local so this module needs no server headers).
struct SwEntry {
    std::string name;
    std::string version;
    std::string publisher;
    std::string install_date;
};

/// Parse `installed_apps` `list` output (pipe-delimited `app|name|version|
/// publisher|install_date` lines) into machine-scope entries. `user_app|`,
/// `error|`, and the `No applications found` sentinel are ignored.
YUZU_EXPORT std::vector<SwEntry> parse_installed_apps_output(const std::string& out);

/// Canonical wire blob: sorted + deduped; fields unit-separated (0x1F), entries
/// record-separated (0x1E); fields truncated to the server's cap. MUST be
/// byte-identical to the server's reconstruction (ADR-0016 §4 /
/// SoftwareInventoryStore::canonical_hash) so the server-recomputed hash equals
/// this source's. Takes its argument by value (it sorts a copy).
YUZU_EXPORT std::string installed_software_canonical_blob(std::vector<SwEntry> entries);

/// SHA-256 hex of a byte string (matches the server's local sha256_hex).
YUZU_EXPORT std::string sha256_hex(const std::string& in);

/// Build the `installed_software` SyncSource. `descriptor` is the loaded
/// `installed_apps` plugin descriptor; when null (plugin not built/loaded — e.g.
/// `build_examples=false`) the source's collect returns std::nullopt and the
/// scheduler no-ops it.
YUZU_EXPORT SyncSource make_installed_software_source(const YuzuPluginDescriptor* descriptor);

} // namespace yuzu::agent
