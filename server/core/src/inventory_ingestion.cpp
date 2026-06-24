#include "inventory_ingestion.hpp"

#include "agent.pb.h"
#include "software_inventory_store.hpp"

#include <spdlog/spdlog.h>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server {

namespace {

namespace pb = ::yuzu::agent::v1;

constexpr const char* kSourceInstalledSoftware = "installed_software";

// Input caps — the report is untrusted (security-guardian). A blob over the cap
// is rejected (neither stored nor nacked); entries/fields beyond the cap are
// dropped/truncated.
constexpr std::size_t kMaxBlobBytes = 4u * 1024 * 1024; // 4 MiB per source
constexpr std::size_t kMaxEntries = 20000;
constexpr std::size_t kMaxFieldLen = 1024;

// Parse the canonical wire blob into rows: entries are 0x1E-separated; each is
// 0x1F-separated (name, version, publisher, install_date) — the same byte form
// the agent hashes (ADR-0016 §4), so the server re-hash matches. nullopt only
// when the blob exceeds the cap; an empty list is a legitimate "nothing here".
std::optional<std::vector<SoftwareEntry>> parse_software_blob(const std::string& blob) {
    if (blob.size() > kMaxBlobBytes)
        return std::nullopt;
    std::vector<SoftwareEntry> out;
    std::size_t i = 0;
    while (i < blob.size() && out.size() < kMaxEntries) {
        std::size_t rec_end = blob.find('\x1e', i);
        if (rec_end == std::string::npos)
            rec_end = blob.size();
        std::string_view rec(blob.data() + i, rec_end - i);
        if (!rec.empty()) {
            SoftwareEntry e;
            std::string* fields[4] = {&e.name, &e.version, &e.publisher, &e.install_date};
            std::size_t fi = 0;
            std::size_t p = 0;
            while (fi < 4) {
                std::size_t f_end = rec.find('\x1f', p);
                if (f_end == std::string_view::npos)
                    f_end = rec.size();
                std::string_view f = rec.substr(p, f_end - p);
                if (f.size() > kMaxFieldLen)
                    f = f.substr(0, kMaxFieldLen);
                *fields[fi] = std::string(f);
                ++fi;
                if (f_end >= rec.size())
                    break;
                p = f_end + 1;
            }
            if (!e.name.empty())
                out.push_back(std::move(e));
        }
        if (rec_end >= blob.size())
            break;
        i = rec_end + 1;
    }
    return out;
}

} // namespace

void ingest_inventory_report(SoftwareInventoryStore& store, const std::string& agent_id,
                             const pb::InventoryReport& report, pb::InventoryAck& ack) {
    if (agent_id.empty())
        return;

    std::int64_t collected_at = 0;
    if (report.has_collected_at())
        collected_at = report.collected_at().millis_epoch() / 1000;

    // content_hashes is the source of truth for "which sources came due" — it is
    // always present per due source, whether or not the blob accompanies it.
    for (const auto& [source, claimed_hash] : report.content_hashes()) {
        if (source != kSourceInstalledSoftware)
            continue; // slice 1: only installed_software is wired

        std::optional<std::vector<SoftwareEntry>> rows;
        auto it = report.plugin_data().find(source);
        if (it != report.plugin_data().end()) {
            rows = parse_software_blob(it->second);
            if (!rows.has_value()) {
                // Oversized blob: don't store it, but DO nack so the agent
                // retries rather than recording a false success (UP-2). The
                // agent's own blob cap (UP-4) should prevent reaching here.
                spdlog::warn("inventory: oversized '{}' blob from agent={}, dropping + nacking",
                             source, agent_id);
                ack.add_need_full(source);
                continue;
            }
        }

        InventoryIngestOutcome outcome =
            store.apply_installed_software(agent_id, claimed_hash, rows, collected_at);
        // need_full on cold-cache/drift (kNeedFull) AND on a transient store
        // failure (kError) — otherwise the agent sees an empty need_full, treats
        // the cycle as stored, and silently advances past un-stored data for up
        // to a week (UP-2). Nacking makes the agent resend a full payload.
        if (outcome == InventoryIngestOutcome::kNeedFull ||
            outcome == InventoryIngestOutcome::kError)
            ack.add_need_full(source);
    }
}

} // namespace yuzu::server
