#include "inventory_ingestion.hpp"

#include "agent.pb.h"
#include "software_inventory_store.hpp"

#include <yuzu/metrics.hpp>

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
// is rejected (dropped + nacked); entries/fields beyond the cap are
// dropped/truncated.
// kMaxBlobBytes MUST equal the agent source's kMaxBlobBytes
// (agents/core/src/sync_source_installed_software.cpp) — comment-coordinated, a
// one-sided bump reintroduces the agent-sends/server-drops tight loop (UP-7).
// Set below the gRPC 4 MiB receive ceiling for the wire-framing reason
// documented agent-side (UP-6).
constexpr std::size_t kMaxBlobBytes = 3u * 1024 * 1024; // 3 MiB per source
constexpr std::size_t kMaxEntries = 20000;
constexpr std::size_t kMaxFieldLen = 1024;
// The sync framework wires a small fixed number of sources (1 today; a handful
// ever). A report carrying an implausibly large content_hashes / plugin_data map is
// malformed or abusive — reject it wholesale (defense-in-depth; already bounded by
// the 4 MiB gRPC receive ceiling, but an explicit cap is cheaper to reason about).
// gov fjarvis LOW.
constexpr int kMaxSources = 64;

// Replace every byte that is not part of a valid UTF-8 sequence with U+FFFD (the
// replacement character, EF BF BD). "Valid" is exactly what PostgreSQL's UTF8
// server-encoding accepts: no overlong forms, no surrogates (U+D800..U+DFFF),
// nothing above U+10FFFF. A field that reaches PG with an invalid byte is
// rejected with SQLSTATE 22021, which rolls back the whole full-replace
// transaction and makes the agent resend the identical poison forever
// (governance UP-IN1). Defence-in-depth against a non-conforming agent (the real
// agent's clamp_field scrubs identically before hashing).
//
// This MUST run BEFORE the length clamp (U+FFFD is 3 bytes, so scrubbing can grow
// the field) and MUST be byte-for-byte identical to the agent's copy in
// sync_source_installed_software.cpp (clamp_field), or the server-recomputed hash
// diverges from the agent's → permanent always-full.
std::string sanitize_utf8_strict(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    const std::size_t n = s.size();
    const auto cont = [&](std::size_t j) -> bool {
        return j < n && (static_cast<unsigned char>(s[j]) & 0xC0) == 0x80;
    };
    std::size_t i = 0;
    while (i < n) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        const unsigned char c1 = i + 1 < n ? static_cast<unsigned char>(s[i + 1]) : 0;
        std::size_t len = 0;
        bool ok = false;
        if (c < 0x80) {
            ok = true;
            len = 1;
        } else if (c >= 0xC2 && c <= 0xDF) {
            ok = cont(i + 1);
            len = 2;
        } else if (c == 0xE0) {
            ok = c1 >= 0xA0 && c1 <= 0xBF && cont(i + 2); // reject overlong 80..9F
            len = 3;
        } else if (c >= 0xE1 && c <= 0xEC) {
            ok = cont(i + 1) && cont(i + 2);
            len = 3;
        } else if (c == 0xED) {
            ok = c1 >= 0x80 && c1 <= 0x9F && cont(i + 2); // reject surrogates A0..BF
            len = 3;
        } else if (c >= 0xEE && c <= 0xEF) {
            ok = cont(i + 1) && cont(i + 2);
            len = 3;
        } else if (c == 0xF0) {
            ok = c1 >= 0x90 && c1 <= 0xBF && cont(i + 2) && cont(i + 3); // reject overlong 80..8F
            len = 4;
        } else if (c >= 0xF1 && c <= 0xF3) {
            ok = cont(i + 1) && cont(i + 2) && cont(i + 3);
            len = 4;
        } else if (c == 0xF4) {
            ok = c1 >= 0x80 && c1 <= 0x8F && cont(i + 2) && cont(i + 3); // reject > U+10FFFF
            len = 4;
        }
        if (ok) {
            out.append(s.data() + i, len);
            i += len;
        } else {
            out.append("\xEF\xBF\xBD", 3); // U+FFFD, advance one byte
            i += 1;
        }
    }
    return out;
}

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
                std::string_view raw = rec.substr(p, f_end - p);
                // Scrub to valid UTF-8 FIRST (governance UP-IN1), then truncate on a
                // codepoint boundary. Both steps MUST match the agent's clamp_field
                // (sync_source_installed_software.cpp) byte-for-byte — scrub before
                // clamp, U+FFFD for any invalid byte — or the server-recomputed hash
                // diverges from the agent's (governance UP-10 for the clamp half).
                std::string f = sanitize_utf8_strict(raw);
                if (f.size() > kMaxFieldLen) {
                    std::size_t end = kMaxFieldLen;
                    while (end > 0 && (static_cast<unsigned char>(f[end]) & 0xC0) == 0x80)
                        --end;
                    f.resize(end);
                }
                *fields[fi] = std::move(f);
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
                             const pb::InventoryReport& report, pb::InventoryAck& ack,
                             ::yuzu::MetricsRegistry* metrics) {
    const auto emit = [&](const std::string& source, const char* outcome) {
        if (metrics)
            metrics->counter("yuzu_inventory_ingest_total",
                             {{"source", source}, {"outcome", outcome}})
                .increment();
    };
    if (agent_id.empty())
        return;
    if (report.content_hashes_size() > kMaxSources || report.plugin_data_size() > kMaxSources) {
        // Whole-report reject (malformed/abusive). Deliberately NO need_full nack — we do
        // not amplify resends to a misbehaving agent; the empty ack means the agent records
        // the cycle done until the weekly floor. Safety rests on the legit source count
        // (1 today) staying far below kMaxSources, so a legit report is never dropped here.
        // Emit the dropped-outcome metric for observability (parity with the oversized-blob
        // path below; gov consistency/compliance) so a flooding agent isn't WARN-only.
        spdlog::warn("inventory: report from agent={} carries too many sources "
                     "(hashes={}, blobs={}, cap={}) — rejecting whole report",
                     agent_id, report.content_hashes_size(), report.plugin_data_size(),
                     kMaxSources);
        emit("__report__", "dropped");
        return;
    }

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
                emit(source, "dropped");
                continue;
            }
        }

        InventoryIngestOutcome outcome =
            store.apply_installed_software(agent_id, claimed_hash, rows, collected_at);
        emit(source, outcome == InventoryIngestOutcome::kStored    ? "stored"
                     : outcome == InventoryIngestOutcome::kTouched  ? "touched"
                     : outcome == InventoryIngestOutcome::kNeedFull ? "need_full"
                                                                    : "error");
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
