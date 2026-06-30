#include "device_ci_ingestion.hpp"

#include "agent.pb.h"
#include "device_inventory_store.hpp"
#include "utf8_sanitize.hpp" // shared yuzu::server::sanitize_utf8_strict (server side of the pair)

#include <yuzu/metrics.hpp>

#include <spdlog/spdlog.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace yuzu::server {

namespace {

namespace pb = ::yuzu::agent::v1;

constexpr const char* kSourceDeviceCi = "device_ci";

// Caps — MUST match the agent source (sync_source_device_ci.cpp), comment-
// coordinated, and sit below the 4 MiB gRPC receive ceiling. The CI blob is a
// single small record; 64 KiB is a generous abuse bound.
constexpr std::size_t kMaxBlobBytes = 64u * 1024;
constexpr std::size_t kMaxFieldLen = 1024;
// The number of positional fields in the canonical record (see DeviceCiRecord /
// the agent's CiRecord). Extra fields in a (forward-version) blob are ignored;
// missing trailing fields stay empty.
constexpr std::size_t kFieldCount = 22;

// ── field clamp ─────────────────────────────────────────────────────────────
// UTF-8 scrub via the shared server-side yuzu::server::sanitize_utf8_strict
// (utf8_sanitize.hpp) — the SAME impl installed_software's seam uses, byte-pinned
// against the agent's copy by the cross-pin test. clamp_field stays local because it
// strips only the framing separators (0x1F/0x1E) + NUL (NOT all control bytes — the
// agent keeps e.g. tabs), unlike app_perf's all-C0 variant. Scrub BEFORE clamp
// (U+FFFD is 3 bytes; clamping first would budget differently on each side).
std::string clamp_field(std::string_view raw) {
    std::string f = sanitize_utf8_strict(raw);
    if (f.size() > kMaxFieldLen) {
        std::size_t end = kMaxFieldLen;
        while (end > 0 && (static_cast<unsigned char>(f[end]) & 0xC0) == 0x80)
            --end;
        f.resize(end);
    }
    std::string out;
    out.reserve(f.size());
    for (char c : f) {
        if (c == '\x1f' || c == '\x1e' || c == '\0')
            continue;
        out.push_back(c);
    }
    return out;
}

} // namespace

DeviceCiRecord parse_device_ci_blob(const std::string& blob) {
    DeviceCiRecord rec;
    if (blob.size() > kMaxBlobBytes)
        return rec; // defence-in-depth; caller caps + nacks before reaching here
    // One record, terminated by the first 0x1E (the agent emits exactly one).
    std::size_t rec_end = blob.find('\x1e');
    if (rec_end == std::string::npos)
        rec_end = blob.size();
    std::string_view record(blob.data(), rec_end);

    std::array<std::string, kFieldCount> f; // value-initialised to empty
    std::size_t fi = 0;
    std::size_t p = 0;
    while (fi < kFieldCount) {
        std::size_t fe = record.find('\x1f', p);
        if (fe == std::string_view::npos)
            fe = record.size();
        f[fi] = clamp_field(record.substr(p, fe - p));
        ++fi;
        if (fe >= record.size())
            break;
        p = fe + 1;
    }
    // Positional assignment — MUST match the agent's CiRecord order.
    rec.manufacturer = std::move(f[0]);
    rec.model = std::move(f[1]);
    rec.serial = std::move(f[2]);
    rec.system_uuid = std::move(f[3]);
    rec.hostname = std::move(f[4]);
    rec.domain = std::move(f[5]);
    rec.ou = std::move(f[6]);
    rec.bios_vendor = std::move(f[7]);
    rec.bios_version = std::move(f[8]);
    rec.bios_date = std::move(f[9]);
    rec.cpu_model = std::move(f[10]);
    rec.cpu_cores = std::move(f[11]);
    rec.cpu_threads = std::move(f[12]);
    rec.ram_bytes = std::move(f[13]);
    rec.disks_summary = std::move(f[14]);
    rec.primary_mac = std::move(f[15]);
    rec.macs_summary = std::move(f[16]);
    rec.nic_count = std::move(f[17]);
    rec.os_name = std::move(f[18]);
    rec.os_version = std::move(f[19]);
    rec.os_build = std::move(f[20]);
    rec.arch = std::move(f[21]);
    return rec;
}

void ingest_device_ci_report(DeviceInventoryStore& store, const std::string& agent_id,
                             const pb::InventoryReport& report, pb::InventoryAck& ack,
                             ::yuzu::MetricsRegistry* metrics) {
    const auto emit = [&](const char* outcome) {
        if (metrics)
            metrics->counter("yuzu_inventory_ingest_total",
                             {{"source", kSourceDeviceCi}, {"outcome", outcome}})
                .increment();
    };
    if (agent_id.empty())
        return;

    // Single keyed lookup — bounded regardless of how many sources the report
    // carries (no full-map iteration; a huge map costs only this one find()).
    const auto hit = report.content_hashes().find(kSourceDeviceCi);
    if (hit == report.content_hashes().end())
        return; // device_ci not due this cycle
    const std::string& claimed_hash = hit->second;

    std::int64_t collected_at = 0;
    if (report.has_collected_at())
        collected_at = report.collected_at().millis_epoch() / 1000;

    const auto bit = report.plugin_data().find(kSourceDeviceCi);
    std::optional<DeviceCiRecord> rec;
    if (bit != report.plugin_data().end()) {
        if (bit->second.size() > kMaxBlobBytes) {
            // Oversized: don't store, but nack so the agent resends rather than
            // recording a false success. The agent's own cap should prevent this.
            spdlog::warn("device_ci: oversized blob from agent={} ({} B > {} B) — dropping + "
                         "nacking",
                         agent_id, bit->second.size(), kMaxBlobBytes);
            ack.add_need_full(kSourceDeviceCi);
            emit("dropped");
            return;
        }
        rec = parse_device_ci_blob(bit->second);
    }
    // rec == nullopt → hash-only report: the store compares claimed_hash against the
    // stored hash (kTouched on match, kNeedFull on cold/drift).
    // Time the apply (parity with the installed_software / app_perf seams), split by
    // phase: a `full` payload runs the upsert; a `hash_only` report is a compare +
    // last_seen bump. Computed BEFORE the move (rec is consumed by apply).
    const char* phase = rec.has_value() ? "full" : "hash_only";
    const auto ingest_t0 = std::chrono::steady_clock::now();
    const InventoryIngestOutcome outcome =
        store.apply_device_ci(agent_id, claimed_hash, std::move(rec), collected_at);
    if (metrics) {
        const double secs =
            std::chrono::duration<double>(std::chrono::steady_clock::now() - ingest_t0).count();
        // Shares the yuzu_inventory_ingest_duration_seconds family with installed_software;
        // MUST pass seconds_buckets_60s() (the bucket-ceiling contract, #1686 UP-6).
        metrics
            ->histogram("yuzu_inventory_ingest_duration_seconds",
                        {{"source", kSourceDeviceCi}, {"phase", phase}},
                        yuzu::Histogram::seconds_buckets_60s())
            .observe(secs);
    }
    emit(outcome == InventoryIngestOutcome::kStored    ? "stored"
         : outcome == InventoryIngestOutcome::kTouched ? "touched"
         : outcome == InventoryIngestOutcome::kNeedFull ? "need_full"
                                                        : "error");
    if (outcome == InventoryIngestOutcome::kNeedFull || outcome == InventoryIngestOutcome::kError)
        ack.add_need_full(kSourceDeviceCi);
}

} // namespace yuzu::server
