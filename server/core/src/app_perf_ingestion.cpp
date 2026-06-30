#include "app_perf_ingestion.hpp"

#include "agent.pb.h"
#include "app_perf_daily_store.hpp"
#include "utf8_sanitize.hpp"

#include <yuzu/metrics.hpp>

#include <spdlog/spdlog.h>

#include <charconv>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server {

namespace {

namespace pb = ::yuzu::agent::v1;

constexpr const char* kSourceAppPerf = "app_perf";

// Untrusted-input caps. The app_perf blob is tiny in practice (≤2 days × top-N
// apps × a few versions ≈ tens of rows), so these are generous abuse bounds, not
// steady-state limits. kMaxBlobBytes MUST match the agent source's cap
// (sync_source_app_perf.cpp), comment-coordinated, and sit below the 4 MiB gRPC
// receive ceiling.
constexpr std::size_t kMaxBlobBytes = 1u * 1024 * 1024; // 1 MiB per app_perf source
constexpr std::size_t kMaxRows = 5000;
constexpr std::size_t kMaxFieldLen = 256; // name/version — keeps the 4-col TEXT PK
                                          // well under PostgreSQL's btree key limit

std::int64_t now_secs() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// Scrub to valid UTF-8 (PG UTF8 rejects bad bytes — SQLSTATE 22021) then truncate
// on a codepoint boundary to the field cap. No hash-coordination requirement
// (B1 is hash-less), so this need NOT byte-match the agent — it only protects PG.
std::string clamp_field(std::string_view raw) {
    std::string f = sanitize_utf8_strict(raw);
    // Strip C0 control bytes incl. NUL. sanitize_utf8_strict keeps them (valid
    // UTF-8), but a NUL survives canon dedup yet is DROPPED by pg::to_text_array, so
    // "foo\0" and "foo" collapse to one PK in the batched upsert → "ON CONFLICT
    // cannot affect row a second time" → the agent's app_perf goes permanently
    // need_full (UP-8). Mirror the agent's append_clean; control bytes never occur in
    // a real app name/version.
    std::erase_if(f, [](unsigned char c) { return c < 0x20; });
    if (f.size() > kMaxFieldLen) {
        std::size_t end = kMaxFieldLen;
        while (end > 0 && (static_cast<unsigned char>(f[end]) & 0xC0) == 0x80)
            --end;
        f.resize(end);
    }
    return f;
}

// Locale-independent numeric parse (std::from_chars). A malformed token yields 0
// (the store re-clamps + merges) rather than rejecting the whole row.
std::int64_t parse_i64(std::string_view s) {
    std::int64_t v = 0;
    const auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
    (void)p;
    return ec == std::errc{} ? v : 0;
}

double parse_double(std::string_view s) {
    // libc++ on Apple Clang 15 has no floating-point std::from_chars
    // (docs/ci-cpp23-troubleshooting.md); std::stod is the portable form used across
    // the codebase (cell_double / parse_perf_tag). Integer from_chars is fine.
    if (s.empty() || s.size() > 64)
        return 0.0;
    try {
        const std::string tmp(s);
        std::size_t pos = 0;
        const double v = std::stod(tmp, &pos);
        if (pos == tmp.size() && std::isfinite(v))
            return v;
    } catch (...) {
    }
    return 0.0;
}

} // namespace

std::vector<AppPerfDailyRow> parse_app_perf_blob(const std::string& blob) {
    std::vector<AppPerfDailyRow> out;
    if (blob.size() > kMaxBlobBytes)
        return out;
    const std::int64_t max_day = now_secs() + 2 * 86400; // tolerate small clock skew
    std::size_t i = 0;
    while (i < blob.size() && out.size() < kMaxRows) {
        std::size_t rec_end = blob.find('\x1e', i);
        if (rec_end == std::string::npos)
            rec_end = blob.size();
        std::string_view rec(blob.data() + i, rec_end - i);
        if (!rec.empty()) {
            std::string_view fields[9]; // value-initialised to empty views
            std::size_t fi = 0;
            std::size_t p = 0;
            while (fi < 9) {
                std::size_t fe = rec.find('\x1f', p);
                if (fe == std::string_view::npos)
                    fe = rec.size();
                fields[fi] = rec.substr(p, fe - p);
                ++fi;
                if (fe >= rec.size())
                    break;
                p = fe + 1;
            }
            AppPerfDailyRow r;
            r.app_name = clamp_field(fields[0]);
            r.version = clamp_field(fields[1]);
            r.day = parse_i64(fields[2]);
            r.samples = parse_i64(fields[3]);
            r.instances_max = parse_i64(fields[4]);
            r.cpu_avg = parse_double(fields[5]);
            r.cpu_max = parse_double(fields[6]);
            r.ws_avg_bytes = parse_i64(fields[7]);
            r.ws_max_bytes = parse_i64(fields[8]);
            // Drop a row with no app name or an implausible day; non-negative-clamp
            // the counters (the store re-clamps too — depth, and keeps test
            // expectations on parse output clean).
            if (!r.app_name.empty() && r.day > 0 && r.day <= max_day) {
                if (r.samples < 0)
                    r.samples = 0;
                if (r.instances_max < 0)
                    r.instances_max = 0;
                if (r.ws_avg_bytes < 0)
                    r.ws_avg_bytes = 0;
                if (r.ws_max_bytes < 0)
                    r.ws_max_bytes = 0;
                out.push_back(std::move(r));
            }
        }
        if (rec_end >= blob.size())
            break;
        i = rec_end + 1;
    }
    return out;
}

void ingest_app_perf_report(AppPerfDailyStore& store, const std::string& agent_id,
                            const pb::InventoryReport& report, pb::InventoryAck& ack,
                            ::yuzu::MetricsRegistry* metrics) {
    const auto emit = [&](const char* outcome) {
        if (metrics)
            metrics->counter("yuzu_app_perf_ingest_total", {{"outcome", outcome}}).increment();
    };
    if (agent_id.empty())
        return;

    // Single keyed lookup — bounded regardless of how many sources the report
    // carries (no iteration; the report-level source-count cap is the inventory
    // seam's concern, and a huge map only costs us this one find()).
    const auto hit = report.content_hashes().find(kSourceAppPerf);
    if (hit == report.content_hashes().end())
        return; // app_perf not due this cycle

    const auto bit = report.plugin_data().find(kSourceAppPerf);
    if (bit == report.plugin_data().end()) {
        // Hash-only report. B1 is hash-less, so the server cannot satisfy it from a
        // stored hash — ask for the full payload. No loop: the agent re-sends full,
        // and steady-state app_perf always sends full anyway (window changes daily).
        ack.add_need_full(kSourceAppPerf);
        emit("need_full");
        return;
    }

    const std::string& blob = bit->second;
    if (blob.size() > kMaxBlobBytes) {
        spdlog::warn("app_perf: oversized blob from agent={} ({} B > {} B) — dropping + nacking",
                     agent_id, blob.size(), kMaxBlobBytes);
        ack.add_need_full(kSourceAppPerf);
        emit("dropped");
        return;
    }

    std::vector<AppPerfDailyRow> rows = parse_app_perf_blob(blob);
    const auto t0 = std::chrono::steady_clock::now();
    const bool ok = store.apply_daily(agent_id, std::move(rows));
    if (metrics) {
        const double secs =
            std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
        // SOLE creating site for yuzu_app_perf_ingest_duration_seconds — births the
        // (single) series with the 60s bucket ceiling. Any future call site MUST
        // pass seconds_buckets_60s() too, or it would birth a default-10s-ceiling
        // series and collapse the tail (mirrors the inventory #1686 UP-6 contract).
        metrics
            ->histogram("yuzu_app_perf_ingest_duration_seconds", {},
                        yuzu::Histogram::seconds_buckets_60s())
            .observe(secs);
    }
    if (ok) {
        emit("stored");
    } else {
        ack.add_need_full(kSourceAppPerf);
        emit("error");
    }
}

} // namespace yuzu::server
