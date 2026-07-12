/**
 * spark_spec.cpp — canonical spark identity (see spark.hpp).
 *
 * spark_key() is the dedup identity for arming (N consumers, 1 watcher) and
 * the correlation handle on every SparkEvent, so it must be deterministic over
 * (type, params) and injective: two different specs must never produce the
 * same key. String params are length-prefixed for that reason — a naive
 * "path:threshold" join would collide a path that itself contains the
 * delimiter.
 */

#include <yuzu/agent/spark.hpp>

#include <string>
#include <type_traits>
#include <variant>

namespace yuzu::agent {

namespace {

// Length-prefixed string field: "<len>:<bytes>" — injective regardless of the
// bytes' content, so params containing ':' or '|' can't collide.
void append_str(std::string& out, const std::string& s) {
    out += std::to_string(s.size());
    out += ':';
    out += s;
}

} // namespace

std::string spark_key(const SparkSpec& spec) {
    std::string key = spark_type_token(spec.type);
    key += '|';
    std::visit(
        [&](const auto& p) {
            using P = std::decay_t<decltype(p)>;
            if constexpr (std::is_same_v<P, IntervalSparkParams>) {
                key += std::to_string(p.interval_ms);
            } else if constexpr (std::is_same_v<P, StartupSparkParams>) {
                // no params
            } else if constexpr (std::is_same_v<P, DiskSparkParams>) {
                append_str(key, p.path);
                key += '|';
                key += std::to_string(p.used_pct_threshold);
                key += '|';
                key += std::to_string(p.min_free_bytes);
                key += '|';
                key += std::to_string(p.poll_ms);
            } else if constexpr (std::is_same_v<P, FileSparkParams>) {
                append_str(key, p.path);
            } else if constexpr (std::is_same_v<P, ServiceSparkParams>) {
                append_str(key, p.service_name);
            } else if constexpr (std::is_same_v<P, RegistrySparkParams>) {
                append_str(key, p.hive);
                key += '|';
                append_str(key, p.key);
            }
        },
        spec.params);
    return key;
}

} // namespace yuzu::agent
