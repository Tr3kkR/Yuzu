#pragma once

/**
 * asset_tags_parsers.hpp — pure core of the asset_tags plugin (#232).
 *
 * No I/O, no threads, no logging: value capping, change-log bounding, the
 * sync diff, the on-disk snapshot (de)serialisation, and every output-row
 * formatter live here so the agent unit suite can exercise them directly.
 * The plugin .cpp keeps only the mutex, spdlog and the ABI shell;
 * asset_tags_store.hpp holds the state-file I/O.
 *
 * Output policy (S20): synced values are stored raw (capped to
 * kMaxValueBytes on a UTF-8 codepoint boundary), and EVERY field emitted in a
 * pipe-delimited row — values, keys, and echoed caller text — goes through
 * yuzu::util::safe_output_field. Nothing is rejected or stripped at rest.
 * safe_output_field is lossy on a literal backslash on the wire (folded to
 * '/'); that is a documented limitation of the shared server decoder.
 */

#include <yuzu/string_utils.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <vector>

namespace yuzu::asset_tags {

// The 4 fixed structured tag categories.
inline constexpr std::array<std::string_view, 4> kCategoryKeys = {"role", "environment", "location",
                                                                  "service"};

/// Maximum entries kept in the change log, in memory and on disk (S19).
inline constexpr std::size_t kMaxChangeLog = 50;

/// Maximum bytes of a stored tag value. Matches the server's
/// TagStore::validate_value cap (server/core/src/tag_store.cpp), so a value
/// the server accepts is never truncated here.
inline constexpr std::size_t kMaxValueBytes = 448;

/// Floor for asset_tags.check_interval, in seconds.
inline constexpr int kMinCheckIntervalS = 30;

using CategoryValues = std::array<std::string, kCategoryKeys.size()>;

struct ChangeRecord {
    std::string key;
    std::string old_value;
    std::string new_value;
    int64_t timestamp{0}; // epoch seconds
};

struct AssetTagState {
    std::unordered_map<std::string, std::string> tags;
    int64_t last_sync_epoch{0};
    bool stale{true};
    std::vector<ChangeRecord> change_log;
};

inline bool is_category_key(std::string_view key) {
    return std::find(kCategoryKeys.begin(), kCategoryKeys.end(), key) != kCategoryKeys.end();
}

/// Cap a value to kMaxValueBytes without tearing a UTF-8 codepoint: a
/// multi-byte sequence that straddles the limit is dropped whole. No
/// stripping, no escaping.
inline std::string cap_value(std::string_view raw) {
    if (raw.size() <= kMaxValueBytes)
        return std::string{raw};
    std::size_t cut = kMaxValueBytes;
    // raw[cut] is the first excluded byte; a continuation byte (10xxxxxx)
    // there means the cut is mid-codepoint.
    while (cut > 0 && (static_cast<unsigned char>(raw[cut]) & 0xC0U) == 0x80U)
        --cut;
    return std::string{raw.substr(0, cut)};
}

/// Evict the oldest entries so at most kMaxChangeLog remain.
inline void trim_change_log(std::vector<ChangeRecord>& log) {
    if (log.size() > kMaxChangeLog)
        log.erase(log.begin(), log.begin() + static_cast<std::ptrdiff_t>(log.size() - kMaxChangeLog));
}

inline void append_change(std::vector<ChangeRecord>& log, ChangeRecord cr) {
    log.push_back(std::move(cr));
    trim_change_log(log);
}

/// Apply a sync: per category (kCategoryKeys order), record a change when the
/// value differs, then store (or erase, when empty) the new value. Returns the
/// changes made by THIS sync (independent of the bounded log).
inline std::vector<ChangeRecord> apply_sync(AssetTagState& st, const CategoryValues& values,
                                            int64_t now) {
    std::vector<ChangeRecord> changes;
    for (std::size_t i = 0; i < kCategoryKeys.size(); ++i) {
        const std::string key{kCategoryKeys[i]};
        const std::string& new_value = values[i];

        auto it = st.tags.find(key);
        std::string old_value = (it != st.tags.end()) ? it->second : std::string{};

        if (new_value != old_value) {
            ChangeRecord cr{key, old_value, new_value, now};
            changes.push_back(cr);
            append_change(st.change_log, std::move(cr));
        }

        if (new_value.empty())
            st.tags.erase(key);
        else
            st.tags[key] = new_value;
    }
    st.last_sync_epoch = now;
    st.stale = false;
    return changes;
}

inline std::string serialize_state(const AssetTagState& st) {
    nlohmann::json j;
    j["tags"] = st.tags;
    j["last_sync_epoch"] = st.last_sync_epoch;
    j["stale"] = st.stale;

    nlohmann::json log_arr = nlohmann::json::array();
    for (const auto& cr : st.change_log) {
        log_arr.push_back({{"key", cr.key},
                           {"old_value", cr.old_value},
                           {"new_value", cr.new_value},
                           {"timestamp", cr.timestamp}});
    }
    j["change_log"] = std::move(log_arr);
    // Raw stored values may carry invalid UTF-8; replace rather than throw
    // (dump()'s default would raise type_error 316 inside the sync lock).
    return j.dump(2, ' ', false, nlohmann::json::error_handler_t::replace);
}

namespace detail {

/// Read an optional string field (capped). Returns false, with err set, when
/// the field is present but not a string.
inline bool read_string_field(const nlohmann::json& obj, const char* name, const std::string& where,
                              std::string& out, std::string& err) {
    auto it = obj.find(name);
    if (it == obj.end())
        return true;
    if (!it->is_string()) {
        err = where + name + ": expected string";
        return false;
    }
    out = cap_value(it->get_ref<const std::string&>());
    return true;
}

} // namespace detail

/// Parse an on-disk snapshot. ONE recovery policy: any schema violation
/// rejects the WHOLE snapshot (nullopt, err names the offending field); no
/// partial state is ever returned. Unknown top-level keys are ignored
/// (forward compatibility); missing known fields keep their defaults. Never
/// throws. Loaded values are capped (an older plugin stored them uncapped)
/// and an oversized change log is trimmed to the newest kMaxChangeLog.
inline std::optional<AssetTagState> parse_state(std::string_view text, std::string& err) {
    err.clear();
    auto j = nlohmann::json::parse(text.begin(), text.end(), nullptr, false);
    if (j.is_discarded()) {
        err = "not valid JSON";
        return std::nullopt;
    }
    if (!j.is_object()) {
        err = "root: expected object";
        return std::nullopt;
    }

    AssetTagState st;

    if (auto it = j.find("tags"); it != j.end()) {
        if (!it->is_object()) {
            err = "tags: expected object";
            return std::nullopt;
        }
        for (const auto& [key, val] : it->items()) {
            if (!is_category_key(key)) {
                err = "tags." + key + ": unknown category";
                return std::nullopt;
            }
            if (!val.is_string()) {
                err = "tags." + key + ": expected string";
                return std::nullopt;
            }
            st.tags[key] = cap_value(val.get_ref<const std::string&>());
        }
    }

    if (auto it = j.find("last_sync_epoch"); it != j.end()) {
        if (!it->is_number_integer()) {
            err = "last_sync_epoch: expected integer";
            return std::nullopt;
        }
        st.last_sync_epoch = it->get<int64_t>();
    }

    if (auto it = j.find("stale"); it != j.end()) {
        if (!it->is_boolean()) {
            err = "stale: expected boolean";
            return std::nullopt;
        }
        st.stale = it->get<bool>();
    }

    if (auto it = j.find("change_log"); it != j.end()) {
        if (!it->is_array()) {
            err = "change_log: expected array";
            return std::nullopt;
        }
        std::size_t idx = 0;
        for (const auto& entry : *it) {
            const std::string where = "change_log[" + std::to_string(idx) + "].";
            if (!entry.is_object()) {
                err = "change_log[" + std::to_string(idx) + "]: expected object";
                return std::nullopt;
            }
            ChangeRecord cr;
            if (!detail::read_string_field(entry, "key", where, cr.key, err) ||
                !detail::read_string_field(entry, "old_value", where, cr.old_value, err) ||
                !detail::read_string_field(entry, "new_value", where, cr.new_value, err))
                return std::nullopt;
            if (entry.contains("key") && !is_category_key(cr.key)) {
                err = where + "key: unknown category";
                return std::nullopt;
            }
            if (auto it_t = entry.find("timestamp"); it_t != entry.end()) {
                if (!it_t->is_number_integer()) {
                    err = where + "timestamp: expected integer";
                    return std::nullopt;
                }
                cr.timestamp = it_t->get<int64_t>();
            }
            st.change_log.push_back(std::move(cr));
            ++idx;
        }
    }
    trim_change_log(st.change_log);
    return st;
}

// ── Row formatters — every string field escaped ─────────────────────────────

inline std::string format_sync_event(const ChangeRecord& cr) {
    const auto key = yuzu::util::safe_output_field(cr.key);
    if (cr.old_value.empty())
        return "sync|tag_added|" + key + "|" + yuzu::util::safe_output_field(cr.new_value);
    if (cr.new_value.empty())
        return "sync|tag_removed|" + key + "|" + yuzu::util::safe_output_field(cr.old_value);
    return "sync|tag_changed|" + key + "|" + yuzu::util::safe_output_field(cr.old_value) + "|" +
           yuzu::util::safe_output_field(cr.new_value);
}

inline std::string format_tag_row(std::string_view key, std::string_view value) {
    return "tag|" + yuzu::util::safe_output_field(key) + "|" + yuzu::util::safe_output_field(value);
}

inline std::string format_change_row(const ChangeRecord& cr) {
    return "change|" + yuzu::util::safe_output_field(cr.key) + "|" +
           yuzu::util::safe_output_field(cr.old_value) + "|" +
           yuzu::util::safe_output_field(cr.new_value) + "|" + std::to_string(cr.timestamp);
}

/// `<prefix>: <echoed>` with the caller-supplied echo escaped. The prefix is
/// plugin-authored and emitted verbatim.
inline std::string format_error_row(std::string_view prefix, std::string_view echoed) {
    std::string out{prefix};
    out += ": ";
    out += yuzu::util::safe_output_field(echoed);
    return out;
}

/// Parse asset_tags.check_interval: the whole string must be a decimal
/// integer; the result is floored at kMinCheckIntervalS. nullopt on malformed
/// input (caller keeps its default and warns).
inline std::optional<int> parse_check_interval(std::string_view s) {
    int v = 0;
    const auto* first = s.data();
    const auto* last = s.data() + s.size();
    auto [ptr, ec] = std::from_chars(first, last, v);
    if (ec != std::errc{} || ptr != last)
        return std::nullopt;
    return std::max(v, kMinCheckIntervalS);
}

} // namespace yuzu::asset_tags
