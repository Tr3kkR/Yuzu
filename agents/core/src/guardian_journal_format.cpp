#include "guardian_journal_format.hpp"

#include <nlohmann/json.hpp>

#include <format>

namespace yuzu::agent {

namespace {

constexpr std::int64_t kNsPerSec = 1'000'000'000;

// Strict UTF-8 validation, matching (or exceeding) nlohmann's decoder: rejects
// overlong encodings, surrogates, and code points > U+10FFFF. If a field passes
// this, serialize's dump() cannot throw type_error 316 on it - so we never have
// to fall back to byte-replacement (which would flip a replay to a false
// Conflict against the server's byte-exact compare).
bool is_valid_utf8(std::string_view s) {
    const auto* p = reinterpret_cast<const unsigned char*>(s.data());
    const std::size_t n = s.size();
    std::size_t i = 0;
    while (i < n) {
        const unsigned char c = p[i];
        std::size_t extra;
        unsigned char low = 0x80, high = 0xBF; // valid range for the FIRST continuation byte
        if (c < 0x80) {
            ++i;
            continue;
        } else if ((c & 0xE0) == 0xC0) {
            extra = 1;
            if (c < 0xC2) return false; // C0/C1: overlong 2-byte
        } else if ((c & 0xF0) == 0xE0) {
            extra = 2;
            if (c == 0xE0) low = 0xA0;  // overlong 3-byte
            if (c == 0xED) high = 0x9F; // UTF-16 surrogate half
        } else if ((c & 0xF8) == 0xF0) {
            extra = 3;
            if (c == 0xF0) low = 0x90;  // overlong 4-byte
            if (c == 0xF4) high = 0x8F; // > U+10FFFF
            if (c > 0xF4) return false;
        } else {
            return false; // 0x80-0xBF stray continuation, or 0xF5-0xFF
        }
        if (i + extra >= n) return false; // truncated multibyte
        if (p[i + 1] < low || p[i + 1] > high) return false;
        for (std::size_t k = 2; k <= extra; ++k) {
            const unsigned char cc = p[i + k];
            if (cc < 0x80 || cc > 0xBF) return false;
        }
        i += extra + 1;
    }
    return true;
}

// A field is journalable iff it is NUL-free, within the byte cap, and valid
// UTF-8. Returns the specific fault (order: NUL, size, UTF-8) or None.
JournalReject check_field(std::string_view f) {
    if (f.find('\0') != std::string_view::npos) return JournalReject::EmbeddedNul;
    if (f.size() > kMaxJournalFieldBytes) return JournalReject::Oversized;
    if (!is_valid_utf8(f)) return JournalReject::InvalidUtf8;
    return JournalReject::None;
}

} // namespace

std::string journal_batch_key(std::string_view boot_nonce, std::uint64_t seq) {
    return std::format("lc:{}:{:012}", boot_nonce, seq);
}

std::string journal_sent_key(std::string_view boot_nonce, std::uint64_t seq) {
    return std::format("sent:{}:{:012}", boot_nonce, seq);
}

std::string journal_quarantine_key(std::string_view batch_key) {
    return std::string(kQuarantineKeyPrefix) + std::string(batch_key);
}

std::string journal_batch_key_from_sent_key(std::string_view sent_key) {
    if (sent_key.starts_with(kSentKeyPrefix))
        return std::string(kBatchKeyPrefix) + std::string(sent_key.substr(kSentKeyPrefix.size()));
    return std::string(sent_key);
}

std::string journal_sent_key_from_batch_key(std::string_view batch_key) {
    if (batch_key.starts_with(kBatchKeyPrefix))
        return std::string(kSentKeyPrefix) + std::string(batch_key.substr(kBatchKeyPrefix.size()));
    return std::string(batch_key);
}

JournalReject validate_record(const JournalRecord& r) {
    // Clock first: a skewed-clock record would replay as server-receipt-now and
    // mismatch on timestamp forever (rev-4.1 #2). Mirror set_common's floored
    // seconds so the threshold is byte-identical to what the wire event carries.
    std::int64_t secs = r.enqueued_ns / kNsPerSec;
    if (r.enqueued_ns % kNsPerSec < 0) --secs; // floor toward -inf, as set_common does
    if (secs <= 0) return JournalReject::SkewedClock;

    for (const std::string_view f : {std::string_view{r.rule_id}, std::string_view{r.event_id},
                                     std::string_view{r.kind}, std::string_view{r.guard_type},
                                     std::string_view{r.rule_name}}) {
        if (auto reason = check_field(f); reason != JournalReject::None) return reason;
    }
    return JournalReject::None;
}

std::string serialize_journal_batch(std::int64_t ts_ms, std::span<const JournalRecord> entries) {
    nlohmann::json j;
    j["v"] = kJournalFormatVersion;
    j["ts_ms"] = ts_ms;
    auto& arr = j["entries"] = nlohmann::json::array();
    for (const auto& r : entries) {
        arr.push_back(nlohmann::json{
            {"rule_id", r.rule_id},
            {"generation", r.generation},
            {"event_id", r.event_id},
            {"enqueued_ns", r.enqueued_ns},
            {"kind", r.kind},
            {"guard_type", r.guard_type},
            {"rule_name", r.rule_name},
        });
    }
    // error_handler_t::replace: a belt-and-suspenders over validate_record so a
    // stray invalid byte can never THROW (which would jam every persist retry).
    return j.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
}

std::expected<JournalBatch, JournalParseError> parse_journal_batch(std::string_view json) {
    auto j = nlohmann::json::parse(json, nullptr, /*allow_exceptions=*/false);
    if (j.is_discarded() || !j.is_object()) return std::unexpected(JournalParseError::Malformed);

    auto vit = j.find("v");
    if (vit == j.end() || !vit->is_number_integer())
        return std::unexpected(JournalParseError::Malformed);
    if (vit->get<int>() != kJournalFormatVersion)
        return std::unexpected(JournalParseError::UnknownVersion);

    JournalBatch batch;
    auto tsit = j.find("ts_ms");
    if (tsit == j.end() || !tsit->is_number_integer())
        return std::unexpected(JournalParseError::Malformed);
    batch.ts_ms = tsit->get<std::int64_t>();

    auto eit = j.find("entries");
    if (eit == j.end() || !eit->is_array()) return std::unexpected(JournalParseError::Malformed);

    const auto req_str = [](const nlohmann::json& o, const char* key,
                            std::string& out) -> bool {
        auto it = o.find(key);
        if (it == o.end() || !it->is_string()) return false;
        out = it->get<std::string>();
        return true;
    };

    for (const auto& e : *eit) {
        if (!e.is_object()) return std::unexpected(JournalParseError::Malformed);
        JournalRecord r;
        auto git = e.find("generation");
        auto nsit = e.find("enqueued_ns");
        if (!req_str(e, "rule_id", r.rule_id) || !req_str(e, "event_id", r.event_id) ||
            !req_str(e, "kind", r.kind) || !req_str(e, "guard_type", r.guard_type) ||
            !req_str(e, "rule_name", r.rule_name) || git == e.end() ||
            !git->is_number_integer() || nsit == e.end() || !nsit->is_number_integer())
            return std::unexpected(JournalParseError::Malformed);
        r.generation = git->get<std::uint64_t>();
        r.enqueued_ns = nsit->get<std::int64_t>();
        batch.entries.push_back(std::move(r));
    }
    return batch;
}

} // namespace yuzu::agent
