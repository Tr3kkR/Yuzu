/**
 * pii_rules.hpp — Rule data structures + JSON deserialization for the
 * pii_scan plugin.
 *
 * Pure logic: parses the flat, normalized JSON array produced at build
 * time by scripts/embed_pii_rules.py (from content/pii-rules/*.yaml) into
 * a std::vector<Rule>. No filesystem access here — the caller supplies
 * the JSON text (normally yuzu::pii::kEmbeddedPiiRulesJson, generated at
 * build time), which keeps this fully unit-testable with hand-written
 * JSON fixtures, matching the ssh_hardening_rules.hpp convention.
 */
#pragma once

#include <nlohmann/json.hpp>

#include <cctype>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::pii {

struct Rule {
    std::string id;
    std::string display_name;
    std::optional<std::string> jurisdiction; // country/state code, or nullopt for generic
    std::string category;
    std::string pattern;                  // RE2-compatible regex
    std::optional<std::string> checksum;  // name dispatched in pii_checksum.hpp, or nullopt
    std::string severity;                 // "critical" | "high" | "medium" | "low"
    std::vector<std::string> compliance_tags;
    std::vector<std::string> confidence_keywords;
    std::string source_confidence; // "HIGH" | "MEDIUM" | "MEDIUM_HIGH" | "LOW_MEDIUM" | "LOW" | "NONE"
    std::optional<std::string> notes;
    // Real example values this rule's own YAML declares itself
    // (`knownTestValues`) — currently only populated for the four
    // generic payment-card rules. Empty for every rule that doesn't
    // declare any. Consumed by test_pii_ruleset_integrity.cpp to
    // actually run these through the real compiled engine, rather than
    // leaving them as unread YAML documentation nothing ever executes.
    std::vector<std::string> known_test_values;
    // When true, a match with no checksum result (no checksum defined,
    // or the checksum function returned "cannot validate") is DROPPED
    // entirely unless a confidenceKeyword is found on the same line --
    // never reported at LOW. For a rule whose shape alone is extremely
    // weak evidence (e.g. generic.date_of_birth's bare "any date" shape,
    // which would otherwise flood real findings against log timestamps
    // and expiry dates), this is the difference between the rule's own
    // documented intent and what scan_text() actually did: this flag
    // used to be describable only in a rule's free-text `notes` field,
    // which the engine never read.
    bool require_keyword = false;
};

// ── Jurisdiction / region filtering ──────────────────────────────────────
//
// Lets an operator scope a scan to only the countries their org actually
// operates in (e.g. "we're a UK/EU shop, we don't need Aadhaar or CPF
// detection cluttering results"). A rule's `jurisdiction` is either
// nullopt (generic — credit cards, IBAN, email, etc. — always relevant
// regardless of filter) or a code like "GB", "US-CA", "CA-ON": a bare
// 2-letter country code, or a country prefix + state/province suffix for
// federated schemes (US driver's licences, Canadian provinces, Australian
// states).
//
// A filter entry matches a rule's jurisdiction if it's an exact match, OR
// if the rule's jurisdiction starts with "<entry>-" (so a filter of "US"
// matches every US state's driver's-licence rule without the caller
// having to enumerate all 51). Region preset names (case-insensitive)
// expand to their member country codes below.

inline const std::vector<std::string>& region_preset(std::string_view region_upper) {
    static const std::vector<std::string> kEmpty;
    static const std::vector<std::string> kEmea = {
        "GB", "IE", "DE", "FR", "ES", "IT", "NL", "SE", "NO", "DK", "PL", "BE",
        "AT", "PT", "GR", "FI", "CZ", "SK", "RO", "HU", "CH", "BG", "HR", "LU",
        "SI", "EE", "LT", "LV", "IL", "SA", "AE", "EG", "NG", "KE", "TR", "ZA",
    };
    static const std::vector<std::string> kApac = {
        "JP", "CN", "KR", "IN", "SG", "AU", "NZ", "ID", "PH", "VN", "TH", "MY",
    };
    static const std::vector<std::string> kAmericas = {
        "US", "CA", "MX", "BR", "AR", "CL", "CO", "PE", "VE",
    };
    if (region_upper == "EMEA")
        return kEmea;
    if (region_upper == "APAC")
        return kApac;
    if (region_upper == "AMERICAS")
        return kAmericas;
    return kEmpty;
}

// Expands any region preset names in `raw_filter` (case-insensitive) into
// their member country codes, leaving plain country/state codes as-is.
inline std::vector<std::string> expand_jurisdiction_filter(const std::vector<std::string>& raw_filter) {
    std::vector<std::string> out;
    for (const auto& entry : raw_filter) {
        std::string upper = entry;
        for (char& c : upper)
            c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        const auto& preset = region_preset(upper);
        if (!preset.empty()) {
            out.insert(out.end(), preset.begin(), preset.end());
        } else {
            out.push_back(upper);
        }
    }
    return out;
}

inline bool jurisdiction_matches_filter(const std::optional<std::string>& jurisdiction,
                                        const std::vector<std::string>& expanded_filter) {
    if (expanded_filter.empty())
        return true; // no filter configured — everything passes
    if (!jurisdiction.has_value())
        return true; // generic rules (cards, IBAN, email, ...) always apply
    for (const auto& code : expanded_filter) {
        if (*jurisdiction == code)
            return true;
        if (jurisdiction->size() > code.size() &&
            jurisdiction->compare(0, code.size(), code) == 0 &&
            (*jurisdiction)[code.size()] == '-') {
            return true; // e.g. filter "US" matches jurisdiction "US-CA"
        }
    }
    return false;
}

// Convenience: filters a rule vector in place by an (already-expanded, or
// raw — this expands internally) jurisdiction filter list.
inline std::vector<Rule> filter_rules_by_jurisdiction(const std::vector<Rule>& rules,
                                                       const std::vector<std::string>& raw_filter) {
    if (raw_filter.empty())
        return rules;
    auto expanded = expand_jurisdiction_filter(raw_filter);
    std::vector<Rule> out;
    out.reserve(rules.size());
    for (const auto& r : rules) {
        if (jurisdiction_matches_filter(r.jurisdiction, expanded))
            out.push_back(r);
    }
    return out;
}

// Parses the embedded rule JSON. Malformed individual entries are
// skipped (not fatal) so one bad rule can't take down the whole ruleset;
// a totally unparseable document returns an empty vector — the caller
// (plugin init) should treat that as a hard failure, not silently scan
// with zero rules.
inline std::vector<Rule> parse_rules_json(std::string_view json_text) {
    std::vector<Rule> rules;

    nlohmann::json doc;
    try {
        doc = nlohmann::json::parse(json_text);
    } catch (const nlohmann::json::parse_error&) {
        return rules;
    }
    if (!doc.is_array())
        return rules;

    for (const auto& item : doc) {
        if (!item.is_object())
            continue;
        if (!item.contains("id") || !item.contains("pattern"))
            continue;

        // A per-field TYPE mismatch (a field present with the wrong JSON
        // type -- e.g. a boolean where a string was expected, the
        // "Norway problem" class of bug) makes nlohmann::json's
        // .value<T>()/.get<T>() throw type_error, not return a default.
        // The outer catch above only guards the top-level parse() call,
        // so one malformed FIELD anywhere in the array used to be an
        // uncaught exception propagating out of this function entirely
        // — not the documented "one bad rule can't take down the whole
        // ruleset" behaviour this function's own header comment
        // promises, but every OTHER real rule in the array going unparsed
        // too. Catch per-item, skip just the offending entry.
        try {
        Rule r;
        r.id = item.value("id", "");
        r.display_name = item.value("displayName", r.id);
        if (item.contains("jurisdiction") && !item.at("jurisdiction").is_null())
            r.jurisdiction = item.at("jurisdiction").get<std::string>();
        r.category = item.value("category", "generic");
        r.pattern = item.value("pattern", "");
        if (r.pattern.empty())
            continue;
        if (item.contains("checksum") && !item.at("checksum").is_null())
            r.checksum = item.at("checksum").get<std::string>();
        r.severity = item.value("severity", "medium");
        if (item.contains("complianceTags") && item.at("complianceTags").is_array()) {
            for (const auto& t : item.at("complianceTags")) {
                if (t.is_string())
                    r.compliance_tags.push_back(t.get<std::string>());
            }
        }
        if (item.contains("confidenceKeywords") && item.at("confidenceKeywords").is_array()) {
            for (const auto& k : item.at("confidenceKeywords")) {
                if (k.is_string())
                    r.confidence_keywords.push_back(k.get<std::string>());
            }
        }
        r.source_confidence = item.value("sourceConfidence", "MEDIUM");
        if (item.contains("notes") && !item.at("notes").is_null())
            r.notes = item.at("notes").get<std::string>();
        if (item.contains("knownTestValues") && item.at("knownTestValues").is_array()) {
            for (const auto& v : item.at("knownTestValues")) {
                if (v.is_string())
                    r.known_test_values.push_back(v.get<std::string>());
            }
        }
        r.require_keyword = item.value("requireKeyword", false);

        rules.push_back(std::move(r));
        } catch (const nlohmann::json::exception&) {
            continue; // this one entry's field types were malformed — skip it, keep the rest
        }
    }

    return rules;
}

} // namespace yuzu::pii
