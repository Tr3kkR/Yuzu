/**
 * pii_matcher.hpp — RE2-based matching engine for the pii_scan plugin.
 *
 * Pure logic: given a set of compiled rules and a text blob, produces
 * Findings. No filesystem access (the caller supplies file content and a
 * label for it) — fully unit-testable with in-memory strings, matching
 * the ssh_hardening_rules.hpp convention.
 *
 * RE2 (not std::regex): guarantees linear-time matching regardless of
 * pattern shape, so a badly-written national-ID regex in the ruleset
 * cannot cause catastrophic backtracking (ReDoS) against attacker- or
 * user-controlled file content.
 *
 * Confidence model (see content/pii-rules/00-manifest.yaml "Finding-
 * confidence model" for the human-readable version this implements):
 *   - checksum defined AND passes  -> HIGH, always reported.
 *   - checksum defined AND FAILS   -> dropped entirely (not reported) —
 *     a checksum-verifiable identifier that fails its checksum is very
 *     likely not a real instance of that type; this is the single
 *     biggest false-positive reduction available and mirrors how real
 *     DLP engines (e.g. Microsoft Purview) treat validated types.
 *   - checksum undefined, or the checksum function returned "cannot
 *     validate" (nullopt) -> MEDIUM if a confidenceKeyword was found on
 *     the same line, else LOW. Both are reported (never dropped) since
 *     they're legitimately candidate matches, just lower-confidence.
 *
 * CRITICAL: never expose the raw matched value beyond mask_value()'s
 * redaction — a Finding carries a masked value only. This mirrors the
 * device_ci / behavioral-PII audit-tier precedent already established
 * elsewhere in this codebase (ADR-0016): a tool that discovers PII must
 * not itself become a new place PII is stored in the clear.
 */
#pragma once

#include <re2/re2.h>

#include <algorithm>
#include <cctype>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "pii_checksum.hpp"
#include "pii_rules.hpp"

namespace yuzu::pii {

struct Finding {
    std::string rule_id;
    std::string display_name;
    std::string category;
    std::string severity;
    std::string finding_confidence;  // "HIGH" | "MEDIUM" | "LOW"
    std::string source_confidence;   // carried through from the Rule definition
    std::string masked_value;        // NEVER the raw matched text
    size_t line_number = 0;
    std::vector<std::string> compliance_tags;
};

// Masks a matched value for reporting: shows at most the last 4
// characters, replaces everything else with '*' (preserving length so an
// operator can gauge the format without seeing the value). Values of 4
// characters or fewer are fully masked — too little entropy to safely
// reveal any of it.
inline std::string mask_value(std::string_view raw) {
    if (raw.size() <= 4)
        return std::string(raw.size(), '*');
    std::string out(raw.size() - 4, '*');
    out += raw.substr(raw.size() - 4);
    return out;
}

namespace detail {

inline bool contains_ci(std::string_view haystack, std::string_view needle) {
    if (needle.empty())
        return false;
    auto it = std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end(),
                          [](char a, char b) {
                              return std::tolower(static_cast<unsigned char>(a)) ==
                                     std::tolower(static_cast<unsigned char>(b));
                          });
    return it != haystack.end();
}

inline bool any_keyword_on_line(const std::vector<std::string>& keywords, std::string_view line) {
    for (const auto& kw : keywords) {
        if (contains_ci(line, kw))
            return true;
    }
    return false;
}

inline std::vector<std::string_view> split_lines(std::string_view text) {
    std::vector<std::string_view> lines;
    size_t start = 0;
    while (start <= text.size()) {
        size_t nl = text.find('\n', start);
        if (nl == std::string_view::npos) {
            lines.push_back(text.substr(start));
            break;
        }
        std::string_view line = text.substr(start, nl - start);
        if (!line.empty() && line.back() == '\r')
            line.remove_suffix(1);
        lines.push_back(line);
        start = nl + 1;
    }
    return lines;
}

} // namespace detail

struct CompiledRule {
    const Rule* rule = nullptr; // non-owning; the caller's Rule vector must outlive this
    std::unique_ptr<re2::RE2> regex;
};

// Compiles every rule's pattern once. Rules whose pattern fails to
// compile under RE2 are skipped (logged via `bad_rule_ids` if provided)
// rather than aborting the whole ruleset over one bad entry.
inline std::vector<CompiledRule> compile_rules(const std::vector<Rule>& rules,
                                               std::vector<std::string>* bad_rule_ids = nullptr) {
    std::vector<CompiledRule> compiled;
    compiled.reserve(rules.size());
    re2::RE2::Options opts;
    opts.set_case_sensitive(true);
    opts.set_log_errors(false);
    for (const auto& r : rules) {
        auto regex = std::make_unique<re2::RE2>(r.pattern, opts);
        if (!regex->ok()) {
            if (bad_rule_ids)
                bad_rule_ids->push_back(r.id);
            continue;
        }
        compiled.push_back(CompiledRule{&r, std::move(regex)});
    }
    return compiled;
}

// Scans `text` (the full content of one file, or any text blob) against
// every compiled rule and returns findings. `source_label` is carried
// only for the caller's own diagnostics (e.g. a file path) — it is not
// stored on the Finding itself, since this function has no concept of
// "file" beyond the text it was given.
inline std::vector<Finding> scan_text(const std::vector<CompiledRule>& compiled_rules,
                                      std::string_view text) {
    std::vector<Finding> findings;
    auto lines = detail::split_lines(text);

    for (size_t line_idx = 0; line_idx < lines.size(); ++line_idx) {
        std::string_view line = lines[line_idx];
        if (line.empty())
            continue;

        for (const auto& cr : compiled_rules) {
            size_t pos = 0;
            while (pos <= line.size()) {
                re2::StringPiece piece(line.data(), line.size());
                re2::StringPiece submatch;
                if (!cr.regex->Match(piece, pos, line.size(), re2::RE2::UNANCHORED, &submatch, 1))
                    break;

                size_t match_start = static_cast<size_t>(submatch.data() - line.data());
                size_t match_len = submatch.size();
                size_t match_end = match_start + match_len;

                if (match_len == 0) {
                    pos = match_start + 1; // avoid an infinite loop on a zero-length match
                    continue;
                }

                std::string_view matched_text = line.substr(match_start, match_len);

                std::optional<bool> checksum_result;
                if (cr.rule->checksum.has_value()) {
                    checksum_result = checksum::validate_named(*cr.rule->checksum, matched_text);
                }

                if (checksum_result.has_value() && !checksum_result.value()) {
                    // Explicit checksum FAILURE — drop, not just downgrade.
                    pos = match_end;
                    continue;
                }

                Finding f;
                f.rule_id = cr.rule->id;
                f.display_name = cr.rule->display_name;
                f.category = cr.rule->category;
                f.severity = cr.rule->severity;
                f.source_confidence = cr.rule->source_confidence;
                f.masked_value = mask_value(matched_text);
                f.line_number = line_idx + 1;
                f.compliance_tags = cr.rule->compliance_tags;

                if (checksum_result.has_value() && checksum_result.value()) {
                    f.finding_confidence = "HIGH";
                } else if (detail::any_keyword_on_line(cr.rule->confidence_keywords, line)) {
                    f.finding_confidence = "MEDIUM";
                } else {
                    f.finding_confidence = "LOW";
                }

                findings.push_back(std::move(f));
                pos = match_end;
            }
        }
    }

    return findings;
}

} // namespace yuzu::pii
