#include "yaml_scan.hpp"

#include <cstddef>

namespace yuzu::server::yaml_scan {

std::string extract_yaml_value(const std::string& yaml, const std::string& key) {
    // Look for "key:" at the start of a line (with optional leading whitespace)
    auto search = key + ":";
    auto pos = yaml.find(search);
    while (pos != std::string::npos) {
        // Verify it's either at start or preceded by whitespace/newline
        if (pos > 0 && yaml[pos - 1] != '\n' && yaml[pos - 1] != ' ' && yaml[pos - 1] != '\t') {
            pos = yaml.find(search, pos + 1);
            continue;
        }
        auto vstart = pos + search.size();
        // Skip whitespace after colon
        while (vstart < yaml.size() && (yaml[vstart] == ' ' || yaml[vstart] == '\t'))
            ++vstart;
        if (vstart >= yaml.size() || yaml[vstart] == '\n') {
            // Block scalar or nested — for folded (>) grab next indented line
            if (vstart < yaml.size() && yaml[vstart] == '\n') {
                auto nl = yaml.find_first_not_of(" \t\n", vstart + 1);
                if (nl != std::string::npos) {
                    auto eol = yaml.find('\n', nl);
                    if (eol == std::string::npos)
                        eol = yaml.size();
                    // Only return if indented (part of this block)
                    if (nl > vstart + 1)
                        return std::string{};
                }
            }
            return {};
        }
        auto eol = yaml.find('\n', vstart);
        if (eol == std::string::npos)
            eol = yaml.size();
        auto val = yaml.substr(vstart, eol - vstart);
        // Strip trailing whitespace
        while (!val.empty() && (val.back() == ' ' || val.back() == '\t' || val.back() == '\r'))
            val.pop_back();
        // Strip surrounding quotes
        if (val.size() >= 2 &&
            ((val.front() == '"' && val.back() == '"') ||
             (val.front() == '\'' && val.back() == '\''))) {
            val = val.substr(1, val.size() - 2);
        }
        // Handle YAML folded/literal block indicator
        if (val == ">" || val == "|")
            return {};
        return val;
    }
    return {};
}

std::vector<std::string> extract_yaml_list(const std::string& yaml, const std::string& key) {
    std::vector<std::string> result;
    auto search = key + ":";
    auto pos = yaml.find(search);
    if (pos == std::string::npos)
        return result;

    // Move past the key line
    auto eol = yaml.find('\n', pos);
    if (eol == std::string::npos)
        return result;

    // Check for inline list: key: [item1, item2]
    auto colon_end = pos + search.size();
    while (colon_end < yaml.size() && (yaml[colon_end] == ' ' || yaml[colon_end] == '\t'))
        ++colon_end;
    if (colon_end < yaml.size() && yaml[colon_end] == '[') {
        auto bracket_end = yaml.find(']', colon_end);
        if (bracket_end != std::string::npos) {
            auto inner = yaml.substr(colon_end + 1, bracket_end - colon_end - 1);
            // Split by comma
            size_t start = 0;
            while (start < inner.size()) {
                auto comma = inner.find(',', start);
                if (comma == std::string::npos)
                    comma = inner.size();
                auto item = inner.substr(start, comma - start);
                // Trim whitespace and quotes
                while (!item.empty() && (item.front() == ' ' || item.front() == '\t'))
                    item.erase(item.begin());
                while (!item.empty() && (item.back() == ' ' || item.back() == '\t'))
                    item.pop_back();
                if (item.size() >= 2 &&
                    ((item.front() == '"' && item.back() == '"') ||
                     (item.front() == '\'' && item.back() == '\'')))
                    item = item.substr(1, item.size() - 2);
                if (!item.empty())
                    result.push_back(item);
                start = comma + 1;
            }
            return result;
        }
    }

    // Block list: lines starting with "- "
    size_t line_start = eol + 1;
    while (line_start < yaml.size()) {
        auto next_eol = yaml.find('\n', line_start);
        if (next_eol == std::string::npos)
            next_eol = yaml.size();

        auto line = yaml.substr(line_start, next_eol - line_start);
        // Trim leading whitespace
        auto first_char = line.find_first_not_of(" \t");
        if (first_char == std::string::npos || line[first_char] == '#') {
            line_start = next_eol + 1;
            continue;
        }
        // Stop if not a list item and not blank
        if (line[first_char] != '-')
            break;

        auto item = line.substr(first_char + 1);
        // Trim
        while (!item.empty() && (item.front() == ' ' || item.front() == '\t'))
            item.erase(item.begin());
        while (!item.empty() && (item.back() == ' ' || item.back() == '\t' || item.back() == '\r'))
            item.pop_back();
        if (item.size() >= 2 &&
            ((item.front() == '"' && item.back() == '"') ||
             (item.front() == '\'' && item.back() == '\'')))
            item = item.substr(1, item.size() - 2);
        if (!item.empty())
            result.push_back(item);

        line_start = next_eol + 1;
    }
    return result;
}

std::vector<std::pair<std::string, std::string>>
extract_yaml_mapping(const std::string& yaml, const std::string& key) {
    std::vector<std::pair<std::string, std::string>> result;
    auto search = key + ":";
    auto pos = yaml.find(search);
    if (pos == std::string::npos)
        return result;

    auto eol = yaml.find('\n', pos);
    if (eol == std::string::npos)
        return result;

    // Determine the indentation of the key itself
    auto key_line_start = yaml.rfind('\n', pos);
    if (key_line_start == std::string::npos)
        key_line_start = 0;
    else
        key_line_start++;
    size_t key_indent = pos - key_line_start;

    size_t line_start = eol + 1;
    while (line_start < yaml.size()) {
        auto next_eol = yaml.find('\n', line_start);
        if (next_eol == std::string::npos)
            next_eol = yaml.size();

        auto line = yaml.substr(line_start, next_eol - line_start);
        auto first_char = line.find_first_not_of(" \t");
        if (first_char == std::string::npos) {
            line_start = next_eol + 1;
            continue;
        }
        // Stop if indentation is <= key indentation (back to same or outer level)
        if (first_char <= key_indent)
            break;

        // Parse "subkey: value"
        auto colon = line.find(':', first_char);
        if (colon != std::string::npos) {
            auto k = line.substr(first_char, colon - first_char);
            while (!k.empty() && (k.back() == ' ' || k.back() == '\t'))
                k.pop_back();
            auto v_start = colon + 1;
            while (v_start < line.size() && (line[v_start] == ' ' || line[v_start] == '\t'))
                ++v_start;
            auto v = (v_start < line.size()) ? line.substr(v_start) : std::string{};
            while (!v.empty() && (v.back() == ' ' || v.back() == '\t' || v.back() == '\r'))
                v.pop_back();
            if (v.size() >= 2 &&
                ((v.front() == '"' && v.back() == '"') ||
                 (v.front() == '\'' && v.back() == '\'')))
                v = v.substr(1, v.size() - 2);
            if (!k.empty())
                result.emplace_back(std::move(k), std::move(v));
        }

        line_start = next_eol + 1;
    }
    return result;
}

std::string extract_yaml_section(const std::string& yaml, const std::string& dotted_path) {
    std::string current = yaml;
    size_t dot = 0;
    std::string remaining = dotted_path;

    while (!remaining.empty()) {
        dot = remaining.find('.');
        auto segment = (dot == std::string::npos) ? remaining : remaining.substr(0, dot);
        remaining = (dot == std::string::npos) ? "" : remaining.substr(dot + 1);

        auto search = segment + ":";
        auto pos = current.find(search);
        if (pos == std::string::npos)
            return {};

        // Find where the section's content starts
        auto eol = current.find('\n', pos);
        if (eol == std::string::npos)
            return {};

        // Get indentation of this key
        auto key_line_start = current.rfind('\n', pos);
        if (key_line_start == std::string::npos)
            key_line_start = 0;
        else
            key_line_start++;
        size_t key_indent = pos - key_line_start;

        // Collect all lines more indented than this key
        std::string block;
        size_t line_start = eol + 1;
        while (line_start < current.size()) {
            auto next_eol = current.find('\n', line_start);
            if (next_eol == std::string::npos)
                next_eol = current.size();

            auto line = current.substr(line_start, next_eol - line_start);
            auto first_char = line.find_first_not_of(" \t");
            if (first_char == std::string::npos) {
                block += line + "\n";
                line_start = next_eol + 1;
                continue;
            }
            if (first_char <= key_indent)
                break;

            block += line + "\n";
            line_start = next_eol + 1;
        }
        current = block;
    }
    return current;
}

bool yaml_has_key(const std::string& block, const std::string& key) {
    const std::string needle = key + ":";
    size_t line_start = 0;
    while (line_start <= block.size()) {
        auto eol = block.find('\n', line_start);
        if (eol == std::string::npos)
            eol = block.size();
        auto fc = block.find_first_not_of(" \t", line_start);
        if (fc != std::string::npos && fc < eol && block[fc] != '#') {
            if (eol - fc >= needle.size() && block.compare(fc, needle.size(), needle) == 0)
                return true;
        }
        if (eol == block.size())
            break;
        line_start = eol + 1;
    }
    return false;
}

} // namespace yuzu::server::yaml_scan
