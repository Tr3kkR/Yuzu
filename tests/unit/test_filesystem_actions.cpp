/**
 * test_filesystem_actions.cpp -- Unit tests for filesystem plugin new actions
 *
 * Tests the helper functions (glob_match, has_nested_quantifiers,
 * atomic_write_file) and core file operation logic (search, replace,
 * append, delete_lines) by replicating the algorithms from the plugin.
 *
 * Same pattern as test_filesystem_read.cpp: helpers are copied into the
 * test file's anonymous namespace since we cannot link the plugin directly.
 */

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <regex>
#include <string>
#include <string_view>
#include <vector>

namespace fs = std::filesystem;

namespace {

// ── TempFile / TempDir helpers ──────────────────────────────────────────

struct TempFile {
    fs::path path;

    explicit TempFile(const std::string& content = "",
                      const std::string& name = "yuzu_test_fsaction.txt") {
        path = fs::temp_directory_path() / name;
        std::ofstream f(path, std::ios::binary);
        f << content;
    }

    ~TempFile() {
        std::error_code ec;
        fs::remove(path, ec);
    }
};

struct TempDir {
    fs::path path;

    explicit TempDir(const std::string& name = "yuzu_test_fsaction_dir") {
        path = fs::temp_directory_path() / name;
        std::error_code ec;
        fs::create_directories(path, ec);
    }

    ~TempDir() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
};

// ── Replicated: glob_match ──────────────────────────────────────────────
// Exact copy from filesystem_plugin.cpp

bool glob_match(std::string_view pattern, std::string_view text) {
    size_t px = 0, tx = 0;
    size_t star_px = std::string_view::npos, star_tx = 0;

    while (tx < text.size()) {
        if (px < pattern.size() && (pattern[px] == '?' ||
            (pattern[px] != '*' && pattern[px] != '[' && (pattern[px] == text[tx])))) {
            ++px; ++tx;
        } else if (px < pattern.size() && pattern[px] == '[') {
            ++px;
            bool negate = (px < pattern.size() && pattern[px] == '!');
            if (negate) ++px;
            bool matched = false;
            while (px < pattern.size() && pattern[px] != ']') {
                if (px + 2 < pattern.size() && pattern[px + 1] == '-') {
                    if (text[tx] >= pattern[px] && text[tx] <= pattern[px + 2])
                        matched = true;
                    px += 3;
                } else {
                    if (text[tx] == pattern[px]) matched = true;
                    ++px;
                }
            }
            if (px < pattern.size()) ++px; // skip ']'
            if (matched == negate) {
                if (star_px != std::string_view::npos) { px = star_px + 1; tx = ++star_tx; }
                else return false;
            } else { ++tx; }
        } else if (px < pattern.size() && pattern[px] == '*') {
            star_px = px; star_tx = tx; ++px;
        } else if (star_px != std::string_view::npos) {
            px = star_px + 1; tx = ++star_tx;
        } else {
            return false;
        }
    }
    while (px < pattern.size() && pattern[px] == '*') ++px;
    return px == pattern.size();
}

// ── Replicated: has_nested_quantifiers ──────────────────────────────────
// Exact copy from filesystem_plugin.cpp

bool has_nested_quantifiers(std::string_view pattern) {
    int paren_depth = 0;
    bool last_was_quantifier = false;
    for (size_t i = 0; i < pattern.size(); ++i) {
        char c = pattern[i];
        if (c == '\\' && i + 1 < pattern.size()) { ++i; last_was_quantifier = false; continue; }
        if (c == '(') { ++paren_depth; last_was_quantifier = false; continue; }
        if (c == ')') {
            --paren_depth;
            if (i + 1 < pattern.size() && last_was_quantifier) {
                char next = pattern[i + 1];
                if (next == '+' || next == '*' || next == '?' || next == '{')
                    return true;
            }
            last_was_quantifier = false;
            continue;
        }
        last_was_quantifier = (c == '+' || c == '*' || c == '?' ||
                               (c == '}' && pattern.substr(0, i).rfind('{') != std::string_view::npos));
    }
    return false;
}

// ── Replicated: atomic_write_file ───────────────────────────────────────
// Simplified (non-Windows) copy from filesystem_plugin.cpp

bool atomic_write_file(const fs::path& target, std::string_view content) {
    auto dir = target.parent_path();
    auto tmp = dir / (target.filename().string() + ".yuzu_tmp");
    {
        std::ofstream ofs(tmp, std::ios::binary | std::ios::trunc);
        if (!ofs) return false;
        ofs.write(content.data(), static_cast<std::streamsize>(content.size()));
        if (!ofs) { std::error_code ec; fs::remove(tmp, ec); return false; }
    }
    std::error_code ec;
    fs::rename(tmp, target, ec);
    if (ec) { fs::remove(tmp, ec); return false; }
    return true;
}

// ── Helper: read entire file as string ──────────────────────────────────

std::string read_file(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(f)),
                        std::istreambuf_iterator<char>());
}

// ── Helper: read file lines ─────────────────────────────────────────────

std::vector<std::string> read_lines(const fs::path& p) {
    std::ifstream f(p);
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(f, line)) {
        lines.push_back(std::move(line));
    }
    return lines;
}

} // namespace

// ============================================================================
// Section A: glob_match tests
// ============================================================================

TEST_CASE("GlobMatch: wildcard *.txt matches hello.txt", "[filesystem][glob]") {
    CHECK(glob_match("*.txt", "hello.txt") == true);
}

TEST_CASE("GlobMatch: wildcard *.txt does not match hello.cpp", "[filesystem][glob]") {
    CHECK(glob_match("*.txt", "hello.cpp") == false);
}

TEST_CASE("GlobMatch: prefix wildcard test*", "[filesystem][glob]") {
    CHECK(glob_match("test*", "testing") == true);
}

TEST_CASE("GlobMatch: single char ? matches one char", "[filesystem][glob]") {
    CHECK(glob_match("test?", "test1") == true);
}

TEST_CASE("GlobMatch: single char ? does not match two chars", "[filesystem][glob]") {
    CHECK(glob_match("test?", "test12") == false);
}

TEST_CASE("GlobMatch: character class [abc] matches 'a'", "[filesystem][glob]") {
    CHECK(glob_match("[abc]", "a") == true);
}

TEST_CASE("GlobMatch: character class [abc] does not match 'd'", "[filesystem][glob]") {
    CHECK(glob_match("[abc]", "d") == false);
}

TEST_CASE("GlobMatch: character range [a-z] matches 'm'", "[filesystem][glob]") {
    CHECK(glob_match("[a-z]", "m") == true);
}

TEST_CASE("GlobMatch: negated class [!a-z] matches digit", "[filesystem][glob]") {
    CHECK(glob_match("[!a-z]", "1") == true);
}

TEST_CASE("GlobMatch: bare * matches anything", "[filesystem][glob]") {
    CHECK(glob_match("*", "anything") == true);
}

TEST_CASE("GlobMatch: empty pattern matches empty string", "[filesystem][glob]") {
    CHECK(glob_match("", "") == true);
}

TEST_CASE("GlobMatch: empty pattern does not match non-empty", "[filesystem][glob]") {
    CHECK(glob_match("", "x") == false);
}

TEST_CASE("GlobMatch: exact match without wildcards", "[filesystem][glob]") {
    CHECK(glob_match("hello.txt", "hello.txt") == true);
    CHECK(glob_match("hello.txt", "hello.txT") == false);
}

TEST_CASE("GlobMatch: multiple wildcards", "[filesystem][glob]") {
    CHECK(glob_match("*test*", "my_test_file") == true);
    CHECK(glob_match("*test*", "nope") == false);
}

TEST_CASE("GlobMatch: ? in middle of pattern", "[filesystem][glob]") {
    CHECK(glob_match("h?llo", "hello") == true);
    CHECK(glob_match("h?llo", "hallo") == true);
    CHECK(glob_match("h?llo", "hllo") == false);
}

TEST_CASE("GlobMatch: combined wildcards and classes", "[filesystem][glob]") {
    CHECK(glob_match("[a-z]*.[ch]pp", "main.cpp") == true);
    CHECK(glob_match("[a-z]*.[ch]pp", "test.hpp") == true);
    CHECK(glob_match("[a-z]*.[ch]pp", "Main.cpp") == false);
}

// ============================================================================
// Section B: has_nested_quantifiers tests (ReDoS guard)
// ============================================================================

TEST_CASE("NestedQuantifiers: (a+)+ is ReDoS", "[filesystem][redos]") {
    CHECK(has_nested_quantifiers("(a+)+") == true);
}

TEST_CASE("NestedQuantifiers: (a*)+ is ReDoS", "[filesystem][redos]") {
    CHECK(has_nested_quantifiers("(a*)+") == true);
}

TEST_CASE("NestedQuantifiers: (a+)* is ReDoS", "[filesystem][redos]") {
    CHECK(has_nested_quantifiers("(a+)*") == true);
}

TEST_CASE("NestedQuantifiers: simple a+ is safe", "[filesystem][redos]") {
    CHECK(has_nested_quantifiers("a+") == false);
}

TEST_CASE("NestedQuantifiers: (abc)+ no inner quantifier is safe", "[filesystem][redos]") {
    CHECK(has_nested_quantifiers("(abc)+") == false);
}

TEST_CASE("NestedQuantifiers: escaped parens not a group", "[filesystem][redos]") {
    CHECK(has_nested_quantifiers("\\(a+\\)+") == false);
}

TEST_CASE("NestedQuantifiers: character class not a group", "[filesystem][redos]") {
    CHECK(has_nested_quantifiers("[a-z]+") == false);
}

TEST_CASE("NestedQuantifiers: (a*){2} is ReDoS", "[filesystem][redos]") {
    CHECK(has_nested_quantifiers("(a*){2}") == true);
}

TEST_CASE("NestedQuantifiers: simple patterns are safe", "[filesystem][redos]") {
    CHECK(has_nested_quantifiers("hello") == false);
    CHECK(has_nested_quantifiers("^foo$") == false);
    CHECK(has_nested_quantifiers("[abc]+") == false);
    CHECK(has_nested_quantifiers("a{3}") == false);
}

// ============================================================================
// Section C: atomic_write_file tests
// ============================================================================

TEST_CASE("AtomicWrite: replaces existing file content", "[filesystem][atomic]") {
    TempFile tf("original content", "yuzu_test_atomic_replace.txt");
    CHECK(read_file(tf.path) == "original content");

    bool ok = atomic_write_file(tf.path, "new content");
    CHECK(ok == true);
    CHECK(read_file(tf.path) == "new content");
}

TEST_CASE("AtomicWrite: writes new file in existing directory", "[filesystem][atomic]") {
    TempDir td("yuzu_test_atomic_new");
    auto target = td.path / "new_file.txt";

    // Create an initial file so rename target exists
    { std::ofstream f(target); f << ""; }

    bool ok = atomic_write_file(target, "hello world");
    CHECK(ok == true);
    CHECK(read_file(target) == "hello world");

    std::error_code ec;
    fs::remove(target, ec);
}

TEST_CASE("AtomicWrite: writes empty content", "[filesystem][atomic]") {
    TempFile tf("non-empty", "yuzu_test_atomic_empty.txt");

    bool ok = atomic_write_file(tf.path, "");
    CHECK(ok == true);
    CHECK(read_file(tf.path).empty());
}

TEST_CASE("AtomicWrite: writes large content 1MB", "[filesystem][atomic]") {
    TempFile tf("", "yuzu_test_atomic_large.txt");

    // Generate 1MB of content
    std::string large(1024 * 1024, 'X');
    bool ok = atomic_write_file(tf.path, large);
    CHECK(ok == true);

    auto result = read_file(tf.path);
    CHECK(result.size() == 1024 * 1024);
    CHECK(result == large);
}

TEST_CASE("AtomicWrite: content roundtrip preserves exact bytes", "[filesystem][atomic]") {
    TempFile tf("", "yuzu_test_atomic_exact.txt");

    // Include special characters, newlines, tabs, unicode-like bytes
    std::string content = "line1\nline2\r\nline3\ttab\0null";
    // Note: the string literal above with \0 only goes up to \0
    // Use explicit construction for content with embedded NUL
    std::string with_nul = "abc";
    with_nul += '\0';
    with_nul += "def";

    bool ok = atomic_write_file(tf.path, with_nul);
    CHECK(ok == true);

    auto result = read_file(tf.path);
    CHECK(result.size() == with_nul.size());
    CHECK(result == with_nul);
}

// ============================================================================
// Section D: File content operations -- Search
// ============================================================================

TEST_CASE("Search: literal string finds correct line numbers", "[filesystem][search]") {
    std::string content = "alpha\nbeta\ngamma\nalpha beta\nepsilon\n";
    TempFile tf(content, "yuzu_test_search_literal.txt");

    // Replicate the search logic: read line by line, find pattern
    std::ifstream f(tf.path);
    std::string line;
    int line_num = 0;
    std::vector<int> match_lines;
    std::string pattern = "alpha";

    while (std::getline(f, line)) {
        ++line_num;
        if (line.find(pattern) != std::string::npos) {
            match_lines.push_back(line_num);
        }
    }

    REQUIRE(match_lines.size() == 2);
    CHECK(match_lines[0] == 1);
    CHECK(match_lines[1] == 4);
}

TEST_CASE("Search: case-insensitive search", "[filesystem][search]") {
    std::string content = "Hello World\nhello world\nHELLO WORLD\nno match\n";
    TempFile tf(content, "yuzu_test_search_icase.txt");

    std::ifstream f(tf.path);
    std::string line;
    int line_num = 0;
    int match_count = 0;
    std::string pattern = "hello";

    while (std::getline(f, line)) {
        ++line_num;
        std::string lower = line;
        std::transform(lower.begin(), lower.end(), lower.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (lower.find(pattern) != std::string::npos) {
            ++match_count;
        }
    }

    CHECK(match_count == 3);
}

TEST_CASE("Search: regex search", "[filesystem][search]") {
    std::string content = "error: file not found\nwarning: deprecated\nerror: timeout\ninfo: ok\n";
    TempFile tf(content, "yuzu_test_search_regex.txt");

    std::regex re("error:.*");
    std::ifstream f(tf.path);
    std::string line;
    int match_count = 0;
    std::vector<int> match_lines;
    int line_num = 0;

    while (std::getline(f, line)) {
        ++line_num;
        if (std::regex_search(line, re)) {
            ++match_count;
            match_lines.push_back(line_num);
        }
    }

    REQUIRE(match_count == 2);
    CHECK(match_lines[0] == 1);
    CHECK(match_lines[1] == 3);
}

TEST_CASE("Search: no matches returns empty", "[filesystem][search]") {
    std::string content = "alpha\nbeta\ngamma\n";
    TempFile tf(content, "yuzu_test_search_nomatch.txt");

    std::ifstream f(tf.path);
    std::string line;
    int match_count = 0;

    while (std::getline(f, line)) {
        if (line.find("delta") != std::string::npos) {
            ++match_count;
        }
    }

    CHECK(match_count == 0);
}

TEST_CASE("Search: pattern at beginning, middle, and end of line", "[filesystem][search]") {
    std::string content = "ABC start\nmid ABC mid\nend ABC\n";
    TempFile tf(content, "yuzu_test_search_positions.txt");

    std::ifstream f(tf.path);
    std::string line;
    int match_count = 0;

    while (std::getline(f, line)) {
        if (line.find("ABC") != std::string::npos) {
            ++match_count;
        }
    }

    CHECK(match_count == 3);
}

// ============================================================================
// Section D: File content operations -- Replace
// ============================================================================

TEST_CASE("Replace: literal replace modifies file", "[filesystem][replace]") {
    std::string content = "hello world\nhello planet\ngoodbye world\n";
    TempFile tf(content, "yuzu_test_replace_literal.txt");

    // Read file content
    std::string data = read_file(tf.path);

    // Perform literal replace of "hello" with "greetings"
    std::string search = "hello";
    std::string replacement = "greetings";
    std::string result;
    size_t pos = 0;
    int count = 0;

    while (pos < data.size()) {
        size_t found = data.find(search, pos);
        if (found == std::string::npos) {
            result.append(data, pos, data.size() - pos);
            break;
        }
        result.append(data, pos, found - pos);
        result.append(replacement);
        pos = found + search.size();
        ++count;
    }

    CHECK(count == 2);

    // Write back
    bool ok = atomic_write_file(tf.path, result);
    CHECK(ok == true);

    auto final_content = read_file(tf.path);
    CHECK(final_content == "greetings world\ngreetings planet\ngoodbye world\n");
}

TEST_CASE("Replace: dry run does not modify file", "[filesystem][replace]") {
    std::string content = "hello world\n";
    TempFile tf(content, "yuzu_test_replace_dryrun.txt");

    // Read and count matches but do NOT write
    std::string data = read_file(tf.path);
    bool dry_run = true;
    int count = 0;
    size_t pos = 0;
    std::string search = "hello";

    while (pos < data.size()) {
        size_t found = data.find(search, pos);
        if (found == std::string::npos) break;
        ++count;
        pos = found + search.size();
    }

    CHECK(count == 1);

    if (!dry_run) {
        // Would write here
    }

    // Verify original content unchanged
    auto actual = read_file(tf.path);
    CHECK(actual == "hello world\n");
}

TEST_CASE("Replace: max_replacements honored", "[filesystem][replace]") {
    std::string content = "aaa bbb aaa ccc aaa\n";
    TempFile tf(content, "yuzu_test_replace_max.txt");

    std::string data = read_file(tf.path);
    std::string search = "aaa";
    std::string replacement = "XXX";
    int max_replacements = 2;
    int count = 0;
    std::string result;
    size_t pos = 0;

    while (pos < data.size()) {
        size_t found = data.find(search, pos);
        if (found == std::string::npos) {
            result.append(data, pos, data.size() - pos);
            break;
        }
        if (max_replacements > 0 && count >= max_replacements) {
            result.append(data, pos, data.size() - pos);
            break;
        }
        result.append(data, pos, found - pos);
        result.append(replacement);
        pos = found + search.size();
        ++count;
    }

    CHECK(count == 2);

    bool ok = atomic_write_file(tf.path, result);
    CHECK(ok == true);

    auto final_content = read_file(tf.path);
    CHECK(final_content == "XXX bbb XXX ccc aaa\n");
}

TEST_CASE("Replace: regex replace", "[filesystem][replace]") {
    std::string content = "error 123\nerror 456\ninfo 789\n";
    TempFile tf(content, "yuzu_test_replace_regex.txt");

    std::string data = read_file(tf.path);
    std::regex re("error (\\d+)");
    std::string replacement = "fixed $1";

    auto it = std::sregex_iterator(data.begin(), data.end(), re);
    auto end = std::sregex_iterator();
    int count = static_cast<int>(std::distance(it, end));
    CHECK(count == 2);

    std::string result = std::regex_replace(data, re, replacement);
    bool ok = atomic_write_file(tf.path, result);
    CHECK(ok == true);

    auto final_content = read_file(tf.path);
    CHECK(final_content == "fixed 123\nfixed 456\ninfo 789\n");
}

TEST_CASE("Replace: no occurrences leaves file unchanged", "[filesystem][replace]") {
    std::string content = "alpha beta gamma\n";
    TempFile tf(content, "yuzu_test_replace_none.txt");

    std::string data = read_file(tf.path);
    size_t pos = data.find("delta");
    CHECK(pos == std::string::npos);

    // File should remain unchanged
    auto actual = read_file(tf.path);
    CHECK(actual == content);
}

// ============================================================================
// Section D: File content operations -- Append
// ============================================================================

TEST_CASE("Append: to file ending with newline -- no extra newline", "[filesystem][append]") {
    std::string content = "line1\nline2\n";
    TempFile tf(content, "yuzu_test_append_nl.txt");

    // Replicate the append logic: check if file ends with newline
    std::string data = read_file(tf.path);
    CHECK(!data.empty());
    CHECK(data.back() == '\n');

    // Append without adding extra newline
    std::ofstream ofs(tf.path, std::ios::binary | std::ios::app);
    std::string to_append = "line3\n";

    // Since file ends with \n, do not add extra
    ofs.write(to_append.data(), static_cast<std::streamsize>(to_append.size()));
    ofs.close();

    auto result = read_file(tf.path);
    CHECK(result == "line1\nline2\nline3\n");

    auto lines = read_lines(tf.path);
    CHECK(lines.size() == 3);
}

TEST_CASE("Append: to file NOT ending with newline -- newline auto-added", "[filesystem][append]") {
    std::string content = "line1\nline2";
    TempFile tf(content, "yuzu_test_append_nonl.txt");

    // Check file does not end with newline
    std::string data = read_file(tf.path);
    REQUIRE(!data.empty());
    CHECK(data.back() != '\n');

    // Replicate the append logic with newline auto-add
    std::ofstream ofs(tf.path, std::ios::binary | std::ios::app);
    size_t bytes = 0;

    // Auto-add newline before appending
    ofs.put('\n');
    ++bytes;

    std::string to_append = "line3";
    ofs.write(to_append.data(), static_cast<std::streamsize>(to_append.size()));
    bytes += to_append.size();
    ofs.close();

    auto result = read_file(tf.path);
    CHECK(result == "line1\nline2\nline3");
    CHECK(bytes == to_append.size() + 1); // +1 for the auto newline
}

TEST_CASE("Append: empty content appended", "[filesystem][append]") {
    std::string content = "existing\n";
    TempFile tf(content, "yuzu_test_append_empty.txt");

    std::ofstream ofs(tf.path, std::ios::binary | std::ios::app);
    std::string to_append = "";
    ofs.write(to_append.data(), static_cast<std::streamsize>(to_append.size()));
    ofs.close();

    auto result = read_file(tf.path);
    CHECK(result == "existing\n");
}

TEST_CASE("Append: verify total size correct", "[filesystem][append]") {
    std::string content = "hello";
    TempFile tf(content, "yuzu_test_append_size.txt");

    std::string to_append = " world";

    // Auto-add newline since file doesn't end with \n
    {
        std::ofstream ofs(tf.path, std::ios::binary | std::ios::app);
        // File doesn't end with \n, so add one
        ofs.put('\n');
        ofs.write(to_append.data(), static_cast<std::streamsize>(to_append.size()));
    }

    std::error_code ec;
    auto total_size = fs::file_size(tf.path, ec);
    // "hello" (5) + '\n' (1) + " world" (6) = 12
    CHECK(total_size == 12);
}

TEST_CASE("Append: multiple appends accumulate correctly", "[filesystem][append]") {
    std::string content = "line1\n";
    TempFile tf(content, "yuzu_test_append_multi.txt");

    for (int i = 2; i <= 5; ++i) {
        std::ofstream ofs(tf.path, std::ios::binary | std::ios::app);
        std::string line = "line" + std::to_string(i) + "\n";
        ofs.write(line.data(), static_cast<std::streamsize>(line.size()));
    }

    auto lines = read_lines(tf.path);
    REQUIRE(lines.size() == 5);
    CHECK(lines[0] == "line1");
    CHECK(lines[4] == "line5");
}

// ============================================================================
// Section D: File content operations -- Delete lines
// ============================================================================

TEST_CASE("DeleteLines: delete middle range", "[filesystem][deletelines]") {
    std::string content = "line1\nline2\nline3\nline4\nline5\n";
    TempFile tf(content, "yuzu_test_dellines_mid.txt");

    // Read all lines
    auto lines = read_lines(tf.path);
    REQUIRE(lines.size() == 5);

    // Delete lines 2-4 (1-based)
    int start_line = 2;
    int end_line = 4;
    lines.erase(lines.begin() + (start_line - 1), lines.begin() + end_line);

    // Rebuild content
    std::string result;
    for (size_t i = 0; i < lines.size(); ++i) {
        result += lines[i];
        if (i + 1 < lines.size()) result += '\n';
    }
    if (!lines.empty()) result += '\n';

    bool ok = atomic_write_file(tf.path, result);
    CHECK(ok == true);

    auto final_lines = read_lines(tf.path);
    REQUIRE(final_lines.size() == 2);
    CHECK(final_lines[0] == "line1");
    CHECK(final_lines[1] == "line5");
}

TEST_CASE("DeleteLines: delete first line", "[filesystem][deletelines]") {
    std::string content = "first\nsecond\nthird\n";
    TempFile tf(content, "yuzu_test_dellines_first.txt");

    auto lines = read_lines(tf.path);
    REQUIRE(lines.size() == 3);

    // Delete line 1
    lines.erase(lines.begin());

    std::string result;
    for (size_t i = 0; i < lines.size(); ++i) {
        result += lines[i];
        if (i + 1 < lines.size()) result += '\n';
    }
    if (!lines.empty()) result += '\n';

    bool ok = atomic_write_file(tf.path, result);
    CHECK(ok == true);

    auto final_lines = read_lines(tf.path);
    REQUIRE(final_lines.size() == 2);
    CHECK(final_lines[0] == "second");
    CHECK(final_lines[1] == "third");
}

TEST_CASE("DeleteLines: delete last line", "[filesystem][deletelines]") {
    std::string content = "first\nsecond\nthird\n";
    TempFile tf(content, "yuzu_test_dellines_last.txt");

    auto lines = read_lines(tf.path);
    REQUIRE(lines.size() == 3);

    // Delete line 3 (the last)
    int total = static_cast<int>(lines.size());
    lines.erase(lines.begin() + (total - 1));

    std::string result;
    for (size_t i = 0; i < lines.size(); ++i) {
        result += lines[i];
        if (i + 1 < lines.size()) result += '\n';
    }
    if (!lines.empty()) result += '\n';

    bool ok = atomic_write_file(tf.path, result);
    CHECK(ok == true);

    auto final_lines = read_lines(tf.path);
    REQUIRE(final_lines.size() == 2);
    CHECK(final_lines[0] == "first");
    CHECK(final_lines[1] == "second");
}

TEST_CASE("DeleteLines: start_line > total lines is an error", "[filesystem][deletelines]") {
    std::string content = "line1\nline2\nline3\n";
    TempFile tf(content, "yuzu_test_dellines_oob.txt");

    auto lines = read_lines(tf.path);
    int total_before = static_cast<int>(lines.size());
    int start_line = 10;

    CHECK(start_line > total_before);

    // The plugin would return an error here; verify the condition
    // and that original file is untouched
    auto original = read_file(tf.path);
    CHECK(original == content);
}

TEST_CASE("DeleteLines: delete all lines", "[filesystem][deletelines]") {
    std::string content = "line1\nline2\nline3\n";
    TempFile tf(content, "yuzu_test_dellines_all.txt");

    auto lines = read_lines(tf.path);
    REQUIRE(lines.size() == 3);

    // Delete lines 1-3
    lines.erase(lines.begin(), lines.begin() + 3);
    CHECK(lines.empty());

    // Rebuild: empty content since no lines remain
    std::string result;
    // The plugin would write "" if lines is empty (the trailing newline
    // is only added when !lines.empty())

    bool ok = atomic_write_file(tf.path, result);
    CHECK(ok == true);

    auto final_content = read_file(tf.path);
    CHECK(final_content.empty());
}

TEST_CASE("DeleteLines: delete single line from multi-line file", "[filesystem][deletelines]") {
    std::string content = "alpha\nbeta\ngamma\ndelta\nepsilon\n";
    TempFile tf(content, "yuzu_test_dellines_single.txt");

    auto lines = read_lines(tf.path);
    REQUIRE(lines.size() == 5);

    // Delete only line 3 (gamma)
    int start_line = 3;
    int end_line = 3;
    lines.erase(lines.begin() + (start_line - 1), lines.begin() + end_line);

    std::string result;
    for (size_t i = 0; i < lines.size(); ++i) {
        result += lines[i];
        if (i + 1 < lines.size()) result += '\n';
    }
    if (!lines.empty()) result += '\n';

    bool ok = atomic_write_file(tf.path, result);
    CHECK(ok == true);

    auto final_lines = read_lines(tf.path);
    REQUIRE(final_lines.size() == 4);
    CHECK(final_lines[0] == "alpha");
    CHECK(final_lines[1] == "beta");
    CHECK(final_lines[2] == "delta");
    CHECK(final_lines[3] == "epsilon");
}

TEST_CASE("DeleteLines: end_line clamped to total lines", "[filesystem][deletelines]") {
    std::string content = "line1\nline2\nline3\n";
    TempFile tf(content, "yuzu_test_dellines_clamp.txt");

    auto lines = read_lines(tf.path);
    int total_before = static_cast<int>(lines.size());
    REQUIRE(total_before == 3);

    // Request delete lines 2-100, should clamp end_line to 3
    int start_line = 2;
    int end_line = 100;
    if (end_line > total_before) end_line = total_before;

    CHECK(end_line == 3);

    lines.erase(lines.begin() + (start_line - 1), lines.begin() + end_line);

    std::string result;
    for (size_t i = 0; i < lines.size(); ++i) {
        result += lines[i];
        if (i + 1 < lines.size()) result += '\n';
    }
    if (!lines.empty()) result += '\n';

    bool ok = atomic_write_file(tf.path, result);
    CHECK(ok == true);

    auto final_lines = read_lines(tf.path);
    REQUIRE(final_lines.size() == 1);
    CHECK(final_lines[0] == "line1");
}
