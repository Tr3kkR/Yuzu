// test_win_str_utils.cpp -- unit coverage for the shared Windows wide<->UTF-8
// helpers extracted in #1681 (agents/plugins/shared/win_str.hpp).
//
// Windows-only: the helpers and the cases that exercise them are #ifdef _WIN32.
// On other platforms this compiles to an empty translation unit so the file can
// be listed unconditionally in tests/meson.build (same convention as the
// test_dex_win_poll.cpp Windows-only cases).
//
// These are pure-function tests -- no registry I/O, no advapi32 -- mirroring the
// REG_SZ byte-count convention that RegQueryValueExW hands reg_sz_to_utf8.

#ifdef _WIN32

#include <win_str.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

using yuzu::win::from_wide;
using yuzu::win::reg_sz_to_utf8;
using yuzu::win::to_wide;

namespace {

// "Café" -- the canonical cp1252 0xE9 case from #1662. UTF-8 is 43 61 66 C3 A9;
// the é (U+00E9) is the byte that Reg*A returned as a lone 0xE9 (cp1252) and then
// failed UTF-8 validation downstream.
// Both sides written with explicit escapes so the test is independent of the
// source-file charset / compiler (a raw é in a wide literal is not guaranteed to
// land as U+00E9 across MSVC/GCC/Clang) -- exactly the class of bug under test.
const std::string kCafeUtf8 = "Caf\xC3\xA9";
const std::wstring kCafeWide = L"Caf\u00E9";

// REG_SZ payload size is in BYTES. Build one from a wchar_t array.
DWORD bytes_of(const std::vector<wchar_t>& v) {
    return static_cast<DWORD>(v.size() * sizeof(wchar_t));
}

} // namespace

TEST_CASE("to_wide / from_wide round-trip preserves non-ASCII", "[win][str][utf8]") {
    const std::wstring w = to_wide(kCafeUtf8);
    REQUIRE(w == kCafeWide);
    // from_wide with an explicit length (no NUL in the buffer).
    REQUIRE(from_wide(w.data(), static_cast<int>(w.size())) == kCafeUtf8);
    // from_wide with len == -1 over a NUL-terminated string.
    REQUIRE(from_wide(kCafeWide.c_str()) == kCafeUtf8);
}

TEST_CASE("from_wide handles empty and null input", "[win][str][utf8]") {
    REQUIRE(from_wide(nullptr).empty());
    REQUIRE(from_wide(L"").empty());
    REQUIRE(from_wide(L"", -1).empty());
    REQUIRE(to_wide("").empty());
}

TEST_CASE("from_wide converts a 512-wchar value with no terminator", "[win][str][utf8]") {
    // Exactly the buffer width the Reg* read sites use (#652 -- the value fills
    // the buffer with no room for a NUL). An explicit length must convert all 512.
    const std::wstring big(512, L'x');
    const std::string out = from_wide(big.data(), 512);
    REQUIRE(out.size() == 512);
    REQUIRE(out == std::string(512, 'x'));
}

TEST_CASE("from_wide maps a lone surrogate to U+FFFD", "[win][str][utf8]") {
    // No WC_ERR_INVALID_CHARS flag -> WideCharToMultiByte substitutes U+FFFD
    // (EF BF BD) rather than failing. Pin that contract.
    const wchar_t lone[] = {static_cast<wchar_t>(0xD800), L'\0'};
    REQUIRE(from_wide(lone, 1) == "\xEF\xBF\xBD");
}

TEST_CASE("reg_sz_to_utf8 strips trailing NULs by wchar count", "[win][str][reg]") {
    SECTION("no trailing NUL") {
        std::vector<wchar_t> buf = {L'A', L'B'};
        REQUIRE(reg_sz_to_utf8(buf.data(), bytes_of(buf)) == "AB");
    }
    SECTION("one trailing NUL (the common RegQueryValueExW case)") {
        std::vector<wchar_t> buf = {L'A', L'B', L'\0'};
        REQUIRE(reg_sz_to_utf8(buf.data(), bytes_of(buf)) == "AB");
    }
    SECTION("two trailing NULs (double-terminated)") {
        std::vector<wchar_t> buf = {L'A', L'B', L'\0', L'\0'};
        REQUIRE(reg_sz_to_utf8(buf.data(), bytes_of(buf)) == "AB");
    }
}

TEST_CASE("reg_sz_to_utf8 floors a non-wchar-multiple size", "[win][str][reg]") {
    // size_bytes that is not a whole multiple of sizeof(wchar_t) (a malformed /
    // truncated registry report) floors to whole wchar units -- it must not read
    // a partial trailing wchar_t.
    std::vector<wchar_t> buf = {L'A', L'B', L'\0'};
    const DWORD odd = bytes_of(buf) - 1; // 5 bytes on a 2-byte-wchar platform
    REQUIRE(reg_sz_to_utf8(buf.data(), odd) == "AB");
}

TEST_CASE("reg_sz_to_utf8 preserves non-ASCII (Café)", "[win][str][reg]") {
    std::vector<wchar_t> buf = {L'C', L'a', L'f', L'\u00E9', L'\0'};
    REQUIRE(reg_sz_to_utf8(buf.data(), bytes_of(buf)) == kCafeUtf8);
}

TEST_CASE("reg_sz_to_utf8 handles null buffer and empty payload", "[win][str][reg]") {
    REQUIRE(reg_sz_to_utf8(nullptr, 10).empty());
    std::vector<wchar_t> buf = {L'\0'};
    REQUIRE(reg_sz_to_utf8(buf.data(), bytes_of(buf)).empty());
    REQUIRE(reg_sz_to_utf8(buf.data(), 0).empty());
}

#endif // _WIN32
