/**
 * test_system_hardening_win_parsers.cpp -- pure tests for
 * system_hardening_win_parsers.hpp. No platform guard, no <windows.h>, no OS
 * call. Inputs are REAL CAPTURE (fixtures/wave8/system_hardening/windows/
 * mitigation_options.hex from the-rig `reg query`; its .provenance.txt holds
 * `Get-ProcessMitigation -System` as `expect.<policy>=<on|off|default>` lines;
 * REQUIRE(exists), never skipped) or RECONSTRUCTION (bytes built from the
 * documented <winbase.h> layout, for table mechanics and malformed input).
 */
#include "system_hardening_win_parsers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <map>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

using namespace yuzu::system_hardening::mitigation;
namespace fs = std::filesystem;

namespace {

fs::path fixture_path(const std::string& rel) {
    return fs::path{YUZU_TEST_FIXTURE_DIR} / "wave8" / "system_hardening" / "windows" / rel;
}

std::string read_fixture_text(const std::string& rel) {
    const fs::path p = fixture_path(rel);
    REQUIRE(fs::exists(p));
    std::ifstream f(p, std::ios::binary);
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

/// RECONSTRUCTION: a little-endian blob of `size` zero bytes with the given
/// (nibble index, nibble value) pairs set in the first QWORD.
std::vector<uint8_t> make_blob(std::size_t size,
                               std::initializer_list<std::pair<unsigned, unsigned>> nibbles) {
    std::vector<uint8_t> b(size, 0);
    for (const auto& [idx, val] : nibbles)
        b[idx / 2] = static_cast<uint8_t>(b[idx / 2] | ((val & 0xF) << (4 * (idx % 2))));
    return b;
}

std::map<std::string, MitigationRow> by_policy(const std::vector<MitigationRow>& rows) {
    std::map<std::string, MitigationRow> m;
    for (const auto& r : rows)
        m.emplace(r.policy, r);
    return m;
}

std::vector<MitigationRow> decode_ok(const std::vector<uint8_t>& blob,
                                     std::string_view prefix = "mitigation.") {
    auto r = decode_mitigation_options(blob, prefix);
    REQUIRE(r.has_value());
    return *r;
}

} // namespace

TEST_CASE("decode: every two-bit nibble value maps 0/1/2/3 to default/on/off/unmodelled",
          "[system_hardening][win_parsers]") {
    // RECONSTRUCTION; drives kPolicyTable itself.
    for (const auto& def : detail::kPolicyTable) {
        if (def.kind != detail::Kind::two_bit)
            continue;
        const std::pair<unsigned, PolicyState> cases[] = {{0, PolicyState::default_state},
                                                          {1, PolicyState::on},
                                                          {2, PolicyState::off},
                                                          {3, PolicyState::unmodelled}};
        for (const auto& [nib, want] : cases) {
            const auto rows = by_policy(decode_ok(make_blob(16, {{def.nibble, nib}})));
            const auto it = rows.find("mitigation." + std::string{def.name});
            REQUIRE(it != rows.end());
            INFO(def.name << " nibble=" << nib);
            CHECK(it->second.state == want);
            CHECK(it->second.raw == "0x" + std::string(1, "0123"[nib]));
            // No other table policy moves.
            for (const auto& [name, row] : rows) {
                if (name != it->first && row.raw != "0x0" && name.find("ext_q") == std::string::npos)
                    FAIL("unexpected non-default row " << name);
            }
        }
    }
}

TEST_CASE("decode: nibble 0 legacy flags are 1-bit on/default, bit 3 is unmodelled",
          "[system_hardening][win_parsers]") {
    // RECONSTRUCTION.
    auto rows = by_policy(decode_ok(make_blob(16, {{0, 0x1}})));
    CHECK(rows.at("mitigation.dep").state == PolicyState::on);
    CHECK(rows.at("mitigation.dep_atl_thunk").state == PolicyState::default_state);
    CHECK(rows.at("mitigation.sehop").state == PolicyState::default_state);

    rows = by_policy(decode_ok(make_blob(16, {{0, 0x4}})));
    CHECK(rows.at("mitigation.sehop").state == PolicyState::on);
    CHECK(rows.at("mitigation.dep").state == PolicyState::default_state);

    rows = by_policy(decode_ok(make_blob(16, {{0, 0x8}})));
    REQUIRE(rows.count("mitigation.reserved_n0_bit3") == 1);
    CHECK(rows.at("mitigation.reserved_n0_bit3").state == PolicyState::unmodelled);
}

TEST_CASE("decode: prefix is applied, nibble 1 non-zero is reserved/unmodelled",
          "[system_hardening][win_parsers]") {
    // RECONSTRUCTION.
    const auto rows = by_policy(decode_ok(make_blob(16, {{1, 0x2}}), "mitigation_audit."));
    REQUIRE(rows.count("mitigation_audit.reserved_n1") == 1);
    CHECK(rows.at("mitigation_audit.reserved_n1").state == PolicyState::unmodelled);
    CHECK(rows.count("mitigation.dep") == 0);
    CHECK(rows.count("mitigation_audit.dep") == 1);
}

TEST_CASE("decode: QWORDs beyond the documented table are unmodelled when non-zero",
          "[system_hardening][win_parsers]") {
    // RECONSTRUCTION: 24-byte blob, third QWORD non-zero.
    auto blob = make_blob(24, {});
    blob[16] = 0x12;
    const auto rows = by_policy(decode_ok(blob));
    CHECK(rows.at("mitigation.ext_q1").state == PolicyState::default_state);
    CHECK(rows.at("mitigation.ext_q2").state == PolicyState::unmodelled);
    CHECK(rows.at("mitigation.ext_q2").raw == "0x0000000000000012");
    CHECK(by_policy(decode_ok(make_blob(16, {}))).count("mitigation.ext_q2") == 0);
}

TEST_CASE("decode: malformed blobs return a typed error, never a partial decode",
          "[system_hardening][win_parsers]") {
    // RECONSTRUCTION negatives.
    const auto err = [](std::size_t n) {
        auto r = decode_mitigation_options(std::vector<uint8_t>(n, 0), "mitigation.");
        REQUIRE_FALSE(r.has_value());
        return r.error().token;
    };
    CHECK(err(0) == "empty_blob");
    CHECK(err(7) == "odd_length");
    CHECK(err(15) == "odd_length");
    CHECK(err(12) == "not_qword_aligned");
    CHECK(err(kMaxBlobBytes + 8) == "oversized");
    CHECK(decode_mitigation_options(std::vector<uint8_t>(16, 0), "").has_value());
    CHECK(decode_mitigation_options(std::vector<uint8_t>(24, 0), "").has_value());
}

TEST_CASE("self policy: Flags bits map to on/off rows, never default",
          "[system_hardening][win_parsers]") {
    // RECONSTRUCTION: layouts from <winnt.h> PROCESS_MITIGATION_*_POLICY.
    auto dep = decode_self_policy(SelfPolicy::dep, 0x1);
    REQUIRE(dep.size() == 1);
    CHECK(dep[0].policy == "self.dep");
    CHECK(dep[0].state == PolicyState::on);
    CHECK(dep[0].raw == "1");
    CHECK(decode_self_policy(SelfPolicy::dep, 0x2)[0].state == PolicyState::off);

    const auto aslr = by_policy(decode_self_policy(SelfPolicy::aslr, 0x5));
    CHECK(aslr.at("self.aslr_bottom_up").state == PolicyState::on);
    CHECK(aslr.at("self.aslr_force_relocate").state == PolicyState::off);
    CHECK(aslr.at("self.aslr_high_entropy").state == PolicyState::on);

    const auto cfg = by_policy(decode_self_policy(SelfPolicy::cfg, 0x3));
    CHECK(cfg.at("self.cfg").state == PolicyState::on);
    CHECK(cfg.at("self.cfg_export_suppression").state == PolicyState::on);
    CHECK(cfg.at("self.cfg_strict_mode").state == PolicyState::off);
    CHECK(cfg.at("self.cfg").raw == "3");
}

TEST_CASE("hex parsing: bare hex, 0x prefix, reg query line, and malformed input",
          "[system_hardening][win_parsers]") {
    // RECONSTRUCTION of the two accepted spellings + negatives.
    const std::vector<uint8_t> want{0x00, 0x22, 0xAB, 0xff};
    CHECK(*parse_hex_blob("0022abFF\n") == want);
    CHECK(*parse_hex_blob("0x00 22 ab ff") == want);
    CHECK(*parse_hex_blob("\r\nHKEY_LOCAL_MACHINE\\...\\kernel\r\n"
                          "    MitigationOptions    REG_BINARY    0022ABFF\r\n\r\n") == want);
    CHECK(parse_hex_blob("").error().token == "no_hex_digits");
    CHECK(parse_hex_blob("   \n").error().token == "no_hex_digits");
    CHECK(parse_hex_blob("002").error().token == "odd_hex_digits");
    CHECK(parse_hex_blob("00zz").error().token == "bad_hex");
}

TEST_CASE("row format: posture|windows|<policy>|<raw>|<state>", "[system_hardening][win_parsers]") {
    CHECK(format_posture_row(MitigationRow{"mitigation.cfg", "0x1", PolicyState::on}) ==
          "posture|windows|mitigation.cfg|0x1|on");
    CHECK(format_posture_row("mitigation_options", "-", "absent") ==
          "posture|windows|mitigation_options|-|absent");
}

TEST_CASE("REAL CAPTURE: decoded DEP/ASLR/CFG match Get-ProcessMitigation -System",
          "[system_hardening][win_parsers][fixture]") {
    // REAL CAPTURE from the-rig. The provenance file records the ground truth
    // as `expect.<short policy>=<on|off|default>` lines (Get-ProcessMitigation
    // -System: ON -> on, OFF -> off, NOTSET -> default).
    const auto blob = parse_hex_blob(read_fixture_text("mitigation_options.hex"));
    REQUIRE(blob.has_value());
    const auto rows = decode_ok(*blob);
    const auto decoded = by_policy(rows);

    std::map<std::string, std::string> expect;
    {
        std::istringstream in(read_fixture_text("mitigation_options.hex.provenance.txt"));
        std::string line;
        while (std::getline(in, line)) {
            if (!line.empty() && line.back() == '\r')
                line.pop_back();
            constexpr std::string_view kTag = "expect.";
            if (line.rfind(kTag, 0) != 0)
                continue;
            const auto eq = line.find('=');
            REQUIRE(eq != std::string::npos);
            expect[line.substr(kTag.size(), eq - kTag.size())] = line.substr(eq + 1);
        }
    }
    // The three headline policies must be asserted -- an unpopulated
    // provenance file is a failed capture, not a vacuous pass.
    for (const char* required : {"dep", "aslr_bottom_up", "cfg"})
        REQUIRE(expect.count(required) == 1);

    for (const auto& [name, state] : expect) {
        const auto it = decoded.find("mitigation." + name);
        INFO("policy " << name);
        REQUIRE(it != decoded.end());
        CHECK(std::string{state_token(it->second.state)} == state);
    }
}
