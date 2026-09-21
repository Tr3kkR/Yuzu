/**
 * test_system_hardening_parsers.cpp -- pure coverage of
 * agents/plugins/system_hardening/src/system_hardening_parsers.hpp.
 *
 * No platform guard: the header is OS-free, and the readers are INJECTED, so
 * nothing here opens /proc, calls sysctlbyname or spawns anything. Fixtures
 * (tests/unit/fixtures/wave8/system_hardening/, each with a .provenance.txt):
 *   linux/proc_sys_{debian12,fedora40}.txt  REAL CAPTURE (docker containers)
 *   macos/sysctl_posture_macos26.txt        REAL CAPTURE (this Mac)
 *   linux/proc_sys_malformed.txt            RECONSTRUCTION (malformed values)
 * Line shape: <key>\t<ok|err>\t<value or the tool's error text>.
 */
#include <catch2/catch_test_macros.hpp>

#include "system_hardening_parsers.hpp"

#include <cerrno>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

using namespace yuzu::system_hardening;
namespace fs = std::filesystem;
using yuzu::shared::ConstraintAccumulator;

namespace {

struct FixtureLine {
    bool ok;
    std::string text;
};

std::map<std::string, FixtureLine> load_fixture(const char* sub, const char* name) {
    const fs::path p = fs::path{YUZU_TEST_FIXTURE_DIR} / "wave8" / "system_hardening" / sub / name;
    std::ifstream f(p);
    REQUIRE(f.is_open()); // a missing fixture is a broken tree, never a skip
    std::map<std::string, FixtureLine> out;
    std::string line;
    while (std::getline(f, line)) {
        const auto t1 = line.find('\t');
        const auto t2 = line.find('\t', t1 + 1);
        REQUIRE(t1 != std::string::npos);
        REQUIRE(t2 != std::string::npos);
        out[line.substr(0, t1)] = {line.substr(t1 + 1, t2 - t1 - 1) == "ok", line.substr(t2 + 1)};
    }
    return out;
}

// The errno a captured tool error text stands for. Only the causes present in
// the captures (plus the two permission phrases) are recognised.
int errno_of(const std::string& text) {
    if (text.find("No such file or directory") != std::string::npos ||
        text.find("unknown oid") != std::string::npos)
        return ENOENT;
    if (text.find("Permission denied") != std::string::npos) return EACCES;
    if (text.find("Operation not permitted") != std::string::npos) return EPERM;
    return EIO;
}

ReadOutcome outcome_of(const FixtureLine& l) {
    return l.ok ? ReadOutcome{0, 0, l.text} : ReadOutcome{errno_of(l.text), 0, {}};
}

/// Linux reader over a fixture; a key the fixture does not mention is ENOENT.
auto linux_reader_over(std::map<std::string, FixtureLine> fx) {
    return [fx = std::move(fx)](std::string_view path) -> ReadOutcome {
        for (const auto& k : kLinuxAllowlist)
            if (k.path == path) {
                const auto it = fx.find(std::string{k.key});
                return it == fx.end() ? ReadOutcome{ENOENT, 0, {}} : outcome_of(it->second);
            }
        return {ENOENT, 0, {}};
    };
}

PostureState state_of(const std::vector<PostureRow>& rows, std::string_view key) {
    for (const auto& r : rows)
        if (r.key == key) return r.state;
    FAIL("no row for " << key);
    return PostureState::unmodelled;
}

std::string raw_of(const std::vector<PostureRow>& rows, std::string_view key) {
    for (const auto& r : rows)
        if (r.key == key) return r.raw;
    return "<missing>";
}

} // namespace

// ── allowlists ───────────────────────────────────────────────────────────

TEST_CASE("system_hardening: the Linux allowlist is exactly the specified 11 keys, path derived from key",
          "[system_hardening][allowlist]") {
    const std::vector<std::string_view> expected{
        "kernel.randomize_va_space", "kernel.kptr_restrict", "kernel.yama.ptrace_scope",
        "kernel.dmesg_restrict",     "kernel.unprivileged_bpf_disabled", "kernel.sysrq",
        "fs.protected_hardlinks",    "fs.protected_symlinks", "fs.protected_fifos",
        "fs.protected_regular",      "fs.suid_dumpable"};
    REQUIRE(kLinuxAllowlist.size() == expected.size());
    for (std::size_t i = 0; i < expected.size(); ++i) {
        CHECK(kLinuxAllowlist[i].key == expected[i]);
        std::string want = "/proc/sys/" + std::string{expected[i]};
        for (auto& c : want)
            if (c == '.') c = '/';
        CHECK(std::string{kLinuxAllowlist[i].path} == want);
        CHECK_FALSE(kLinuxAllowlist[i].rules.empty()); // every key has a value mapping
    }
}

TEST_CASE("system_hardening: the macOS allowlist has 4 keys, kern.nx removed, only bootargs is a string",
          "[system_hardening][allowlist]") {
    REQUIRE(kMacosAllowlist.size() == 4);
    for (const auto& k : kMacosAllowlist) {
        CHECK(k.name != "kern.nx");
        CHECK((k.kind == SysctlKind::string) == (k.name == "kern.bootargs"));
    }
    CHECK(kMacosAllowlist[0].name == "kern.securelevel");
    CHECK(kMacosAllowlist[3].name == "kern.bootargs");
}

// ── errno classification ─────────────────────────────────────────────────

TEST_CASE("system_hardening: only ENOENT is absent; every other errno is unreadable",
          "[system_hardening][errno]") {
    CHECK(classify_read_errno(ENOENT) == PostureState::absent);
    CHECK(classify_read_errno(EACCES) == PostureState::unreadable);
    CHECK(classify_read_errno(EPERM) == PostureState::unreadable);
    CHECK(classify_read_errno(EIO) == PostureState::unreadable);
    CHECK(classify_read_errno(EINVAL) == PostureState::unreadable);
}

TEST_CASE("system_hardening: ENOENT / EACCES(EPERM) / other errno carry distinct reason tokens",
          "[system_hardening][errno]") {
    CHECK(failure_token("k", ENOENT) == "k:enoent");
    CHECK(failure_token("k", EACCES) == "k:eacces");
    CHECK(failure_token("k", EPERM) == "k:eacces");
    CHECK(failure_token("k", EIO) == "k:errno_" + std::to_string(EIO));
    CHECK(failure_token("k", EIO) != failure_token("k", ENOENT));
}

// ── mappers ──────────────────────────────────────────────────────────────

TEST_CASE("system_hardening: evaluate_linux maps every allowlisted key's documented values",
          "[system_hardening][mapper]") {
    struct C { const char* key; const char* raw; PostureState want; };
    using P = PostureState;
    const C cases[] = {
        {"kernel.randomize_va_space", "0\n", P::disabled}, {"kernel.randomize_va_space", "1", P::partial},
        {"kernel.randomize_va_space", "2\n", P::enabled},
        {"kernel.kptr_restrict", "0", P::disabled}, {"kernel.kptr_restrict", "1", P::partial},
        {"kernel.kptr_restrict", "2", P::enabled},
        {"kernel.yama.ptrace_scope", "0", P::disabled}, {"kernel.yama.ptrace_scope", "1", P::enabled},
        {"kernel.yama.ptrace_scope", "3", P::enabled},
        {"kernel.dmesg_restrict", "0", P::disabled}, {"kernel.dmesg_restrict", "1", P::enabled},
        {"kernel.unprivileged_bpf_disabled", "0", P::disabled},
        {"kernel.unprivileged_bpf_disabled", "1", P::enabled},
        {"kernel.unprivileged_bpf_disabled", "2", P::enabled},
        {"kernel.sysrq", "0", P::enabled}, {"kernel.sysrq", "1", P::disabled},
        {"kernel.sysrq", "176", P::partial}, {"kernel.sysrq", "511", P::partial},
        {"fs.protected_hardlinks", "0", P::disabled}, {"fs.protected_hardlinks", "1", P::enabled},
        {"fs.protected_symlinks", "1", P::enabled},
        {"fs.protected_fifos", "0", P::disabled}, {"fs.protected_fifos", "1", P::partial},
        {"fs.protected_fifos", "2", P::enabled},
        {"fs.protected_regular", "2", P::enabled},
        {"fs.suid_dumpable", "0", P::enabled}, {"fs.suid_dumpable", "1", P::disabled},
        {"fs.suid_dumpable", "2", P::partial},
    };
    for (const auto& c : cases) {
        INFO(c.key << " = " << c.raw);
        CHECK(evaluate_linux(c.key, c.raw) == c.want);
    }
}

TEST_CASE("system_hardening: evaluate_linux returns unmodelled, never a guess, for unmapped input",
          "[system_hardening][mapper]") {
    for (const char* raw : {"", "\n", "banana", "3", "-1", "1.5", "0x2", "+1", "99999999999999999999999"})
        CHECK(evaluate_linux("kernel.randomize_va_space", raw) == PostureState::unmodelled);
    CHECK(evaluate_linux("kernel.sysrq", "512") == PostureState::unmodelled);
    CHECK(evaluate_linux("kernel.not_allowlisted", "1") == PostureState::unmodelled);
}

TEST_CASE("system_hardening: evaluate_macos_int / evaluate_macos_string", "[system_hardening][mapper]") {
    using P = PostureState;
    CHECK(evaluate_macos_int("kern.securelevel", -1) == P::disabled);
    CHECK(evaluate_macos_int("kern.securelevel", 0) == P::disabled);
    CHECK(evaluate_macos_int("kern.securelevel", 1) == P::partial);
    CHECK(evaluate_macos_int("kern.securelevel", 2) == P::enabled);
    CHECK(evaluate_macos_int("kern.securelevel", 3) == P::unmodelled);
    CHECK(evaluate_macos_int("kern.coredump", 0) == P::enabled);
    CHECK(evaluate_macos_int("kern.coredump", 1) == P::disabled);
    CHECK(evaluate_macos_int("kern.sugid_coredump", 0) == P::enabled);
    CHECK(evaluate_macos_int("kern.sugid_coredump", 2) == P::unmodelled);
    CHECK(evaluate_macos_int("kern.bootargs", 0) == P::unmodelled); // a string key, not an int
    CHECK(evaluate_macos_int("kern.nx", 1) == P::unmodelled);
    // The empty-bootargs contract: an empty value is a successful read, defined `enabled`.
    CHECK(evaluate_macos_string("kern.bootargs", "") == P::enabled);
    CHECK(evaluate_macos_string("kern.bootargs", " \n") == P::enabled);
    CHECK(evaluate_macos_string("kern.bootargs", "-v debug=0x144") == P::unmodelled);
    CHECK(evaluate_macos_string("kern.securelevel", "") == P::unmodelled);
}

// ── row formatting ───────────────────────────────────────────────────────

TEST_CASE("system_hardening: format_posture_row is posture|os|key|raw|state and escapes raw",
          "[system_hardening][row]") {
    CHECK(format_posture_row({"linux", "kernel.kptr_restrict", "1", PostureState::partial}) ==
          "posture|linux|kernel.kptr_restrict|1|partial");
    CHECK(format_posture_row({"linux", "k", "-", PostureState::absent}) == "posture|linux|k|-|absent");
    // OS-supplied raw text is untrusted: a pipe must not add a field.
    CHECK(format_posture_row({"macos", "kern.bootargs", "a|b", PostureState::unmodelled}) ==
          "posture|macos|kern.bootargs|a\\|b|unmodelled");
    for (const auto s : {PostureState::enabled, PostureState::disabled, PostureState::partial,
                         PostureState::unmodelled, PostureState::absent, PostureState::unreadable}) {
        bool found = false;
        for (const auto t : kStateTokens) found = found || t == state_token(s);
        CHECK(found);
    }
}

// ── collect loops through the injected reader ───────────────────────────

TEST_CASE("system_hardening: ENOENT, EACCES and a successful read give three distinct rows and tokens",
          "[system_hardening][collect]") {
    // kernel.randomize_va_space: value; kptr_restrict: EACCES; yama: ENOENT;
    // dmesg_restrict: EPERM; sysrq: EIO; everything else: value "1".
    auto reader = [](std::string_view path) -> ReadOutcome {
        if (path == "/proc/sys/kernel/kptr_restrict") return {EACCES, 0, {}};
        if (path == "/proc/sys/kernel/yama/ptrace_scope") return {ENOENT, 0, {}};
        if (path == "/proc/sys/kernel/dmesg_restrict") return {EPERM, 0, {}};
        if (path == "/proc/sys/kernel/sysrq") return {EIO, 0, {}};
        if (path == "/proc/sys/kernel/randomize_va_space") return {0, 0, "2\n"};
        return {0, 0, "1\n"};
    };
    ConstraintAccumulator acc;
    const auto rows = collect_linux_posture(reader, acc);
    REQUIRE(rows.size() == kLinuxAllowlist.size());
    CHECK(state_of(rows, "kernel.randomize_va_space") == PostureState::enabled);
    CHECK(raw_of(rows, "kernel.randomize_va_space") == "2");
    CHECK(state_of(rows, "kernel.kptr_restrict") == PostureState::unreadable);
    CHECK(state_of(rows, "kernel.yama.ptrace_scope") == PostureState::absent);
    CHECK(state_of(rows, "kernel.dmesg_restrict") == PostureState::unreadable);
    CHECK(state_of(rows, "kernel.sysrq") == PostureState::unreadable);
    CHECK(raw_of(rows, "kernel.yama.ptrace_scope") == "-");
    CHECK(acc.any_failure());
    CHECK(acc.reason() == "kernel.kptr_restrict:eacces,kernel.yama.ptrace_scope:enoent,"
                          "kernel.dmesg_restrict:eacces,kernel.sysrq:errno_" + std::to_string(EIO));
}

TEST_CASE("system_hardening: a later successful read never erases an earlier failure",
          "[system_hardening][collect]") {
    auto reader = [](std::string_view path) -> ReadOutcome {
        if (path == "/proc/sys/kernel/randomize_va_space") return {ENOENT, 0, {}}; // FIRST key fails
        return {0, 0, "1\n"};
    };
    ConstraintAccumulator acc;
    const auto rows = collect_linux_posture(reader, acc);
    REQUIRE(rows.size() == kLinuxAllowlist.size());
    CHECK(acc.reason() == "kernel.randomize_va_space:enoent");
}

TEST_CASE("system_hardening: an all-values Linux read adds no failure token and stays in allowlist order",
          "[system_hardening][collect]") {
    ConstraintAccumulator acc;
    const auto rows = collect_linux_posture([](std::string_view) { return ReadOutcome{0, 0, "1\n"}; }, acc);
    REQUIRE(rows.size() == kLinuxAllowlist.size());
    CHECK_FALSE(acc.any_failure());
    for (std::size_t i = 0; i < rows.size(); ++i) CHECK(rows[i].key == kLinuxAllowlist[i].key);
}

TEST_CASE("system_hardening: macOS collect classifies ENOENT/EPERM and treats empty bootargs as a value",
          "[system_hardening][collect]") {
    auto reader = [](std::string_view name, SysctlKind kind) -> ReadOutcome {
        if (name == "kern.securelevel") return {ENOENT, 0, {}};
        if (name == "kern.coredump") return {EPERM, 0, {}};
        if (kind == SysctlKind::string) return {0, 0, std::string{}}; // empty bootargs: success
        return {0, 1, {}};
    };
    ConstraintAccumulator acc;
    const auto rows = collect_macos_posture(reader, acc);
    REQUIRE(rows.size() == kMacosAllowlist.size());
    CHECK(state_of(rows, "kern.securelevel") == PostureState::absent);
    CHECK(state_of(rows, "kern.coredump") == PostureState::unreadable);
    CHECK(state_of(rows, "kern.sugid_coredump") == PostureState::disabled);
    CHECK(state_of(rows, "kern.bootargs") == PostureState::enabled);
    CHECK(raw_of(rows, "kern.bootargs").empty()); // read-and-empty, not "-"
    CHECK(acc.reason() == "kern.securelevel:enoent,kern.coredump:eacces"); // bootargs adds nothing
}

// ── REAL CAPTURE fixtures ────────────────────────────────────────────────

TEST_CASE("system_hardening: REAL CAPTURE docker debian:12 and fedora:40 /proc/sys reads",
          "[system_hardening][fixture]") {
    for (const char* name : {"proc_sys_debian12.txt", "proc_sys_fedora40.txt"}) {
        INFO(name);
        ConstraintAccumulator acc;
        const auto rows = collect_linux_posture(linux_reader_over(load_fixture("linux", name)), acc);
        REQUIRE(rows.size() == kLinuxAllowlist.size());
        using P = PostureState;
        CHECK(state_of(rows, "kernel.randomize_va_space") == P::enabled);
        CHECK(state_of(rows, "kernel.kptr_restrict") == P::disabled);
        CHECK(state_of(rows, "kernel.dmesg_restrict") == P::enabled);
        CHECK(state_of(rows, "kernel.unprivileged_bpf_disabled") == P::disabled);
        CHECK(state_of(rows, "kernel.sysrq") == P::disabled); // value 1
        CHECK(state_of(rows, "fs.protected_hardlinks") == P::enabled);
        CHECK(state_of(rows, "fs.protected_fifos") == P::disabled);
        CHECK(state_of(rows, "fs.suid_dumpable") == P::enabled);
        // Yama is genuinely not built into this kernel: the real ENOENT case.
        CHECK(state_of(rows, "kernel.yama.ptrace_scope") == P::absent);
        CHECK(acc.reason() == "kernel.yama.ptrace_scope:enoent"); // exactly one failure, by design
    }
}

TEST_CASE("system_hardening: REAL CAPTURE this Mac's sysctl reads (empty bootargs, kern.nx unknown oid)",
          "[system_hardening][fixture]") {
    const auto fx = load_fixture("macos", "sysctl_posture_macos26.txt");
    auto reader = [&](std::string_view name, SysctlKind kind) -> ReadOutcome {
        const auto it = fx.find(std::string{name});
        if (it == fx.end()) return {ENOENT, 0, {}};
        if (!it->second.ok) return {errno_of(it->second.text), 0, {}};
        if (kind == SysctlKind::integer) return {0, std::stoll(it->second.text), {}};
        return {0, 0, it->second.text};
    };
    ConstraintAccumulator acc;
    const auto rows = collect_macos_posture(reader, acc);
    REQUIRE(rows.size() == kMacosAllowlist.size());
    CHECK(state_of(rows, "kern.securelevel") == PostureState::disabled); // 0
    CHECK(state_of(rows, "kern.coredump") == PostureState::disabled);    // 1
    CHECK(state_of(rows, "kern.sugid_coredump") == PostureState::enabled); // 0
    CHECK(state_of(rows, "kern.bootargs") == PostureState::enabled);     // empty string, a real read
    CHECK_FALSE(acc.any_failure()); // an empty bootargs is not a failure
    // The captured `sysctl: unknown oid 'kern.nx'` is ENOENT -> absent (kern.nx is why it was dropped).
    const auto nx = fx.at("kern.nx");
    REQUIRE_FALSE(nx.ok);
    CHECK(classify_read_errno(errno_of(nx.text)) == PostureState::absent);
    CHECK(failure_token("kern.nx", errno_of(nx.text)) == "kern.nx:enoent");
}

TEST_CASE("system_hardening: RECONSTRUCTION malformed values map to unmodelled, never a guess",
          "[system_hardening][fixture]") {
    ConstraintAccumulator acc;
    const auto rows =
        collect_linux_posture(linux_reader_over(load_fixture("linux", "proc_sys_malformed.txt")), acc);
    REQUIRE(rows.size() == kLinuxAllowlist.size());
    CHECK(state_of(rows, "kernel.randomize_va_space") == PostureState::unmodelled); // "banana"
    CHECK(state_of(rows, "kernel.kptr_restrict") == PostureState::unmodelled);      // 7
    CHECK(state_of(rows, "kernel.sysrq") == PostureState::unmodelled);              // empty file
    CHECK(state_of(rows, "fs.protected_fifos") == PostureState::unmodelled);        // overflow
    CHECK(raw_of(rows, "kernel.randomize_va_space") == "banana"); // the raw is still reported
}
