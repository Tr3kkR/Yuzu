/**
 * firewall_plugin.cpp — Firewall status and rules plugin for Yuzu
 *
 * Actions:
 *   "state" — Return firewall state per profile/backend.
 *   "rules" — List firewall rules (summary).
 *
 * Output is pipe-delimited via write_output().
 *
 * Acquisition ladder (ADR-3002):
 *   Windows — rung 1, native INetFwPolicy2 COM (agents/shared/win_com.hpp),
 *             replacing both former `netsh` shell-outs.
 *   macOS   — rung 2, run_bounded_subprocess argv (socketfilterfw/pfctl) —
 *             same 3 sites as before, only the acquisition mechanism
 *             changed (popen -> bounded runner); the pure parsers in
 *             firewall_parsers.hpp are untouched.
 *   Linux   — backend probe order: firewalld -> nftables -> ufw -> iptables
 *             -> none.
 *               firewalld: rung 1, bounded sd-bus (org.fedoraproject.
 *                 FirewallD1), mirroring guardian_state_reader.cpp's
 *                 timeout-budget-re-arm pattern across sequential calls.
 *               nftables:  rung 1, bounded NETLINK_NETFILTER (no libnftnl/
 *                 libmnl dependency — neither is a vcpkg dependency today,
 *                 see PR notes). Read-only table/chain/rule enumeration via
 *                 NLM_F_DUMP requests, deadline-bounded like every other
 *                 backend probe here; a mutating nftables leg is explicitly
 *                 out of scope (ADR-3002 Decision 8). Pure decode lives in
 *                 firewall_parsers.hpp's nft_raw namespace / parse_nft_*.
 *               ufw / iptables: rung 2, run_bounded_subprocess argv, each
 *                 backend now emitting STRUCTURED rows via its own pure
 *                 parser (parse_ufw_rules / parse_iptables_save) — replacing
 *                 the old single opaque `firewall-cmd --list-all || ufw
 *                 status numbered || iptables -L -n --line-numbers` shell
 *                 chain and its `rule|<raw line>` passthrough.
 */

#include <yuzu/plugin.hpp>

#include "firewall_parsers.hpp"

#include <yuzu/agent/subprocess_runner.hpp>

#include <chrono>
#include <format>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <netfw.h>
#include <oleauto.h> // SysAllocString / SysFreeString / VARIANT

#include <win_com.hpp> // ComInit / ComPtr<T> / BStr (PR3.3-a shared header)
#include <win_str.hpp> // yuzu::win::from_wide
#endif

#if defined(__linux__) && defined(YUZU_HAVE_LIBSYSTEMD)
#include <systemd/sd-bus.h>
#endif

#if defined(__linux__)
#include <yuzu/agent/scoped_fd.hpp>

#include <linux/netfilter/nfnetlink.h>
#include <linux/netlink.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace {

using yuzu::agent::run_bounded_subprocess;
using yuzu::agent::SubprocessOptions;

constexpr std::chrono::milliseconds kAcqDeadline{5000};

// Strip pipe/newline/CR from a value echoed back into the pipe-delimited
// protocol so a hostile/unusual firewall-rule name cannot inject synthetic
// fields or rows. Platform-agnostic (mirrors rdp_control_plugin.cpp's
// sanitize_field).
std::string sanitize_field(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        out += (c == '|' || c == '\n' || c == '\r') ? '_' : c;
    }
    return out;
}

#ifdef _WIN32

using yuzu::shared::win::ComInit;
using yuzu::shared::win::ComPtr;

/// Acquire INetFwPolicy2 into an owning ComPtr (only inside a live ComInit).
/// Mirrored from rdp_control_plugin.cpp's get_fw_policy() — same
/// CoCreateInstance(__uuidof(NetFwPolicy2), ...) shape, no hnetcfg.lib.
HRESULT get_fw_policy(ComPtr<INetFwPolicy2>& policy) {
    return CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER,
                            __uuidof(INetFwPolicy2), reinterpret_cast<void**>(policy.put()));
}

// CRITICAL (mirrored from rdp_control_plugin.cpp's classify_fw_hr and its
// governing comment): INetFwPolicy2::get_FirewallEnabled and the
// INetFwRules enumeration both follow the same Windows Firewall COM
// contract — S_FALSE PASSES SUCCEEDED() but means "not found" / "no more
// items", NOT success. A naive `if (SUCCEEDED(hr))` here would report an
// unreadable profile as enabled (a fail-safe inversion identical to H2 in
// rdp_control_plugin.cpp). S_OK alone is success; S_FALSE is "not found"
// (report unknown, never a false enabled/disabled); anything else is an
// error. The regression test for this exact bug class lives in
// test_firewall_parsers.cpp / test_new_plugins.cpp's mirrored copy.
enum class FwHrResult { Ok, NotFound, Error };
FwHrResult classify_fw_hr(HRESULT hr) {
    if (hr == S_OK)
        return FwHrResult::Ok;
    if (hr == S_FALSE)
        return FwHrResult::NotFound;
    return FwHrResult::Error;
}

const char* profile_name(NET_FW_PROFILE_TYPE2 p) {
    switch (p) {
    case NET_FW_PROFILE2_DOMAIN:
        return "Domain";
    case NET_FW_PROFILE2_PRIVATE:
        return "Private";
    case NET_FW_PROFILE2_PUBLIC:
        return "Public";
    default:
        return "Unknown";
    }
}

void do_state_windows(yuzu::CommandContext& ctx) {
    ComInit com;
    if (!com.ok()) {
        ctx.write_output("error|com_init");
        return;
    }
    ComPtr<INetFwPolicy2> policy;
    HRESULT hr = get_fw_policy(policy);
    if (FAILED(hr)) {
        ctx.write_output(std::format("error|policy2_create:0x{:08x}", static_cast<uint32_t>(hr)));
        return;
    }
    static constexpr NET_FW_PROFILE_TYPE2 kProfiles[] = {
        NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC};
    for (auto profile : kProfiles) {
        VARIANT_BOOL enabled = VARIANT_FALSE;
        HRESULT phr = policy->get_FirewallEnabled(profile, &enabled);
        switch (classify_fw_hr(phr)) {
        case FwHrResult::Ok:
            ctx.write_output(std::format("profile|{}|{}", profile_name(profile),
                                         enabled != VARIANT_FALSE ? "enabled" : "disabled"));
            break;
        case FwHrResult::NotFound:
            // Unreadable — report unknown, never a false-safe "disabled"
            // (same fail-safe direction as the CRITICAL note above).
            ctx.write_output(std::format("profile|{}|unknown", profile_name(profile)));
            break;
        case FwHrResult::Error:
            ctx.write_output(std::format("profile|{}|error:0x{:08x}", profile_name(profile),
                                         static_cast<uint32_t>(phr)));
            break;
        }
    }
}

void do_rules_windows(yuzu::CommandContext& ctx) {
    ComInit com;
    if (!com.ok()) {
        ctx.write_output("error|com_init");
        return;
    }
    ComPtr<INetFwPolicy2> policy;
    HRESULT hr = get_fw_policy(policy);
    if (FAILED(hr)) {
        ctx.write_output(std::format("error|policy2_create:0x{:08x}", static_cast<uint32_t>(hr)));
        return;
    }
    ComPtr<INetFwRules> rules;
    hr = policy->get_Rules(rules.put());
    if (FAILED(hr)) {
        ctx.write_output(std::format("error|rules_create:0x{:08x}", static_cast<uint32_t>(hr)));
        return;
    }
    ComPtr<IUnknown> enum_unk;
    hr = rules->get__NewEnum(enum_unk.put());
    if (FAILED(hr) || !enum_unk) {
        ctx.write_output(std::format("error|enum_create:0x{:08x}", static_cast<uint32_t>(hr)));
        return;
    }
    ComPtr<IEnumVARIANT> enum_var;
    hr = enum_unk->QueryInterface(__uuidof(IEnumVARIANT),
                                  reinterpret_cast<void**>(enum_var.put()));
    if (FAILED(hr) || !enum_var) {
        ctx.write_output(std::format("error|enum_variant:0x{:08x}", static_cast<uint32_t>(hr)));
        return;
    }

    int count = 0;
    bool truncated = false;
    for (;;) {
        VARIANT v;
        VariantInit(&v);
        ULONG fetched = 0;
        // Same S_FALSE-is-not-success contract as classify_fw_hr above:
        // IEnumVARIANT::Next returns S_FALSE (SUCCEEDED, fetched==0) at
        // end-of-enumeration — checked via `fetched == 0`, never a bare
        // SUCCEEDED(hr), so end-of-list is never mistaken for "another rule".
        hr = enum_var->Next(1, &v, &fetched);
        if (FAILED(hr) || fetched == 0) {
            VariantClear(&v);
            break;
        }
        // The cap check happens AFTER a successful fetch, not before: at
        // exactly 100 already-emitted rules, this proves a genuine 101st
        // rule exists (Next() actually returned one) before declaring
        // truncation — checking `count >= 100` up front (the original
        // shape) set truncated|true on a host with EXACTLY 100 rules,
        // none of them actually cut off, because it never called Next()
        // again to find out (governance Gate 4 happy-path finding).
        if (count >= 100) {
            VariantClear(&v);
            truncated = true;
            break;
        }
        if (v.vt != VT_DISPATCH || !v.pdispVal) {
            VariantClear(&v);
            continue;
        }
        ComPtr<INetFwRule> rule;
        HRESULT qhr = v.pdispVal->QueryInterface(__uuidof(INetFwRule),
                                                 reinterpret_cast<void**>(rule.put()));
        VariantClear(&v);
        if (FAILED(qhr) || !rule)
            continue;

        // RAII over the raw BSTR out-param: the shared win_com.hpp BStr type
        // only constructs by ALLOCATING a new BSTR, so it can't adopt one
        // already returned by a COM out-param without an ambiguous overload
        // (BSTR is literally wchar_t*). A manual SysFreeString here would
        // leak on any exception thrown between receipt and free (e.g.
        // std::wstring's allocation) -- unconditional release in the
        // destructor closes that gap.
        struct RuleNameBstr {
            BSTR b = nullptr;
            ~RuleNameBstr() {
                if (b)
                    SysFreeString(b);
            }
            // A user-declared (even deleted) copy constructor suppresses
            // the implicitly-declared default constructor entirely --
            // without this, `} name_bstr;` below fails to compile.
            // Confirmed with a standalone repro (see BusGuard's identical
            // comment further down this file).
            RuleNameBstr() = default;
            RuleNameBstr(const RuleNameBstr&) = delete;
            RuleNameBstr& operator=(const RuleNameBstr&) = delete;
        } name_bstr;
        rule->get_Name(&name_bstr.b);
        std::wstring name_w = name_bstr.b ? name_bstr.b : L"";

        VARIANT_BOOL enabled = VARIANT_FALSE;
        rule->get_Enabled(&enabled);

        // Direction/Action are read as explicitly failure-checked (rather
        // than relying on a sentinel initial value that "happens" not to
        // collide with a real enumerator) so an unreadable field reports
        // honestly as unknown regardless of the underlying enum's numbering.
        NET_FW_RULE_DIRECTION dir{};
        HRESULT dir_hr = rule->get_Direction(&dir);
        std::string dir_s = FAILED(dir_hr)          ? "unknown"
                            : (dir == NET_FW_RULE_DIR_IN)  ? "in"
                            : (dir == NET_FW_RULE_DIR_OUT) ? "out"
                                                            : "unknown";

        NET_FW_ACTION action{};
        HRESULT action_hr = rule->get_Action(&action);
        std::string action_s = FAILED(action_hr)            ? "unknown"
                               : (action == NET_FW_ACTION_ALLOW) ? "allow"
                               : (action == NET_FW_ACTION_BLOCK) ? "block"
                                                                  : "unknown";

        long profiles_mask = 0;
        rule->get_Profiles(&profiles_mask);

        std::string name = sanitize_field(yuzu::win::from_wide(name_w.c_str()));

        ctx.write_output(std::format("rule|{}|{}|{}|{}|{}", name,
                                     enabled != VARIANT_FALSE ? "enabled" : "disabled", dir_s,
                                     action_s, profiles_mask));
        ++count;
    }
    if (truncated)
        ctx.write_output("truncated|true");
}

#elif defined(__APPLE__)

void do_state_macos(yuzu::CommandContext& ctx) {
    // Primary: the macOS Application Firewall — the firewall a Mac admin
    // means. pf is off by default and unrelated, so reporting it as THE
    // state gave false confidence. Unprivileged read.
    auto alf_res = run_bounded_subprocess(
        {"/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"},
        SubprocessOptions{.deadline = kAcqDeadline});
    auto alf = yuzu::firewall::parse_alf_global_state(alf_res.output);
    ctx.write_output("backend|appfirewall");
    ctx.write_output(std::format("state|{}", yuzu::firewall::to_string(alf.state)));
    if (alf.block_all) {
        ctx.write_output("mode|block_all");
    }
    // Secondary: the pf packet filter (reading /dev/pf needs root;
    // unreadable reports as unknown, never a false-safe value). Absolute
    // path per the quarantine plugin's kPfctl discipline.
    auto pf_res =
        run_bounded_subprocess({"/sbin/pfctl", "-s", "info"}, SubprocessOptions{.deadline = kAcqDeadline});
    ctx.write_output(std::format(
        "pf|{}", yuzu::firewall::to_string(yuzu::firewall::parse_pf_status(pf_res.output))));
}

void do_rules_macos(yuzu::CommandContext& ctx) {
    auto res = run_bounded_subprocess({"/sbin/pfctl", "-s", "rules"},
                                      SubprocessOptions{.deadline = kAcqDeadline});
    std::istringstream iss(res.output);
    std::string line;
    while (std::getline(iss, line)) {
        if (!line.empty()) {
            ctx.write_output(std::format("rule|{}", line));
        }
    }
}

#elif defined(__linux__)

#if defined(YUZU_HAVE_LIBSYSTEMD)

// ── firewalld (rung 1, bounded sd-bus) ──────────────────────────────────
//
// RAII guards mirrored from guardian_state_reader.cpp's read_service_blocking
// (same sd_bus_error/sd_bus_message/bus ownership convention).
struct BusGuard {
    sd_bus* bus = nullptr;
    ~BusGuard() {
        if (bus)
            sd_bus_flush_close_unref(bus);
    }
    BusGuard() = default;
    BusGuard(const BusGuard&) = delete;
    BusGuard& operator=(const BusGuard&) = delete;
};
struct SdBusErrorGuard {
    sd_bus_error err = SD_BUS_ERROR_NULL;
    ~SdBusErrorGuard() { sd_bus_error_free(&err); }
    // A user-declared (even deleted) copy constructor suppresses the
    // implicitly-declared default constructor entirely -- without this,
    // `SdBusErrorGuard err;` below fails to compile ("no default
    // constructor"), not merely "uses the deleted one". Confirmed with a
    // standalone repro on this Mac (Linux-only code, never actually
    // compiled anywhere else in this branch's history).
    SdBusErrorGuard() = default;
    SdBusErrorGuard(const SdBusErrorGuard&) = delete;
    SdBusErrorGuard& operator=(const SdBusErrorGuard&) = delete;
};
struct SdBusMessageGuard {
    sd_bus_message* m = nullptr;
    ~SdBusMessageGuard() {
        if (m)
            sd_bus_message_unref(m);
    }
    SdBusMessageGuard() = default;
    SdBusMessageGuard(const SdBusMessageGuard&) = delete;
    SdBusMessageGuard& operator=(const SdBusMessageGuard&) = delete;
};

// Total sd-bus budget for the whole read, split across the sequential calls
// below (getActiveZones, then getServices/getPorts per active zone) — same
// re-arm-with-the-remainder shape as guardian_state_reader.cpp's
// kSdBusTotalBudgetUs, so a wedged firewalld cannot hold this call for an
// unbounded multiple of the per-method timeout.
constexpr std::uint64_t kSdBusTotalBudgetUs = 5'000'000; // 5s

constexpr const char* kFirewalldDest = "org.fedoraproject.FirewallD1";
constexpr const char* kFirewalldPath = "/org/fedoraproject/FirewallD1";
constexpr const char* kFirewalldZoneIface = "org.fedoraproject.FirewallD1.zone";

struct FirewalldZoneInfo {
    std::string name;
    std::vector<std::string> services;
};
struct FirewalldQueryResult {
    bool reachable = false; // false -> caller falls through to the next backend
    std::vector<FirewalldZoneInfo> zones;
};

// NOTE: getActiveZones()'s "a{sa{sas}}" signature (zone -> {"interfaces":
// [...], "sources": [...]}) and getServices()'s "as" signature are taken
// from firewalld's published D-Bus API and exercised here via the same
// enter_container/exit_container idiom as guardian_state_reader.cpp — this
// leg has not been verified against a live firewalld (no D-Bus broker
// available in this sandbox; see the PR notes). A signature mismatch fails
// the corresponding enter_container/read call (rc < 0), which this code
// treats as "that field unavailable" rather than a crash or a fabricated
// row — so a wrong guess degrades honestly instead of corrupting output.
// getPorts() is deliberately NOT queried here: its per-element termination
// semantics under a manually-entered outer array could not be verified with
// the same confidence (no live firewalld to test against) and a
// speculative implementation risks a subtly wrong read loop rather than an
// honestly-empty one — service enumeration alone is the higher-confidence
// subset. Tracked as a gap for whoever next touches this leg with access to
// a live firewalld.
FirewalldQueryResult query_firewalld(bool want_rules) {
    FirewalldQueryResult r;
    BusGuard bus;
    if (sd_bus_open_system(&bus.bus) < 0 || !bus.bus)
        return r; // D-Bus unreachable -> honest fall-through, never fabricate

    const auto t_start = std::chrono::steady_clock::now();
    sd_bus_set_method_call_timeout(bus.bus, kSdBusTotalBudgetUs);

    auto remaining_budget = [&]() -> std::uint64_t {
        const auto elapsed_us = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - t_start)
                .count());
        return elapsed_us >= kSdBusTotalBudgetUs ? 0 : kSdBusTotalBudgetUs - elapsed_us;
    };

    SdBusErrorGuard err;
    SdBusMessageGuard reply;
    int rc = sd_bus_call_method(bus.bus, kFirewalldDest, kFirewalldPath, kFirewalldZoneIface,
                                "getActiveZones", &err.err, &reply.m, "");
    if (rc < 0)
        return r; // firewalld not running / not reachable -> fall through
    r.reachable = true;
    if (!want_rules)
        return r;

    if (sd_bus_message_enter_container(reply.m, 'a', "{sa{sas}}") < 0)
        return r;
    while (sd_bus_message_enter_container(reply.m, 'e', "sa{sas}") > 0) {
        FirewalldZoneInfo zone;
        const char* zone_name = nullptr;
        sd_bus_message_read(reply.m, "s", &zone_name);
        if (zone_name)
            zone.name = zone_name;
        // interfaces/sources sub-dict — not consumed today; step over it so
        // the message cursor lands correctly for the next zone entry.
        if (sd_bus_message_enter_container(reply.m, 'a', "{sas}") >= 0) {
            while (sd_bus_message_enter_container(reply.m, 'e', "sas") > 0) {
                sd_bus_message_skip(reply.m, "s");
                sd_bus_message_skip(reply.m, "as");
                sd_bus_message_exit_container(reply.m);
            }
            sd_bus_message_exit_container(reply.m);
        }
        sd_bus_message_exit_container(reply.m); // exit this zone's dict-entry
        if (!zone.name.empty())
            r.zones.push_back(std::move(zone));
    }
    sd_bus_message_exit_container(reply.m);

    // Per-zone getServices, each re-arming against the remaining budget —
    // bail out (report what we have so far) once it's exhausted.
    for (auto& zone : r.zones) {
        const auto budget = remaining_budget();
        if (budget == 0)
            break;
        sd_bus_set_method_call_timeout(bus.bus, budget);

        SdBusErrorGuard svc_err;
        SdBusMessageGuard svc_reply;
        if (sd_bus_call_method(bus.bus, kFirewalldDest, kFirewalldPath, kFirewalldZoneIface,
                               "getServices", &svc_err.err, &svc_reply.m, "s",
                               zone.name.c_str()) >= 0) {
            // RAII over the raw strv: a manual free() after
            // zone.services.emplace_back() (which can throw std::bad_alloc)
            // leaks the array and its remaining strings on exception --
            // the same shape as the BSTR leak fixed elsewhere in this file.
            // Unconditional release in the destructor closes that gap.
            struct StrvGuard {
                char** v = nullptr;
                ~StrvGuard() {
                    if (v) {
                        for (char** p = v; *p; ++p)
                            free(*p);
                        free(v);
                    }
                }
                // A user-declared (even deleted) copy constructor
                // suppresses the implicitly-declared default constructor
                // entirely -- without this, `} strv;` below fails to
                // compile. Confirmed with a standalone repro.
                StrvGuard() = default;
                StrvGuard(const StrvGuard&) = delete;
                StrvGuard& operator=(const StrvGuard&) = delete;
            } strv;
            if (sd_bus_message_read_strv(svc_reply.m, &strv.v) >= 0 && strv.v) {
                for (char** p = strv.v; *p; ++p)
                    zone.services.emplace_back(*p);
            }
        }
    }
    return r;
}

bool try_firewalld_state(yuzu::CommandContext& ctx) {
    auto q = query_firewalld(/*want_rules=*/false);
    if (!q.reachable)
        return false;
    ctx.write_output("backend|firewalld");
    ctx.write_output("state|running");
    return true;
}

bool try_firewalld_rules(yuzu::CommandContext& ctx) {
    auto q = query_firewalld(/*want_rules=*/true);
    if (!q.reachable)
        return false;
    ctx.write_output("backend|firewalld");
    for (const auto& zone : q.zones) {
        for (const auto& svc : zone.services)
            ctx.write_output(
                std::format("rule|firewalld|{}|service|{}", sanitize_field(zone.name), svc));
    }
    return true;
}

#else // !YUZU_HAVE_LIBSYSTEMD

bool try_firewalld_state(yuzu::CommandContext&) { return false; }
bool try_firewalld_rules(yuzu::CommandContext&) { return false; }

#endif // YUZU_HAVE_LIBSYSTEMD

// ── nftables (rung 1, netlink) ───────────────────────────────────────────
//
// Read-only ruleset enumeration over NETLINK_NETFILTER/NFNL_SUBSYS_NFTABLES.
// No libnftnl/libmnl dependency — neither is a vcpkg dependency today (see
// PR notes) — just the raw socket plus the documented, VERSIONED UAPI wire
// format (linux/netlink.h, linux/netfilter/nfnetlink.h,
// linux/netfilter/nf_tables.h). Socket-level types (AF_NETLINK,
// NETLINK_NETFILTER, sockaddr_nl) come from the REAL system headers here —
// unlike the message-body wire structs, which firewall_parsers.hpp
// transcribes by hand so the pure decode stays compilable/testable on every
// host, the socket API itself must match the running kernel's ABI exactly,
// so pulling it from the system's own headers is the safer choice.
//
// Pure decode (nft_raw namespace, parse_nft_table/chain/rules) is the
// tested core; everything below is the thin, impure shell — one bounded-
// deadline NLM_F_DUMP round-trip per query, sent on a fresh socket per
// try_nftables_state/rules() call and fully drained (to NLMSG_DONE) before
// the next request goes out on the same fd, so there is no cross-request
// interleaving to guard against with a sequence-number check.
//
// Read-only by design (ADR-3002 Decision 8): only GET* dumps are ever sent;
// a mutating leg needs a separately-approved brokered-elevation design and
// is out of scope here.
//
// Protocol assumption, now confirmed rather than merely asserted: a
// GETTABLE/GETCHAIN/GETRULE dump with family=NFPROTO_UNSPEC and no further
// selector attributes enumerates every table/chain/rule across every
// address family in one pass, mirroring how `nft list ruleset` walks the
// whole namespace — verified 2026-08-23 against a real kernel (see
// docs/agent-privilege-model.md): correctly returned every ip/ip6/inet
// table on the test host in one pass each, including a manually-added
// inet table alongside Docker's own ip/ip6 chains.

constexpr std::uint16_t kNlmFRequest = 0x1;
constexpr std::uint16_t kNlmFDump = 0x300; // NLM_F_ROOT | NLM_F_MATCH

namespace nft = yuzu::firewall::nft_raw;

/// Opens and binds a NETLINK_NETFILTER socket for one dump round-trip.
/// Returns an empty (invalid) ScopedFd on any failure — the caller treats
/// that as "backend unreachable", the same fall-through contract as
/// query_firewalld's D-Bus-unreachable path above.
yuzu::agent::ScopedFd open_nft_socket() {
    int fd = ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER);
    if (fd < 0)
        return yuzu::agent::ScopedFd{};
    sockaddr_nl addr{};
    addr.nl_family = AF_NETLINK;
    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        ::close(fd);
        return yuzu::agent::ScopedFd{};
    }
    return yuzu::agent::ScopedFd{fd};
}

/// One bounded NLM_F_DUMP request/response round-trip for `msg_type`
/// (NFT_MSG_GETTABLE/GETCHAIN/GETRULE). Accumulates raw reply bytes into
/// `out`; returns false on any send/poll/recv failure, a kernel
/// NLMSG_ERROR, or the deadline elapsing — false means "nothing trustworthy
/// was read", never a partial-success fabrication (mirrors
/// try_firewalld_state's reachable=false contract).
bool nft_dump(int fd, std::uint16_t msg_type, std::vector<std::byte>& out,
              std::chrono::steady_clock::time_point deadline) {
    alignas(4) unsigned char req[sizeof(nft::NlMsgHdr) + sizeof(nft::NfGenMsg)];
    nft::NlMsgHdr h{};
    h.len = sizeof(req);
    h.type = static_cast<std::uint16_t>((nft::kNfnlSubsysNftables << 8) | msg_type);
    h.flags = kNlmFRequest | kNlmFDump;
    h.seq = 1;
    h.pid = 0;
    nft::NfGenMsg g{};
    g.family = nft::kNfprotoUnspec;
    g.version = 0;
    g.res_id = 0;
    std::memcpy(req, &h, sizeof(h));
    std::memcpy(req + sizeof(h), &g, sizeof(g));

    // Same bounded-deadline contract as the poll loop below: when this is the
    // second or third dump on a shared per-call deadline (try_nftables_state/
    // rules pass one `deadline` to all of GETTABLE/GETCHAIN/GETRULE), an
    // earlier dump can already have consumed the whole budget -- sending a
    // request whose reply has no chance of being read before the poll loop's
    // own `now >= deadline` check triggers is wasted kernel-side work for no
    // benefit (adversarial-review gate-2 finding, unverified/uncompiled).
    if (std::chrono::steady_clock::now() >= deadline)
        return false;

    if (::send(fd, req, sizeof(req), 0) != static_cast<ssize_t>(sizeof(req)))
        return false;

    for (;;) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline)
            return false;
        const auto remaining_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
        pollfd pfd{.fd = fd, .events = POLLIN, .revents = 0};
        if (::poll(&pfd, 1, static_cast<int>(remaining_ms)) <= 0)
            return false; // timeout or error -- bounded, never blocks past deadline
        std::byte buf[8192];
        const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n <= 0)
            return false;
        out.insert(out.end(), buf, buf + n);
        // A dump may span several recv()s -- inspect what's accumulated so
        // far after each read rather than assuming one recv() == the whole
        // reply.
        for (const auto& m : nft::split_nlmsgs(out)) {
            if (m.hdr.type == nft::kNlmsgDone)
                return true;
            if (m.hdr.type == nft::kNlmsgError)
                return false;
        }
    }
}

bool try_nftables_state(yuzu::CommandContext& ctx) {
    const auto deadline = std::chrono::steady_clock::now() + kAcqDeadline;

    // Each dump gets its OWN socket rather than sharing one across
    // GETTABLE/GETCHAIN/GETRULE (adversarial-review/governance gate-3
    // finding UP-1, unverified/uncompiled until this branch's Linux
    // container check): a dump abandoned mid-recv (deadline hit after
    // partial bytes already arrived) can leave undrained bytes sitting in
    // the socket buffer, and nft_dump has no seq/pid check to reject them
    // -- a later dump on the SAME fd could then consume those stale bytes
    // first and report fabricated content instead of the honest `unknown`
    // this function exists to guarantee. A fresh fd per dump removes the
    // shared-buffer assumption entirely rather than trying to correctly
    // drain an abandoned read.
    auto table_sock = open_nft_socket();
    if (!table_sock)
        return false;
    std::vector<std::byte> table_buf;
    if (!nft_dump(table_sock.get(), nft::kNftMsgGettable, table_buf, deadline))
        return false; // unreachable -- fall through to ufw/iptables
    table_sock.reset();

    auto chain_sock = open_nft_socket();
    std::vector<std::byte> chain_buf;
    const bool chains_ok =
        chain_sock && nft_dump(chain_sock.get(), nft::kNftMsgGetchain, chain_buf, deadline);
    chain_sock.reset();

    auto rule_sock = open_nft_socket();
    std::vector<std::byte> rule_buf;
    const bool rules_ok =
        rule_sock && nft_dump(rule_sock.get(), nft::kNftMsgGetrule, rule_buf, deadline);

    ctx.write_output("backend|nftables");
    // Content is only trusted when BOTH follow-up dumps succeeded -- a
    // partial read (e.g. the rule dump alone failing) must not bias toward
    // either "active" or "inactive"; report unknown, same honest-status
    // invariant as try_iptables_state's nonzero-exit path.
    if (!chains_ok || !rules_ok) {
        ctx.write_output("state|unknown");
        return true;
    }
    auto chains = yuzu::firewall::parse_nft_chains(chain_buf);
    auto rules = yuzu::firewall::parse_nft_rules(rule_buf);
    ctx.write_output(std::format(
        "state|{}", yuzu::firewall::nft_has_content(chains, rules) ? "active" : "inactive"));
    return true;
}

bool try_nftables_rules(yuzu::CommandContext& ctx) {
    const auto deadline = std::chrono::steady_clock::now() + kAcqDeadline;

    // See try_nftables_state's comment on UP-1: a fresh socket per dump
    // (rather than one shared across GETTABLE/GETCHAIN/GETRULE) removes the
    // undrained-leftover-bytes class entirely.
    auto table_sock = open_nft_socket();
    if (!table_sock)
        return false;
    std::vector<std::byte> table_buf;
    if (!nft_dump(table_sock.get(), nft::kNftMsgGettable, table_buf, deadline))
        return false; // unreachable -- fall through to ufw/iptables
    table_sock.reset();

    // Reachable even with zero tables -- report that honestly rather than
    // falling through, matching try_firewalld_rules's shape (an empty
    // active-zone list still reports backend|firewalld with no rule rows).
    ctx.write_output("backend|nftables");

    auto chain_sock = open_nft_socket();
    std::vector<std::byte> chain_buf;
    const bool chains_ok =
        chain_sock && nft_dump(chain_sock.get(), nft::kNftMsgGetchain, chain_buf, deadline);
    chain_sock.reset();

    auto rule_sock = open_nft_socket();
    std::vector<std::byte> rule_buf;
    const bool rules_ok =
        rule_sock && nft_dump(rule_sock.get(), nft::kNftMsgGetrule, rule_buf, deadline);

    // Content is only trusted when BOTH dumps succeeded -- a partial read
    // (e.g. the rule dump alone failing) must not be reported as "these are
    // all the rules there are". Same honest-unknown invariant as
    // try_nftables_state and try_iptables_rules's nonzero-exit path.
    if (!chains_ok || !rules_ok) {
        ctx.write_output("rules|unknown");
        return true;
    }

    for (const auto& c : yuzu::firewall::parse_nft_chains(chain_buf)) {
        if (!c.is_base_chain)
            continue; // regular chains carry no hook/policy of their own
        ctx.write_output(std::format(
            "rule|nftables|{}|{}|{}|{}|{}", yuzu::firewall::nft_family_name(c.family),
            sanitize_field(c.table), sanitize_field(c.name),
            yuzu::firewall::nft_hook_name(c.hooknum), yuzu::firewall::nft_policy_name(c.policy)));
    }

    for (const auto& r : yuzu::firewall::parse_nft_rules(rule_buf)) {
        ctx.write_output(std::format(
            "rule|nftables|{}|{}|{}|handle|{}", yuzu::firewall::nft_family_name(r.family),
            sanitize_field(r.table), sanitize_field(r.chain),
            r.handle ? std::to_string(*r.handle) : "unknown"));
    }
    return true;
}

// ── ufw (rung 2, argv) ───────────────────────────────────────────────────
//
// Fixed absolute path, matching every other run_bounded_subprocess call
// site in this file — a distro that installs ufw elsewhere falls through to
// iptables, same as ufw being genuinely absent.

bool try_ufw_state(yuzu::CommandContext& ctx) {
    auto res = run_bounded_subprocess({"/usr/sbin/ufw", "status"},
                                      SubprocessOptions{.deadline = kAcqDeadline});
    if (!res.tool_ran)
        return false; // ufw not installed at this path -> try the next backend
    // Mirrors try_iptables_state's exit-code check, but ufw is NOT the last
    // backend before "none" (iptables still follows), so a failed read (e.g.
    // permission denied) falls through to the next backend rather than
    // stopping the probe here and reporting unknown -- an unprivileged host
    // that can read iptables but not ufw must still get a real answer.
    if (res.exit_code != 0)
        return false;
    ctx.write_output("backend|ufw");
    auto state = yuzu::firewall::parse_ufw_status(res.output);
    ctx.write_output(std::format(
        "state|{}", state == yuzu::firewall::FwState::enabled    ? "active"
                    : state == yuzu::firewall::FwState::disabled ? "inactive"
                                                                  : "unknown"));
    return true;
}

bool try_ufw_rules(yuzu::CommandContext& ctx) {
    auto res = run_bounded_subprocess({"/usr/sbin/ufw", "status", "numbered"},
                                      SubprocessOptions{.deadline = kAcqDeadline});
    if (!res.tool_ran)
        return false;
    // Same fallthrough-not-stop rationale as try_ufw_state: a permission-
    // denied read must not report zero rules as if ufw genuinely had none.
    if (res.exit_code != 0)
        return false;
    ctx.write_output("backend|ufw");
    for (const auto& r : yuzu::firewall::parse_ufw_rules(res.output)) {
        ctx.write_output(std::format("rule|{}|{}|{}|{}", sanitize_field(r.index),
                                     sanitize_field(r.to), sanitize_field(r.action),
                                     sanitize_field(r.from)));
    }
    return true;
}

// ── iptables (rung 2, argv) — the final backend before "none" ──────────

bool try_iptables_state(yuzu::CommandContext& ctx) {
    auto res = run_bounded_subprocess({"/usr/sbin/iptables", "-S"},
                                      SubprocessOptions{.deadline = kAcqDeadline});
    if (!res.tool_ran)
        return false;
    ctx.write_output("backend|iptables");
    // A nonzero exit (commonly EPERM -- iptables needs root/CAP_NET_ADMIN,
    // and this is the last backend in the probe order, so there's nowhere
    // left to fall through to) means the read did not actually happen --
    // honest unknown, never a false-safe "inactive" from empty output.
    if (res.exit_code != 0) {
        ctx.write_output("state|unknown");
        return true;
    }
    auto rules = yuzu::firewall::parse_iptables_save(res.output);
    // iptables has no on/off concept the way ufw/firewalld do: any policy
    // other than the default ACCEPT, or any non-policy entry, counts as
    // "active"; three bare ACCEPT policies and nothing else is "inactive" —
    // matches this leg's pre-migration semantics.
    bool has_content = false;
    for (const auto& r : rules) {
        if (r.type == yuzu::firewall::IptablesEntryType::policy) {
            if (r.spec != "ACCEPT")
                has_content = true;
        } else {
            has_content = true;
        }
    }
    ctx.write_output(std::format("state|{}", has_content ? "active" : "inactive"));
    return true;
}

bool try_iptables_rules(yuzu::CommandContext& ctx) {
    auto res = run_bounded_subprocess({"/usr/sbin/iptables", "-S"},
                                      SubprocessOptions{.deadline = kAcqDeadline});
    if (!res.tool_ran)
        return false;
    ctx.write_output("backend|iptables");
    // Same reasoning as try_iptables_state above: a nonzero exit (commonly
    // EPERM) means the read did not actually happen -- report an honest
    // unknown, never a false-safe empty rule set from unparsed empty output.
    if (res.exit_code != 0) {
        ctx.write_output("rules|unknown");
        return true;
    }
    for (const auto& r : yuzu::firewall::parse_iptables_save(res.output)) {
        const char* type_s = r.type == yuzu::firewall::IptablesEntryType::policy      ? "policy"
                             : r.type == yuzu::firewall::IptablesEntryType::new_chain ? "new_chain"
                             : r.type == yuzu::firewall::IptablesEntryType::append    ? "append"
                                                                                       : "unknown";
        ctx.write_output(std::format("rule|{}|{}|{}", type_s, sanitize_field(r.chain),
                                     sanitize_field(r.spec)));
    }
    return true;
}

#endif // platform dispatch

// ── ABI4 capability declarations (#2204) ────────────────────────────────
//
// Windows: entirely native, zero subprocesses — INetFwPolicy2 COM (rung 1).
// macOS: run_bounded_subprocess argv, no shell (rung 2) — same 3 sites as
// before the migration. Linux: firewalld and nftables are both native rung 1
// (bounded sd-bus / bounded NETLINK_NETFILTER); ufw/iptables are
// run_bounded_subprocess argv (rung 2), the fallback once neither native
// backend is reachable. Neither action mutates firewall state — this plugin
// exposes status/listing only.
const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "state",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "firewalld sd-bus, else nftables NETLINK_NETFILTER (both rung 1), "
         "else ufw/iptables via run_bounded_subprocess (rung 2)",
         nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 2, "socketfilterfw/pfctl via run_bounded_subprocess", nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "INetFwPolicy2 COM (per-profile FirewallEnabled)", nullptr},
    },
    {
        /* .action      = */ "rules",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "firewalld sd-bus, else nftables NETLINK_NETFILTER (both rung 1), "
         "else ufw/iptables via run_bounded_subprocess (rung 2)",
         nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 2, "pfctl via run_bounded_subprocess", nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "INetFwPolicy2 COM (INetFwRules enumeration)", nullptr},
    },
};

} // namespace

class FirewallPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "firewall"; }
    std::string_view version() const noexcept override { return "0.4.0"; }
    std::string_view description() const noexcept override {
        return "Firewall status and rule listing";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"state", "rules", nullptr};
        return acts;
    }

    const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }
    size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }
    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action,
                yuzu::Params /*params*/) override {

        if (action == "state") {
#ifdef _WIN32
            do_state_windows(ctx);
#elif defined(__linux__)
            if (!try_firewalld_state(ctx) && !try_nftables_state(ctx) && !try_ufw_state(ctx) &&
                !try_iptables_state(ctx)) {
                // Every backend was unreachable/absent -- we could not
                // determine anything, so the honest answer is unknown,
                // never a false-safe "inactive" (this file's own
                // never-fabricate invariant, governance Gate 4 unhappy-path
                // finding UP-9: an nftables-only host with no ufw/iptables
                // binaries would otherwise report a genuinely-active
                // firewall as inactive -- pre-existing, byte-identical to
                // the pre-migration fallback, fixed here while already in
                // this exact function).
                ctx.write_output("backend|none");
                ctx.write_output("state|unknown");
            }
#elif defined(__APPLE__)
            do_state_macos(ctx);
#endif
            return 0;
        }

        if (action == "rules") {
#ifdef _WIN32
            do_rules_windows(ctx);
#elif defined(__linux__)
            if (!try_firewalld_rules(ctx) && !try_nftables_rules(ctx) && !try_ufw_rules(ctx) &&
                !try_iptables_rules(ctx)) {
                ctx.write_output("backend|none");
            }
#elif defined(__APPLE__)
            do_rules_macos(ctx);
#endif
            return 0;
        }

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(FirewallPlugin)
