#include "default_certs.hpp"

#include "key_provider.hpp"
#include "x509_ca.hpp"

#include <yuzu/secure_zero.hpp>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <random>
#include <string_view>
#include <system_error>
#include <vector>

#ifndef _WIN32
#include <cerrno>
#include <cstring> // strerror
#include <grp.h>   // getgrnam (--cert-group resolution)
#include <unistd.h> // gethostname, chown
#endif

namespace yuzu::server {

namespace fs = std::filesystem;

namespace {

// Apply the cross-container cert-sharing perms (PKI #1289). Default (empty group)
// keeps the tight single-host posture: dir 0700, keys 0600. When `cert_group` is
// set (a name or numeric gid that the server, gateway, AND agent users all belong
// to), the shared cert volume is opened up *just enough* for sibling containers:
//   - cert dir → 0750 + group=cert_group   (so a different-uid container can
//     TRAVERSE in; the server makes it 0700 by default, which blocks that)
//   - default-gateway.key → 0640 + group=cert_group  (the ONE shared private key:
//     the gateway runs as a different uid and must read its own leaf key)
// The CA cert + leaf certs are public (0644); the server/HTTPS private keys stay
// 0600 owner-only — never group-shared.
void apply_cert_group_share(const fs::path& dir, const DefaultCertSet& out,
                            const std::string& cert_group) {
    std::error_code ec;
    if (cert_group.empty()) {
        fs::permissions(dir, fs::perms::owner_all, fs::perm_options::replace, ec); // 0700
        // True idempotency: if a prior boot ran with --cert-group, the gateway key
        // may still carry 0640. Re-tighten it to 0600 so dropping --cert-group fully
        // reverts the posture (the 0700 dir already blocks traversal, but be explicit).
        if (fs::exists(out.gateway_key))
            fs::permissions(out.gateway_key, fs::perms::owner_read | fs::perms::owner_write,
                            fs::perm_options::replace, ec); // 0600
        return;
    }
#ifndef _WIN32
    gid_t gid = static_cast<gid_t>(-1);
    char* end = nullptr;
    const long n = std::strtol(cert_group.c_str(), &end, 10);
    if (end && *end == '\0' && n >= 0) {
        gid = static_cast<gid_t>(n);
    } else if (const struct group* gr = ::getgrnam(cert_group.c_str())) {
        gid = gr->gr_gid;
    }
    if (gid == static_cast<gid_t>(-1)) {
        spdlog::warn("default_certs: --cert-group '{}' does not resolve to a group — leaving "
                     "tight 0700/0600 perms (a gateway/agent in another container will NOT be "
                     "able to read the shared certs)", cert_group);
        fs::permissions(dir, fs::perms::owner_all, fs::perm_options::replace, ec);
        return;
    }
    // Chgrp BEFORE widening: never expose the dir to a group we have not
    // confirmed ownership of. On chgrp failure the dir stays 0700.
    if (::chown(dir.c_str(), static_cast<uid_t>(-1), gid) == 0) {
        fs::permissions(dir, fs::perms::owner_all | fs::perms::group_read | fs::perms::group_exec,
                        fs::perm_options::replace, ec); // 0750
    } else {
        spdlog::warn("default_certs: chgrp '{}' on {} failed: {} — leaving 0700 (the server user "
                     "must be a member of that group to share it)", cert_group, dir.string(),
                     std::strerror(errno));
        fs::permissions(dir, fs::perms::owner_all, fs::perm_options::replace, ec); // 0700
        return; // do not group-share the gateway key either if the dir chgrp failed
    }
    if (fs::exists(out.gateway_key)) {
        if (::chown(out.gateway_key.c_str(), static_cast<uid_t>(-1), gid) == 0)
            fs::permissions(out.gateway_key,
                            fs::perms::owner_read | fs::perms::owner_write | fs::perms::group_read,
                            fs::perm_options::replace, ec); // 0640
        else
            spdlog::warn("default_certs: chgrp on gateway key failed: {}", std::strerror(errno));
    }
    spdlog::info("default_certs: cert dir + gateway key shared with group '{}' (gid {}) for "
                 "multi-container TLS", cert_group, static_cast<unsigned long>(gid));
#else
    (void)out;
    spdlog::warn("default_certs: --cert-group is POSIX-only; ignored on Windows (use ACLs / a "
                 "shared service account). Leaving owner-only perms.");
    fs::permissions(dir, fs::perms::owner_all, fs::perm_options::replace, ec);
#endif
}

constexpr int kMarkerVersion = 1;

int64_t to_epoch(std::chrono::system_clock::time_point tp) {
    return std::chrono::duration_cast<std::chrono::seconds>(tp.time_since_epoch()).count();
}
std::chrono::system_clock::time_point from_epoch(int64_t s) {
    return std::chrono::system_clock::time_point{std::chrono::seconds{s}};
}

std::string read_text_file(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    if (!in)
        return {};
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

std::string rand_suffix() {
    std::random_device rd;
    static const char* kHex = "0123456789abcdef";
    std::string s;
    for (int i = 0; i < 4; ++i) {
        uint32_t v = rd();
        for (int j = 0; j < 8; ++j) {
            s += kHex[v & 0xF];
            v >>= 4;
        }
    }
    return s;
}

// Atomic write of a PUBLIC file (certs, marker) — stage to a sibling temp then
// rename. The artifact is set to a DETERMINISTIC 0644 (world-readable), NOT the
// umask default: the CA cert + leaf certs are public trust material (the CA cert
// is also served at GET /api/v1/ca/root), and under the secure-by-default
// multi-container deploy a different-uid agent/gateway container must be able to
// read the shared default-ca.pem. A strict server umask (e.g. 0077) would
// otherwise leave it 0600 and break CA auto-discovery even with --cert-group
// sharing the dir. The 0700/0750 dir still gates who can traverse to it, so 0644
// on the file never widens access beyond what the dir already allows. Private
// keys never come through here — they go through FileKeyProvider (0600).
bool write_public_file(const fs::path& dest, const std::string& contents) {
    std::error_code ec;
    const fs::path tmp = dest.parent_path() / (dest.filename().string() + ".tmp." + rand_suffix());
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) {
            spdlog::error("default_certs: cannot open temp {}", tmp.string());
            return false;
        }
        out.write(contents.data(), static_cast<std::streamsize>(contents.size()));
        out.flush();
        if (!out) {
            spdlog::error("default_certs: write failed for {}", tmp.string());
            out.close();
            fs::remove(tmp, ec);
            return false;
        }
    }
    // Set perms on the temp BEFORE the rename so the destination is never briefly
    // visible at the umask default (and so the public bit is atomic with publish).
    fs::permissions(tmp,
                    fs::perms::owner_read | fs::perms::owner_write | fs::perms::group_read |
                        fs::perms::others_read,
                    fs::perm_options::replace, ec); // 0644
    if (ec)
        spdlog::warn("default_certs: chmod 0644 on {} failed: {}", tmp.string(), ec.message());
    fs::rename(tmp, dest, ec);
    if (ec) {
        spdlog::error("default_certs: rename {} -> {} failed: {}", tmp.string(), dest.string(),
                      ec.message());
        fs::remove(tmp, ec);
        return false;
    }
    return true;
}

bool file_present(const fs::path& p) {
    std::error_code ec;
    return fs::exists(p, ec) && !ec && fs::file_size(p, ec) > 0 && !ec;
}

// One server-side leaf to generate.
struct LeafSpec {
    const char* key_id;    // FileKeyProvider id -> <dir>/<key_id>.key
    const char* cert_file; // <dir>/<cert_file>
    const char* purpose;   // ca_store purpose + subject text
    pki::LeafUsage usage;
};

std::string join_san(const pki::SubjectAltNames& san) {
    std::string s;
    auto add = [&](const char* pfx, const std::vector<std::string>& v) {
        for (const auto& e : v) {
            if (!s.empty())
                s += ',';
            s += pfx;
            s += e;
        }
    };
    add("DNS:", san.dns);
    add("IP:", san.ips);
    add("URI:", san.uris);
    return s;
}

void fill_paths(const fs::path& dir, DefaultCertSet& out) {
    out.ca_cert = dir / "default-ca.pem";
    out.https_cert = dir / "default-https.pem";
    out.https_key = dir / "default-https.key";
    out.server_cert = dir / "default-server.pem";
    out.server_key = dir / "default-server.key";
    out.gateway_cert = dir / "default-gateway.pem";
    out.gateway_key = dir / "default-gateway.key";
}

bool all_files_present(const DefaultCertSet& s) {
    return file_present(s.ca_cert) && file_present(s.https_cert) && file_present(s.https_key) &&
           file_present(s.server_cert) && file_present(s.server_key) &&
           file_present(s.gateway_cert) && file_present(s.gateway_key);
}

// RAII: wipe key material on scope exit, INCLUDING exception unwind. ~std::string
// does not zero freed memory, so a throw mid-generation would otherwise leave the
// CA / leaf private key recoverable in freed heap.
struct KeyZeroGuard {
    std::string& s;
    explicit KeyZeroGuard(std::string& str) : s(str) {}
    ~KeyZeroGuard() { yuzu::secure_zero(s); }
    KeyZeroGuard(const KeyZeroGuard&) = delete;
    KeyZeroGuard& operator=(const KeyZeroGuard&) = delete;
};

// case-insensitive ASCII prefix test (no locale, no <cctype> surprises).
bool ci_prefix(std::string_view s, std::string_view pfx) {
    if (s.size() < pfx.size())
        return false;
    for (std::size_t i = 0; i < pfx.size(); ++i) {
        char c = s[i];
        if (c >= 'A' && c <= 'Z')
            c = static_cast<char>(c - 'A' + 'a');
        if (c != pfx[i])
            return false;
    }
    return true;
}

std::string_view trim_ws(std::string_view s) {
    auto ws = [](char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; };
    while (!s.empty() && ws(s.front()))
        s.remove_prefix(1);
    while (!s.empty() && ws(s.back()))
        s.remove_suffix(1);
    return s;
}

bool has_control_char(std::string_view s) {
    for (unsigned char c : s)
        if (c < 0x20 || c == 0x7f)
            return true;
    return false;
}

// Bounds on operator --cert-san input so a malformed/huge value (CLI or the
// YUZU_CERT_SAN env, which a deployment may template from a less-trusted source)
// cannot hang or balloon boot, and so each DNS name stays within RFC 1035 limits.
constexpr std::size_t kMaxExtraSans = 64;     // total accepted extra names
constexpr std::size_t kMaxRawEntryLen = 1024; // per raw --cert-san entry
constexpr std::size_t kMaxDnsNameLen = 253;   // RFC 1035 total
constexpr std::size_t kMaxDnsLabelLen = 63;   // RFC 1035 label

// Validate a dNSName SAN: non-empty, <=253 bytes, every dot-separated label
// non-empty and <=63 bytes, no leading/trailing dot, and a host-name charset
// (letters/digits/hyphen/underscore, plus '*' for a wildcard). The charset keeps
// genuine config mistakes (path-like '/', zone-id '%', whitespace, ':') out of
// the certificate rather than baking a never-matching SAN; IDNs are punycode
// (xn--…) so they remain ASCII-LDH. Wildcards are warned on by the caller.
bool valid_dns_name(std::string_view s) {
    if (s.empty() || s.size() > kMaxDnsNameLen)
        return false;
    std::size_t label = 0;
    for (char c : s) {
        if (c == '.') {
            if (label == 0)
                return false; // empty label (leading dot or "a..b")
            label = 0;
            continue;
        }
        const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                        (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '*';
        if (!ok)
            return false;
        if (++label > kMaxDnsLabelLen)
            return false;
    }
    return label != 0; // reject a trailing dot
}

// Parse operator --cert-san values into a validated, de-duplicated SAN set.
// Each raw entry may be comma-separated; each piece is "dns:<name>", "ip:<addr>",
// or a bare value classified IP-vs-DNS by pki::is_valid_ip_literal — the EXACT
// parser issue_leaf uses, so a value accepted here can never hard-fail cert
// generation (a typo'd IP is dropped, not boot-fatal). Invalid / over-bound /
// control-char / non-IP-"ip:" pieces are dropped with a warning; the total is
// capped. Returns only the extras (the base SAN set is merged separately).
pki::SubjectAltNames parse_extra_sans(const std::vector<std::string>& extra) {
    pki::SubjectAltNames out;
    std::size_t total = 0;
    auto push_unique = [](std::vector<std::string>& v, std::string val) -> bool {
        if (val.empty() || std::find(v.begin(), v.end(), val) != v.end())
            return false;
        v.push_back(std::move(val));
        return true;
    };
    auto add_dns = [&](std::string_view name) {
        std::string n(name);
        if (!valid_dns_name(n)) {
            spdlog::warn("default_certs: ignoring --cert-san DNS '{}' (empty/over-length/malformed)",
                         n);
            return;
        }
        if (n.find('*') != std::string::npos) {
            // #1271 UP-10/11: REJECT wildcards in default-cert SANs (was warn-only).
            // The install CA is distributed to every agent as a trust anchor, so a
            // wildcard leaf has real blast radius — a single stolen default-leaf key
            // would validate for an entire `*.<domain>`. An operator who genuinely
            // needs a wildcard must bring their own cert (`--https-cert` etc.).
            spdlog::warn("default_certs: REJECTING --cert-san DNS '{}' — wildcard SANs are not "
                         "allowed in fleet-trusted default certs; supply your own cert for a "
                         "wildcard",
                         n);
            return;
        }
        if (push_unique(out.dns, std::move(n)))
            ++total;
    };
    auto add_ip = [&](std::string_view addr) {
        std::string a(addr);
        if (!pki::is_valid_ip_literal(a)) {
            spdlog::warn("default_certs: ignoring --cert-san IP '{}' (not a valid IP literal)", a);
            return;
        }
        if (push_unique(out.ips, std::move(a)))
            ++total;
    };
    auto classify = [&](std::string_view piece) {
        piece = trim_ws(piece);
        if (piece.empty())
            return;
        if (has_control_char(piece)) {
            spdlog::warn("default_certs: ignoring --cert-san entry containing control characters");
            return;
        }
        if (ci_prefix(piece, "dns:")) {
            const std::string_view v = trim_ws(piece.substr(4));
            if (pki::is_valid_ip_literal(std::string(v)))
                spdlog::warn("default_certs: --cert-san 'dns:{}' is an IP literal — keeping it as a "
                             "DNS-type SAN as written; use 'ip:' for an iPAddress SAN",
                             std::string(v));
            add_dns(v);
        } else if (ci_prefix(piece, "ip:")) {
            add_ip(trim_ws(piece.substr(3)));
        } else if (pki::is_valid_ip_literal(std::string(piece))) {
            add_ip(piece);
        } else {
            add_dns(piece);
        }
    };
    // #1271 UP-9: the kMaxExtraSans cap counts only ACCEPTED names, so a flood of
    // INVALID entries (each warns + validates without ever incrementing `total`)
    // could CPU/log-flood at boot. Bound the total PIECES parsed (raw entries ×
    // comma-split) independently — generous headroom above kMaxExtraSans, then a
    // hard stop. Never boot-fatal (matches the drop-with-warning posture).
    constexpr std::size_t kMaxSanPieces = 512;
    std::size_t pieces_seen = 0;
    for (const auto& raw : extra) {
        if (total >= kMaxExtraSans) {
            spdlog::warn("default_certs: --cert-san capped at {} extra names — ignoring the rest",
                         kMaxExtraSans);
            break;
        }
        if (raw.size() > kMaxRawEntryLen) {
            spdlog::warn("default_certs: ignoring oversize --cert-san entry ({} bytes)", raw.size());
            continue;
        }
        std::string_view rv{raw};
        std::size_t start = 0;
        for (;;) {
            if (++pieces_seen > kMaxSanPieces) {
                spdlog::warn("default_certs: --cert-san piece limit ({}) reached — ignoring the "
                             "rest (invalid-entry flood guard)",
                             kMaxSanPieces);
                return out;
            }
            const std::size_t comma = rv.find(',', start);
            classify(rv.substr(
                start, comma == std::string_view::npos ? std::string_view::npos : comma - start));
            if (comma == std::string_view::npos || total >= kMaxExtraSans)
                break;
            start = comma + 1;
        }
    }
    return out;
}

// Merge validated extras into the base SAN set, de-duping against it.
void merge_sans(pki::SubjectAltNames& base, const pki::SubjectAltNames& extra) {
    for (const auto& d : extra.dns)
        if (std::find(base.dns.begin(), base.dns.end(), d) == base.dns.end())
            base.dns.push_back(d);
    for (const auto& i : extra.ips)
        if (std::find(base.ips.begin(), base.ips.end(), i) == base.ips.end())
            base.ips.push_back(i);
}

// Best-effort operator-footgun guard for the idempotent fast path: if --cert-san
// asks for names the EXISTING cert set does not carry, warn. Changing --cert-san
// deliberately does NOT auto-rotate (that would mint a new CA and break every
// enrolled agent's trust) — the operator must clear the dir to apply. DNS + IPv4
// only; IPv6 is skipped because the parsed-back form is uncompressed
// (e.g. "0:0:0:0:0:0:0:1"), so a literal compare would false-positive.
void warn_on_san_drift(const fs::path& representative_leaf,
                       const std::vector<std::string>& extra_sans) {
    const pki::SubjectAltNames want = parse_extra_sans(extra_sans);
    if (want.dns.empty() && want.ips.empty())
        return;
    const auto cert = pki::parse_certificate(read_text_file(representative_leaf));
    if (!cert)
        return;
    auto missing = [](const std::vector<std::string>& w, const std::vector<std::string>& have,
                      bool skip_ipv6) {
        std::vector<std::string> m;
        for (const auto& e : w) {
            if (skip_ipv6 && e.find(':') != std::string::npos)
                continue;
            if (std::find(have.begin(), have.end(), e) == have.end())
                m.push_back(e);
        }
        return m;
    };
    std::vector<std::string> miss = missing(want.dns, cert->san.dns, false);
    const std::vector<std::string> miss_ip = missing(want.ips, cert->san.ips, true);
    miss.insert(miss.end(), miss_ip.begin(), miss_ip.end());
    if (miss.empty())
        return;
    std::string joined;
    for (const auto& m : miss) {
        if (!joined.empty())
            joined += ", ";
        joined += m;
    }
    spdlog::warn("default_certs: --cert-san requests [{}] not present in the existing default certs "
                 "(they predate these SANs). Clear the cert directory to regenerate with them.",
                 joined);
}

} // namespace

std::string detect_hostname() {
#ifdef _WIN32
    if (const char* c = std::getenv("COMPUTERNAME"); c && c[0])
        return std::string(c);
    return "localhost";
#else
    char buf[256] = {};
    if (::gethostname(buf, sizeof(buf) - 1) == 0 && buf[0])
        return std::string(buf);
    return "localhost";
#endif
}

bool ensure_default_certs(const fs::path& dir, const std::string& hostname, CaStore* ca_store,
                          DefaultCertSet& out, const std::vector<std::string>& extra_sans,
                          const std::string& cert_group) {
    fill_paths(dir, out);
    const fs::path marker = dir / "default-marker.json";

    // ── Idempotent fast path ──────────────────────────────────────────────────
    if (file_present(marker) && all_files_present(out)) {
        const std::string marker_text = read_text_file(marker);
        try {
            const auto j = nlohmann::json::parse(marker_text);
            if (j.value("version", 0) == kMarkerVersion) {
                const std::string expected_fp = j.value("ca_fingerprint", "");
                const std::string ca_pem = read_text_file(out.ca_cert);
                auto fp = pki::fingerprint_sha256(ca_pem);
                if (fp && *fp == expected_fp && !expected_fp.empty()) {
                    // Beyond file-exists+size: confirm every leaf still chains to
                    // this CA (catches a corrupt/substituted leaf) AND that the CA
                    // is CURRENTLY valid. The validity check self-heals a set minted
                    // under a skewed clock — e.g. clock ahead at first boot yields a
                    // not-yet-valid CA; once the clock is corrected the next boot
                    // regenerates rather than serving an unusable (or expired) cert.
                    const bool leaves_ok =
                        pki::verify_chain(read_text_file(out.https_cert), ca_pem) &&
                        pki::verify_chain(read_text_file(out.server_cert), ca_pem) &&
                        pki::verify_chain(read_text_file(out.gateway_cert), ca_pem);
                    auto ca_info = pki::parse_certificate(ca_pem);
                    const auto now = std::chrono::system_clock::now();
                    const bool ca_valid_now =
                        ca_info && ca_info->not_before <= now && now < ca_info->not_after;
                    if (leaves_ok && ca_valid_now) {
                        out.ca_fingerprint_sha256 = *fp;
                        out.ca_expires_at = from_epoch(j.value("expires_at", int64_t{0}));
                        out.freshly_generated = false;
                        spdlog::info("default_certs: existing default cert set is intact (CA {})",
                                     out.ca_fingerprint_sha256);
                        // Tell the operator if --cert-san now asks for names the
                        // existing certs don't carry (we never auto-rotate).
                        warn_on_san_drift(out.gateway_cert, extra_sans);
                        // Re-assert the cert-sharing perms on the existing set so a
                        // restart (or a --cert-group added after first boot) is
                        // consistent — idempotent.
                        apply_cert_group_share(dir, out, cert_group);
                        return true;
                    }
                    spdlog::warn("default_certs: existing default certs unusable ({}) — "
                                 "regenerating",
                                 !leaves_ok ? "a leaf no longer chains to the CA"
                                            : "CA not currently valid (clock skew?)");
                } else {
                    spdlog::warn("default_certs: marker/CA fingerprint mismatch — regenerating");
                }
            }
        } catch (const std::exception& e) {
            spdlog::warn("default_certs: marker parse failed ({}) — regenerating", e.what());
        }
    }

    // ── B-2 (#1238): never silently re-root a populated CA ─────────────────────
    // We only reach here because the fast path found the on-disk default certs
    // missing / corrupt / mismatched. If ca.db STILL remembers a CA root,
    // generating a fresh one would set_root-REPLACE it and purge the issued
    // inventory — orphaning every agent already enrolled under the old root (their
    // leaves now chain to a dead CA). That is the dangerous quadrant the
    // corrupt-only self-heal above does NOT cover: a wiped cert dir on a
    // persistent ca.db volume, or a botched restore. Refuse with an actionable
    // message; the operator restores the certs from backup (matching the ca.db
    // root) or removes ca.db too for a deliberate clean re-root. We refuse on ANY
    // existing root (not only a fingerprint mismatch): the regen path always mints
    // a brand-new CA, so proceeding would re-root regardless.
    if (ca_store && ca_store->is_open() && ca_store->has_root()) {
        const auto root = ca_store->get_root();
        const std::string on_disk = file_present(out.ca_cert)
                                        ? ("on-disk CA " + pki::fingerprint_sha256(
                                                               read_text_file(out.ca_cert))
                                                               .value_or(std::string{"unreadable"}))
                                        : std::string{"no on-disk CA cert"};
        spdlog::error("default_certs: ca.db already holds a CA root ({}) but the on-disk default "
                      "certs in {} are missing/corrupt ({}). Refusing to regenerate — a fresh CA "
                      "would re-root the fleet and orphan every enrolled agent. Restore "
                      "default-*.{{pem,key}} from backup (matching the ca.db root), or remove ca.db "
                      "for a deliberate clean re-root.",
                      root ? root->fingerprint_sha256 : std::string{"?"}, dir.string(), on_disk);
        return false;
    }

    // ── (Re)generate the whole set ────────────────────────────────────────────
    spdlog::warn("default_certs: generating a fresh per-install CA + default leaves in {}",
                 dir.string());

    std::error_code ec;
    fs::create_directories(dir, ec);
    if (ec) {
        spdlog::error("default_certs: cannot create {}: {}", dir.string(), ec.message());
        return false;
    }
    fs::permissions(dir, fs::perms::owner_all, fs::perm_options::replace, ec); // 0700
    if (ec)
        spdlog::error("default_certs: could not set 0700 on {}: {} (keys stay 0600 regardless)",
                      dir.string(), ec.message());

    // On regeneration, purge any prior default-cert inventory rows so ca.db
    // reflects only the live set (no orphan leaves referencing a replaced root;
    // set_root REPLACEs the single root row separately). After B-2 this path is
    // only reached with an EMPTY ca.db (regen against a populated root is now
    // refused), so this normally deletes nothing — but a failed purge would leave
    // stale rows, so surface it (#1238 should-fix: don't silently ignore the rc).
    if (ca_store && !ca_store->delete_issued_by("system:default-certs"))
        spdlog::warn("default_certs: failed to purge prior default-cert inventory rows "
                     "(stale rows may remain) — continuing");

    auto ca_key_pem = pki::generate_private_key(pki::KeyAlgo::EcP384);
    if (!ca_key_pem)
        return false;
    KeyZeroGuard ca_zero{*ca_key_pem}; // exception-safe wipe of the CA key

    pki::CaParams ca_params;
    ca_params.subject = {"Yuzu Install CA (" + hostname + ")", "Yuzu"};
    ca_params.validity = pki::validity_years_from_now(10);
    ca_params.path_len = 0;
    auto ca_cert_pem = pki::self_sign_ca(*ca_key_pem, ca_params);
    if (!ca_cert_pem)
        return false;

    auto ca_info = pki::parse_certificate(*ca_cert_pem);
    auto ca_fp = pki::fingerprint_sha256(*ca_cert_pem);
    if (!ca_info || !ca_fp)
        return false;
    // #1296: STABLE key-based CA identity stamped on every issued row so an
    // "issued by this CA" query survives a subordinate re-key. Best-effort: a
    // derivation miss leaves the field blank (the row stays serial-addressable).
    const std::string ca_key_id = pki::issuer_key_id(*ca_cert_pem).value_or(std::string{});
    // Leaves are sized to the CA's exact notAfter so they never outlive the
    // issuer (the x509_ca leaf-<=-CA invariant would otherwise reject them).
    const pki::Validity leaf_validity{std::chrono::system_clock::now(), ca_info->not_after};

    pki::SubjectAltNames san;
    san.dns = {"localhost"};
    san.ips = {"127.0.0.1", "::1"};
    // An IP-literal hostname must go in the iPAddress SAN, not dNSName. The
    // detected hostname is gated through the SAME validation as operator extras
    // (a container gethostname() can return non-hostname bytes) — if it is
    // neither a valid IP nor a valid DNS name it is omitted with a warning rather
    // than baking a malformed SAN; localhost/loopback still cover local access.
    if (pki::is_valid_ip_literal(hostname))
        san.ips.push_back(hostname);
    else if (valid_dns_name(hostname))
        san.dns.push_back(hostname);
    else if (!hostname.empty())
        spdlog::warn("default_certs: host name '{}' is not a valid DNS name — omitting from the "
                     "default-cert SAN (use --cert-san to add a reachable name)",
                     hostname);
    // Operator --cert-san extend the SAME set on every default leaf. This mirrors
    // the base set above — localhost/loopback/hostname is itself identical across
    // all three leaves — so an extra grants nothing a stolen leaf key couldn't
    // already do (impersonation needs the 0600 key = host compromise; all three
    // are co-located, same-operator, same-CA server infra). Per-leaf scoping is a
    // possible future refinement, not a day-one need.
    merge_sans(san, parse_extra_sans(extra_sans));

    const std::array<LeafSpec, 3> leaves = {{
        {"default-https", "default-https.pem", "https", pki::LeafUsage{.server_auth = true}},
        // The server is a server to agents/gateway AND a client when it forwards
        // commands to the gateway's mgmt plane over mutual TLS (#1314), so its leaf
        // needs clientAuth too — otherwise a strict verifier rejects it as a client
        // cert and the mTLS command-forwarding dial fails.
        {"default-server", "default-server.pem", "server",
         pki::LeafUsage{.server_auth = true, .client_auth = true}},
        // The gateway is a server to agents AND a client to the server upstream.
        {"default-gateway", "default-gateway.pem", "gateway",
         pki::LeafUsage{.server_auth = true, .client_auth = true}},
    }};

    FileKeyProvider kp(dir);
    bool ok = write_public_file(out.ca_cert, *ca_cert_pem);

    for (const auto& spec : leaves) {
        if (!ok)
            break;
        pki::LeafParams lp;
        lp.subject = {std::string("Yuzu Default ") + spec.purpose, "Yuzu"};
        lp.san = san;
        lp.validity = leaf_validity;
        lp.usage = spec.usage;
        auto kc = pki::issue_leaf(*ca_cert_pem, *ca_key_pem, pki::KeyAlgo::EcP256, lp);
        if (!kc) {
            ok = false;
            break;
        }
        KeyZeroGuard leaf_zero{kc->private_key_pem}; // exception-safe wipe
        ok = write_public_file(dir / spec.cert_file, kc->cert_pem);
        if (ok && !kp.store_key(spec.key_id, kc->private_key_pem)) {
            ok = false;
        }

        if (ok && ca_store) {
            IssuedCertRecord rec;
            rec.serial_hex = kc->serial_hex;
            rec.subject = lp.subject.common_name;
            rec.san = join_san(san);
            rec.purpose = spec.purpose;
            rec.not_after = to_epoch(ca_info->not_after);
            rec.cert_pem = kc->cert_pem;
            rec.issued_by = "system:default-certs";
            rec.issuer_fingerprint = *ca_fp;
            rec.issuer_key_id = ca_key_id;
            if (!ca_store->record_issued(rec)) {
                spdlog::error("default_certs: failed to record issued '{}' in ca.db — aborting "
                              "(the inventory must be consistent for revocation / rotation)",
                              spec.purpose);
                ok = false;
            }
        }
    }

    std::string ca_key_ref;
    if (ok) {
        auto ref = kp.store_key("default-ca", *ca_key_pem);
        if (ref)
            ca_key_ref = *ref;
        else
            ok = false;
    }
    if (!ok) {
        spdlog::error("default_certs: generation failed; leaving no marker (will retry next boot)");
        return false;
    }

    if (ca_store) {
        CaRoot root;
        root.cert_pem = *ca_cert_pem;
        root.key_ref = ca_key_ref;
        root.algo = "EcP384";
        root.not_before = to_epoch(ca_info->not_before);
        root.not_after = to_epoch(ca_info->not_after);
        root.fingerprint_sha256 = *ca_fp;
        root.mode = CaMode::Builtin;
        if (!ca_store->set_root(root)) {
            spdlog::error("default_certs: failed to record CA root in ca.db — aborting");
            return false; // before the marker — next boot regenerates
        }
    }

    // Marker LAST — its presence is the "set is complete" signal.
    nlohmann::json j;
    j["version"] = kMarkerVersion;
    j["generated_at"] = to_epoch(std::chrono::system_clock::now());
    j["ca_fingerprint"] = *ca_fp;
    j["expires_at"] = to_epoch(ca_info->not_after);
    j["hostname"] = hostname;
    if (!write_public_file(marker, j.dump(2))) {
        spdlog::error("default_certs: failed to write marker");
        return false;
    }

    out.ca_fingerprint_sha256 = *ca_fp;
    out.ca_expires_at = ca_info->not_after;
    out.freshly_generated = true;
    // Now that the full set (incl. default-gateway.key) exists, apply the
    // cross-container sharing perms (no-op tight perms when --cert-group is unset).
    apply_cert_group_share(dir, out, cert_group);
    spdlog::warn("default_certs: generated default cert set — CA {} expires {}",
                 out.ca_fingerprint_sha256, to_epoch(ca_info->not_after));
    return true;
}

} // namespace yuzu::server
