#include "default_certs.hpp"

#include "key_provider.hpp"
#include "x509_ca.hpp"

#include <yuzu/secure_zero.hpp>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <random>
#include <system_error>
#include <vector>

#ifndef _WIN32
#include <unistd.h> // gethostname
#endif

namespace yuzu::server {

namespace fs = std::filesystem;

namespace {

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
// rename. Public artifacts keep default perms; private keys go through
// FileKeyProvider (0600) instead.
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

// Heuristic: does `h` look like an IP literal? IP literals belong in the
// iPAddress SAN, never dNSName (strict TLS stacks reject an IP in a DNS SAN).
bool looks_like_ip(const std::string& h) {
    if (h.find(':') != std::string::npos)
        return true; // IPv6
    if (h.empty())
        return false;
    for (char c : h)
        if (!((c >= '0' && c <= '9') || c == '.'))
            return false;
    return h.find('.') != std::string::npos; // dotted-decimal IPv4
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
                          DefaultCertSet& out) {
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
    if (ca_store && ca_store->has_root()) {
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
    // set_root REPLACEs the single root row separately).
    if (ca_store)
        ca_store->delete_issued_by("system:default-certs");

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
    // Leaves are sized to the CA's exact notAfter so they never outlive the
    // issuer (the x509_ca leaf-<=-CA invariant would otherwise reject them).
    const pki::Validity leaf_validity{std::chrono::system_clock::now(), ca_info->not_after};

    pki::SubjectAltNames san;
    san.dns = {"localhost"};
    san.ips = {"127.0.0.1", "::1"};
    // An IP-literal hostname must go in the iPAddress SAN, not dNSName.
    if (looks_like_ip(hostname))
        san.ips.push_back(hostname);
    else if (!hostname.empty())
        san.dns.push_back(hostname);

    const std::array<LeafSpec, 3> leaves = {{
        {"default-https", "default-https.pem", "https", pki::LeafUsage{.server_auth = true}},
        {"default-server", "default-server.pem", "server", pki::LeafUsage{.server_auth = true}},
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
    spdlog::warn("default_certs: generated default cert set — CA {} expires {}",
                 out.ca_fingerprint_sha256, to_epoch(ca_info->not_after));
    return true;
}

} // namespace yuzu::server
