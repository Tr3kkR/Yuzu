#include <yuzu/agent/agent_csr.hpp>

#include <spdlog/spdlog.h>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <ctime>
#include <fstream>
#include <random>
#include <string_view>
#include <system_error>
#include <utility>

#ifndef _WIN32
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#endif

namespace yuzu::agent {

namespace fs = std::filesystem;

namespace {

// ── RAII for OpenSSL objects (mirrors server/core/src/x509_ca.cpp) ─────────────
#define YUZU_SSL_PTR(T, freefn)                                                                    \
    struct T##_Deleter {                                                                            \
        void operator()(T* p) const noexcept {                                                      \
            freefn(p);                                                                              \
        }                                                                                          \
    };                                                                                             \
    using T##_ptr = std::unique_ptr<T, T##_Deleter>

YUZU_SSL_PTR(BIO, BIO_free);
YUZU_SSL_PTR(EVP_PKEY, EVP_PKEY_free);
YUZU_SSL_PTR(X509, X509_free);
YUZU_SSL_PTR(X509_REQ, X509_REQ_free);
YUZU_SSL_PTR(X509_NAME, X509_NAME_free);
#undef YUZU_SSL_PTR

void log_ssl_errors(std::string_view ctx) {
    unsigned long e = 0;
    bool any = false;
    while ((e = ERR_get_error()) != 0) {
        std::array<char, 256> buf{};
        ERR_error_string_n(e, buf.data(), buf.size());
        spdlog::error("agent_csr: {}: {}", ctx, buf.data());
        any = true;
    }
    if (!any)
        spdlog::error("agent_csr: {} (no OpenSSL error detail)", ctx);
}

std::string bio_to_string(BIO* bio) {
    char* data = nullptr;
    const long len = BIO_get_mem_data(bio, &data);
    if (!data || len <= 0)
        return {};
    return std::string(data, static_cast<std::size_t>(len));
}

template <typename Fn>
std::optional<std::string> to_pem(Fn&& write_fn, std::string_view ctx) {
    BIO_ptr bio{BIO_new(BIO_s_mem())};
    if (!bio) {
        log_ssl_errors(ctx);
        return std::nullopt;
    }
    if (write_fn(bio.get()) != 1) {
        log_ssl_errors(ctx);
        return std::nullopt;
    }
    return bio_to_string(bio.get());
}

constexpr std::size_t kMaxPemSize = 1024 * 1024; // 1 MiB — far above any cert/key

X509_ptr load_cert(std::string_view pem) {
    if (pem.empty() || pem.size() > kMaxPemSize)
        return nullptr;
    BIO_ptr bio{BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()))};
    if (!bio)
        return nullptr;
    return X509_ptr{PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr)};
}

std::optional<std::chrono::system_clock::time_point> from_asn1_time(const ASN1_TIME* at) {
    if (!at)
        return std::nullopt;
    std::tm tm{};
    if (ASN1_TIME_to_tm(at, &tm) != 1)
        return std::nullopt;
#ifdef _WIN32
    const std::time_t t = _mkgmtime(&tm);
#else
    const std::time_t t = timegm(&tm);
#endif
    if (t == static_cast<std::time_t>(-1))
        return std::nullopt;
    return std::chrono::system_clock::from_time_t(t);
}

std::string read_text_file(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    if (!in)
        return {};
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

std::string random_suffix() {
    static const char* kHex = "0123456789abcdef";
    // A one-time process-random base (seeded once — no per-call random_device fd
    // churn) XORed with a monotonic counter: unique within the process and
    // unpredictable across processes, without depending SOLELY on random_device
    // entropy (which can degrade in some virtualised hosts). The real
    // symlink/redirect defence is O_EXCL|O_NOFOLLOW + the 0700 dir below — this
    // just guarantees collision-free staging.
    static const std::uint64_t base = [] {
        std::random_device rd;
        return (static_cast<std::uint64_t>(rd()) << 32) ^ rd();
    }();
    static std::atomic<std::uint64_t> counter{0};
    std::uint64_t v = base ^ counter.fetch_add(1, std::memory_order_relaxed);
    std::string s;
    for (int j = 0; j < 16; ++j) {
        s += kHex[v & 0xF];
        v >>= 4;
    }
    return s;
}

// Atomic write of an owner-readable PUBLIC artifact (leaf / chain): stage to a
// sibling temp, then rename. Default perms are fine — these are not secrets.
bool write_public_file(const fs::path& dest, const std::string& contents) {
    std::error_code ec;
    const fs::path tmp = dest.parent_path() / (dest.filename().string() + ".tmp." + random_suffix());
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) {
            spdlog::error("agent_csr: cannot open temp {}", tmp.string());
            return false;
        }
        out.write(contents.data(), static_cast<std::streamsize>(contents.size()));
        out.flush();
        if (!out) {
            spdlog::error("agent_csr: write failed for {}", tmp.string());
            out.close();
            fs::remove(tmp, ec);
            return false;
        }
    }
    fs::rename(tmp, dest, ec);
    if (ec) {
        spdlog::error("agent_csr: rename {} -> {} failed: {}", tmp.string(), dest.string(),
                      ec.message());
        fs::remove(tmp, ec);
        return false;
    }
    return true;
}

// Atomic write of the PRIVATE key at mode 0600 (mirrors FileKeyProvider): the
// POSIX path creates the temp 0600 from the outset (no umask window), the Windows
// path uses ofstream + a best-effort permissions tightening (owner-only DACL is a
// documented follow-up, same as the server key-write path).
bool write_private_key(const fs::path& dest, const std::string& contents) {
    std::error_code ec;
    const fs::path tmp = dest.parent_path() / (dest.filename().string() + ".tmp." + random_suffix());
#ifndef _WIN32
    {
        // O_EXCL refuses to reuse an attacker-planted path; O_NOFOLLOW additionally
        // refuses to open it if the final component is a symlink (defence in depth
        // for the key write — the cert dir is already 0700/owner-only above).
        const int fd =
            ::open(tmp.c_str(), O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (fd < 0) {
            spdlog::error("agent_csr: open temp {} failed: {}", tmp.string(), std::strerror(errno));
            return false;
        }
        const char* p = contents.data();
        std::size_t remaining = contents.size();
        bool ok = true;
        while (remaining > 0) {
            const ssize_t n = ::write(fd, p, remaining);
            if (n < 0) {
                if (errno == EINTR)
                    continue; // interrupted before any byte written — retry
                ok = false;
                break;
            }
            if (n == 0) {
                ok = false;
                break;
            }
            p += n;
            remaining -= static_cast<std::size_t>(n);
        }
        if (::close(fd) != 0)
            ok = false;
        if (!ok) {
            spdlog::error("agent_csr: write failed for {}", tmp.string());
            fs::remove(tmp, ec);
            return false;
        }
    }
#else
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) {
            spdlog::error("agent_csr: cannot open temp {}", tmp.string());
            return false;
        }
        out.write(contents.data(), static_cast<std::streamsize>(contents.size()));
        out.flush();
        if (!out) {
            spdlog::error("agent_csr: write failed for {}", tmp.string());
            out.close();
            fs::remove(tmp, ec);
            return false;
        }
    }
#endif
    fs::permissions(tmp, fs::perms::owner_read | fs::perms::owner_write,
                    fs::perm_options::replace, ec); // re-assert 0600
    fs::rename(tmp, dest, ec);
    if (ec) {
        spdlog::error("agent_csr: rename {} -> {} failed: {}", tmp.string(), dest.string(),
                      ec.message());
        fs::remove(tmp, ec);
        return false;
    }
    fs::permissions(dest, fs::perms::owner_read | fs::perms::owner_write,
                    fs::perm_options::replace, ec); // re-assert after rename
    return true;
}

} // namespace

std::optional<KeyAndCsr> generate_key_and_csr(const std::string& agent_id) {
    EVP_PKEY_ptr key{EVP_EC_gen("P-256")};
    if (!key) {
        log_ssl_errors("generate_key_and_csr EVP_EC_gen");
        return std::nullopt;
    }
    auto key_pem = to_pem(
        [&](BIO* b) {
            return PEM_write_bio_PrivateKey(b, key.get(), nullptr, nullptr, 0, nullptr, nullptr);
        },
        "generate_key_and_csr key to_pem");
    if (!key_pem)
        return std::nullopt;

    X509_REQ_ptr req{X509_REQ_new()};
    if (!req || X509_REQ_set_version(req.get(), 0) != 1) {
        log_ssl_errors("generate_key_and_csr req new");
        return std::nullopt;
    }
    X509_NAME_ptr name{X509_NAME_new()};
    if (!name) {
        log_ssl_errors("generate_key_and_csr name new");
        return std::nullopt;
    }
    // O=Yuzu Agent, CN=<agent_id>. Explicit byte lengths (not strlen) so an
    // embedded NUL in a future agent_id can't silently truncate the DN.
    static constexpr char kOrg[] = "Yuzu Agent";
    if (X509_NAME_add_entry_by_txt(name.get(), "O", MBSTRING_UTF8,
                                   reinterpret_cast<const unsigned char*>(kOrg),
                                   static_cast<int>(sizeof(kOrg) - 1), -1, 0) != 1) {
        log_ssl_errors("generate_key_and_csr name O");
        return std::nullopt;
    }
    if (!agent_id.empty() &&
        X509_NAME_add_entry_by_txt(name.get(), "CN", MBSTRING_UTF8,
                                   reinterpret_cast<const unsigned char*>(agent_id.data()),
                                   static_cast<int>(agent_id.size()), -1, 0) != 1) {
        log_ssl_errors("generate_key_and_csr name CN");
        return std::nullopt;
    }
    if (X509_REQ_set_subject_name(req.get(), name.get()) != 1) {
        log_ssl_errors("generate_key_and_csr set subject");
        return std::nullopt;
    }
    if (X509_REQ_set_pubkey(req.get(), key.get()) != 1) {
        log_ssl_errors("generate_key_and_csr set pubkey");
        return std::nullopt;
    }
    // P-256 → SHA-256 (ECDSA pairs the digest to the curve size).
    if (X509_REQ_sign(req.get(), key.get(), EVP_sha256()) == 0) {
        log_ssl_errors("generate_key_and_csr sign");
        return std::nullopt;
    }
    auto csr_pem =
        to_pem([&](BIO* b) { return PEM_write_bio_X509_REQ(b, req.get()); },
               "generate_key_and_csr csr to_pem");
    if (!csr_pem)
        return std::nullopt;

    return KeyAndCsr{std::move(*key_pem), std::move(*csr_pem)};
}

ProvisionedCertPaths provisioned_cert_paths(const fs::path& cert_dir) {
    return ProvisionedCertPaths{.key_path = cert_dir / "agent-client.key",
                                .cert_path = cert_dir / "agent-client.pem",
                                .ca_path = cert_dir / "agent-ca.pem"};
}

bool persist_provisioned_cert(const fs::path& cert_dir, const std::string& key_pem,
                              const std::string& leaf_pem, const std::string& ca_chain_pem) {
    if (key_pem.empty() || leaf_pem.empty()) {
        spdlog::error("agent_csr: refusing to persist an empty key or leaf");
        return false;
    }
    std::error_code ec;
    fs::create_directories(cert_dir, ec);
    if (ec) {
        spdlog::error("agent_csr: cannot create {}: {}", cert_dir.string(), ec.message());
        return false;
    }
    fs::permissions(cert_dir, fs::perms::owner_all, fs::perm_options::replace, ec); // 0700

    const auto paths = provisioned_cert_paths(cert_dir);
    // Key first (the secret), then the public artifacts. A crash between writes
    // leaves the leaf missing → inspect() reports Missing → clean re-enroll.
    if (!write_private_key(paths.key_path, key_pem))
        return false;
    if (!write_public_file(paths.cert_path, leaf_pem))
        return false;
    if (!ca_chain_pem.empty() && !write_public_file(paths.ca_path, ca_chain_pem))
        return false;
    spdlog::info("agent_csr: provisioned per-agent client certificate under {}", cert_dir.string());
    return true;
}

CertState inspect_provisioned_cert(const fs::path& cert_dir,
                                   std::chrono::system_clock::time_point now) {
    const auto paths = provisioned_cert_paths(cert_dir);
    std::error_code ec;
    if (!fs::exists(paths.cert_path, ec) || !fs::exists(paths.key_path, ec))
        return CertState::Missing;
    const std::string leaf = read_text_file(paths.cert_path);
    if (leaf.empty())
        return CertState::Missing;
    X509_ptr cert = load_cert(leaf);
    if (!cert)
        return CertState::Missing;
    auto nb = from_asn1_time(X509_get0_notBefore(cert.get()));
    auto na = from_asn1_time(X509_get0_notAfter(cert.get()));
    if (!nb || !na || *na <= *nb)
        return CertState::Missing;
    if (now >= *na)
        return CertState::Expired;
    // Renew once two-thirds of the validity window has elapsed (renew-ahead).
    const auto renew_at = *nb + ((*na - *nb) * 2) / 3;
    if (now >= renew_at)
        return CertState::NeedsRenew;
    return CertState::Valid;
}

} // namespace yuzu::agent
