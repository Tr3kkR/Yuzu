#include "secret_codec.hpp"

#include "../aes_gcm.hpp"
#include "pg_migration_runner.hpp"
#include "pg_raii.hpp"

#include <openssl/rand.h>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <cstring>

namespace yuzu::server::pg {

namespace {

// Same first advisory-lock key as PgMigrationRunner (cluster-wide "yuzu"
// namespace); constant second key scoped to KEK bootstrap/rotation so two
// server processes first-booting against one database serialize here and the
// loser sees the winner's fingerprint row (the ADR-0010 §2 dual-server rule
// fails loudly instead of minting two independent v1 KEKs).
constexpr const char* kKekLockSql =
    "SELECT pg_advisory_xact_lock(2037545589, hashtext('secrets_kek'::text))";

constexpr std::string_view kKekIdPrefix = "secrets-kek-v";

std::string kek_key_id(std::uint32_t version) {
    return std::string{kKekIdPrefix} + std::to_string(version);
}

bool exec_ok(PGconn* conn, const char* sql, std::string_view what) {
    PgResult res{PQexec(conn, sql)};
    if (!res.ok()) {
        spdlog::error("secret_codec: {} failed: {}", what, PQerrorMessage(conn));
        return false;
    }
    return true;
}

void put_u32_be(std::uint8_t* out, std::uint32_t v) {
    out[0] = static_cast<std::uint8_t>(v >> 24);
    out[1] = static_cast<std::uint8_t>(v >> 16);
    out[2] = static_cast<std::uint8_t>(v >> 8);
    out[3] = static_cast<std::uint8_t>(v);
}

std::uint32_t get_u32_be(const std::uint8_t* p) {
    return (static_cast<std::uint32_t>(p[0]) << 24) | (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) | static_cast<std::uint32_t>(p[3]);
}

/// Canonical AAD field append: u32-BE length prefix, then the bytes
/// (ADR-0010 §1 "Canonical AAD serialization" — naive concatenation is
/// ambiguous, which is exactly the swap class AAD exists to defeat).
void append_field(std::vector<std::uint8_t>& aad, std::span<const std::uint8_t> field) {
    std::array<std::uint8_t, 4> len{};
    put_u32_be(len.data(), static_cast<std::uint32_t>(field.size()));
    aad.insert(aad.end(), len.begin(), len.end());
    aad.insert(aad.end(), field.begin(), field.end());
}

void append_field(std::vector<std::uint8_t>& aad, std::string_view field) {
    append_field(aad, std::span<const std::uint8_t>{
                          reinterpret_cast<const std::uint8_t*>(field.data()), field.size()});
}

/// Payload AAD: (ver, store, table, column, row_pk) — deliberately WITHOUT
/// kek_version, so re-wrap-only rotation never invalidates payload tags
/// (the #1333 HIGH-1 rotation-bricking bug class).
std::vector<std::uint8_t> payload_aad(const SecretCodec::SecretId& id) {
    std::vector<std::uint8_t> aad;
    aad.reserve(5 * 4 + 1 + id.store.size() + id.table.size() + id.column.size() +
                id.row_pk.size());
    const std::uint8_t ver = SecretCodec::kBlobVersion;
    append_field(aad, std::span<const std::uint8_t>{&ver, 1});
    append_field(aad, id.store);
    append_field(aad, id.table);
    append_field(aad, id.column);
    append_field(aad, id.row_pk);
    return aad;
}

/// Wrap AAD: the payload tuple PLUS kek_version — its 4 bytes byte-identical
/// to the blob's field, so a tampered blob kek_version fails the wrap tag.
std::vector<std::uint8_t> wrap_aad(const SecretCodec::SecretId& id, std::uint32_t kek_version) {
    std::vector<std::uint8_t> aad = payload_aad(id);
    std::array<std::uint8_t, 4> ver_be{};
    put_u32_be(ver_be.data(), kek_version);
    append_field(aad, std::span<const std::uint8_t>{ver_be});
    return aad;
}

std::string to_hex(std::span<const std::uint8_t> bytes) {
    static const char* kHex = "0123456789abcdef";
    std::string s;
    s.reserve(bytes.size() * 2);
    for (std::uint8_t b : bytes) {
        s += kHex[b >> 4];
        s += kHex[b & 0xF];
    }
    return s;
}

std::optional<std::vector<std::uint8_t>> from_hex(std::string_view hex) {
    if (hex.size() % 2 != 0)
        return std::nullopt;
    const auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
            return c - 'A' + 10;
        return -1;
    };
    std::vector<std::uint8_t> out;
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        const int hi = nibble(hex[i]);
        const int lo = nibble(hex[i + 1]);
        if (hi < 0 || lo < 0)
            return std::nullopt;
        out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return out;
}

/// Parsed view over a v1 blob (borrows; caller keeps the bytes alive).
struct BlobView {
    std::uint32_t kek_version;
    WrappedDek wrapped;
    std::span<const std::uint8_t> data_nonce; // 12
    std::span<const std::uint8_t> data_tag;   // 16
    std::span<const std::uint8_t> ciphertext;
};

std::optional<BlobView> parse_blob(std::span<const std::uint8_t> blob) {
    // Reject below the fixed minimum BEFORE slicing (ADR §1).
    if (blob.size() < SecretCodec::kMinBlobSize)
        return std::nullopt;
    if (blob[0] != SecretCodec::kBlobVersion)
        return std::nullopt;
    BlobView v{};
    v.kek_version = get_u32_be(blob.data() + SecretCodec::kKekVersionOffset);
    std::memcpy(v.wrapped.nonce.data(), blob.data() + SecretCodec::kWrapNonceOffset, 12);
    std::memcpy(v.wrapped.wrapped.data(), blob.data() + SecretCodec::kWrappedDekOffset, 32);
    std::memcpy(v.wrapped.tag.data(), blob.data() + SecretCodec::kWrapTagOffset, 16);
    v.data_nonce = blob.subspan(SecretCodec::kDataNonceOffset, 12);
    v.data_tag = blob.subspan(SecretCodec::kDataTagOffset, 16);
    v.ciphertext = blob.subspan(SecretCodec::kCiphertextOffset);
    return v;
}

/// Quoted, dot-joined relation name from pre-validated identifiers.
std::string rel_name(const SecretCodec::SecretColumn& c) {
    return "\"" + c.store + "\".\"" + c.table + "\"";
}

} // namespace

std::string_view SecretCodec::to_string(FailureClass cls) {
    switch (cls) {
    case FailureClass::tag_mismatch:
        return "tag_mismatch";
    case FailureClass::kek_unresolvable:
        return "kek_unresolvable";
    case FailureClass::malformed_blob:
        return "malformed_blob";
    case FailureClass::crypto_failure:
        return "crypto_failure";
    }
    return "unknown";
}

std::string SecretCodec::encode_bigint_pk(std::int64_t pk) {
    std::array<std::uint8_t, 8> be{};
    const auto u = static_cast<std::uint64_t>(pk);
    for (int i = 0; i < 8; ++i)
        be[static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(u >> (56 - 8 * i));
    return {reinterpret_cast<const char*>(be.data()), be.size()};
}

SecretCodec::SecretCodec(KeyProvider& provider) : provider_(provider) {}

void SecretCodec::set_audit_hook(AuditHook hook) {
    std::lock_guard lock{mu_};
    audit_hook_ = std::move(hook);
}

void SecretCodec::emit_audit(std::string_view verb, const std::string& detail_json) {
    AuditHook hook;
    {
        std::lock_guard lock{mu_};
        hook = audit_hook_;
    }
    if (hook)
        hook(verb, detail_json);
}

std::uint32_t SecretCodec::active_kek_version() const {
    std::lock_guard lock{mu_};
    return active_version_;
}

bool SecretCodec::register_secret_column(SecretColumn col) {
    const auto valid = PgMigrationRunner::valid_store_name;
    if (!valid(col.store) || !valid(col.table) || !valid(col.column) || !valid(col.pk_column)) {
        spdlog::error("secret_codec: rejected secret-column registration with invalid "
                      "identifier(s): {}.{}.{} pk={}",
                      col.store, col.table, col.column, col.pk_column);
        return false;
    }
    std::lock_guard lock{mu_};
    columns_.push_back(std::move(col));
    return true;
}

SecretCodec::Error SecretCodec::fail(const SecretId& id, FailureClass cls,
                                     std::uint32_t kek_version, std::string_view what) {
    {
        std::lock_guard lock{mu_};
        ++failure_counts_[{id.store, cls}];
    }
    // Identifiers only — the AAD tuple coordinates and version; never
    // ciphertext, plaintext, DEK, or key bytes (ADR-0010 §1).
    nlohmann::json detail{
        {"store", id.store},
        {"table", id.table},
        {"column", id.column},
        {"row_pk_hex",
         to_hex({reinterpret_cast<const std::uint8_t*>(id.row_pk.data()), id.row_pk.size()})},
        {"kek_version", kek_version},
        {"failure_class", to_string(cls)}};
    emit_audit("secret.decrypt_failure", detail.dump());
    Error err;
    err.cls = cls;
    err.message = std::string{to_string(cls)} + ": " + std::string{what} + " (" + id.store + "." +
                  id.table + "." + id.column + ")";
    spdlog::error("secret_codec: {}", err.message);
    return err;
}

std::expected<std::vector<std::uint8_t>, SecretCodec::Error>
SecretCodec::encrypt(const SecretId& id, std::span<const std::uint8_t> plaintext) {
    std::uint32_t version = 0;
    std::string key_ref;
    {
        std::lock_guard lock{mu_};
        version = active_version_;
        if (auto it = key_refs_.find(version); it != key_refs_.end())
            key_ref = it->second;
    }
    if (version == 0 || key_ref.empty())
        return std::unexpected{fail(id, FailureClass::kek_unresolvable, version,
                                    "no active KEK (init() not run or failed)")};

    // Fresh DEK + fresh data nonce per value per encryption (ADR §1).
    SecureBuffer dek{32};
    std::array<std::uint8_t, 12> data_nonce{};
    if (RAND_bytes(dek.data(), static_cast<int>(dek.size())) != 1 ||
        RAND_bytes(data_nonce.data(), static_cast<int>(data_nonce.size())) != 1)
        return std::unexpected{
            fail(id, FailureClass::crypto_failure, version, "RAND_bytes failed minting DEK/nonce")};

    std::vector<std::uint8_t> blob(kCiphertextOffset + plaintext.size());
    blob[0] = kBlobVersion;
    put_u32_be(blob.data() + kKekVersionOffset, version);

    std::array<std::uint8_t, 16> data_tag{};
    const auto aad = payload_aad(id);
    const auto rc = detail::aes256gcm_encrypt(std::span<const std::uint8_t, 32>{dek.data(), 32},
                                              std::span<const std::uint8_t, 12>{data_nonce}, aad,
                                              plaintext, blob.data() + kCiphertextOffset,
                                              std::span<std::uint8_t, 16>{data_tag});
    if (rc != detail::GcmResult::ok)
        return std::unexpected{
            fail(id, FailureClass::crypto_failure, version, "payload encrypt failed (EVP)")};

    const auto wrapped = provider_.wrap_dek(
        key_ref, std::span<const std::uint8_t, 32>{dek.data(), 32}, wrap_aad(id, version));
    if (!wrapped) {
        const FailureClass cls = wrapped.error() == KekError::unresolvable
                                     ? FailureClass::kek_unresolvable
                                     : FailureClass::crypto_failure;
        return std::unexpected{fail(id, cls, version, "DEK wrap failed")};
    }

    std::memcpy(blob.data() + kWrapNonceOffset, wrapped->nonce.data(), 12);
    std::memcpy(blob.data() + kWrappedDekOffset, wrapped->wrapped.data(), 32);
    std::memcpy(blob.data() + kWrapTagOffset, wrapped->tag.data(), 16);
    std::memcpy(blob.data() + kDataNonceOffset, data_nonce.data(), 12);
    std::memcpy(blob.data() + kDataTagOffset, data_tag.data(), 16);
    return blob;
}

std::expected<SecureBuffer, SecretCodec::Error>
SecretCodec::decrypt(const SecretId& id, std::span<const std::uint8_t> blob) {
    const auto view = parse_blob(blob);
    if (!view)
        return std::unexpected{fail(id, FailureClass::malformed_blob, 0,
                                    "blob below minimum size or unknown version byte")};

    std::string key_ref;
    {
        std::lock_guard lock{mu_};
        if (auto it = key_refs_.find(view->kek_version); it != key_refs_.end())
            key_ref = it->second;
    }
    if (key_ref.empty())
        return std::unexpected{fail(id, FailureClass::kek_unresolvable, view->kek_version,
                                    "blob references unregistered/retired KEK version")};

    auto dek = provider_.unwrap_dek(key_ref, view->wrapped, wrap_aad(id, view->kek_version));
    if (!dek) {
        switch (dek.error()) {
        case KekError::tag_mismatch:
            return std::unexpected{fail(id, FailureClass::tag_mismatch, view->kek_version,
                                        "wrap-layer tag check failed (tampered blob field, "
                                        "swapped row/column, or wrong KEK)")};
        case KekError::unresolvable:
            return std::unexpected{
                fail(id, FailureClass::kek_unresolvable, view->kek_version, "KEK unresolvable")};
        case KekError::crypto_failure:
        default:
            return std::unexpected{
                fail(id, FailureClass::crypto_failure, view->kek_version, "DEK unwrap failed")};
        }
    }

    SecureBuffer plaintext{view->ciphertext.size()};
    const auto aad = payload_aad(id);
    std::array<std::uint8_t, 12> nonce{};
    std::array<std::uint8_t, 16> tag{};
    std::memcpy(nonce.data(), view->data_nonce.data(), nonce.size());
    std::memcpy(tag.data(), view->data_tag.data(), tag.size());
    const auto rc =
        detail::aes256gcm_decrypt(std::span<const std::uint8_t, 32>{dek->data(), 32},
                                  std::span<const std::uint8_t, 12>{nonce}, aad, view->ciphertext,
                                  std::span<const std::uint8_t, 16>{tag}, plaintext.data());
    if (rc == detail::GcmResult::auth_failed)
        return std::unexpected{fail(id, FailureClass::tag_mismatch, view->kek_version,
                                    "payload tag check failed (tampered ciphertext or "
                                    "swapped identity)")};
    if (rc != detail::GcmResult::ok)
        return std::unexpected{
            fail(id, FailureClass::crypto_failure, view->kek_version, "payload decrypt failed")};
    return plaintext;
}

std::expected<std::vector<std::uint8_t>, SecretCodec::Error>
SecretCodec::rewrap(const SecretId& id, std::span<const std::uint8_t> blob,
                    std::uint32_t to_version) {
    const auto view = parse_blob(blob);
    if (!view)
        return std::unexpected{fail(id, FailureClass::malformed_blob, 0,
                                    "blob below minimum size or unknown version byte")};
    if (view->kek_version == to_version)
        return std::vector<std::uint8_t>{blob.begin(), blob.end()};

    std::string from_ref;
    std::string to_ref;
    {
        std::lock_guard lock{mu_};
        if (auto it = key_refs_.find(view->kek_version); it != key_refs_.end())
            from_ref = it->second;
        if (auto it = key_refs_.find(to_version); it != key_refs_.end())
            to_ref = it->second;
    }
    if (from_ref.empty())
        return std::unexpected{fail(id, FailureClass::kek_unresolvable, view->kek_version,
                                    "source KEK version unresolvable")};
    if (to_ref.empty())
        return std::unexpected{fail(id, FailureClass::kek_unresolvable, to_version,
                                    "target KEK version unresolvable")};

    auto dek = provider_.unwrap_dek(from_ref, view->wrapped, wrap_aad(id, view->kek_version));
    if (!dek) {
        const FailureClass cls =
            dek.error() == KekError::tag_mismatch
                ? FailureClass::tag_mismatch
                : (dek.error() == KekError::unresolvable ? FailureClass::kek_unresolvable
                                                         : FailureClass::crypto_failure);
        return std::unexpected{fail(id, cls, view->kek_version, "DEK unwrap failed during rewrap")};
    }
    const auto rewrapped = provider_.wrap_dek(
        to_ref, std::span<const std::uint8_t, 32>{dek->data(), 32}, wrap_aad(id, to_version));
    if (!rewrapped)
        return std::unexpected{
            fail(id, FailureClass::crypto_failure, to_version, "DEK re-wrap failed")};

    // New header + wrap fields; payload section copied VERBATIM — rotation
    // must never touch data_nonce/data_tag/ciphertext (ADR §1/§3; the
    // fjarvis #1333 reproduction pins this).
    std::vector<std::uint8_t> out{blob.begin(), blob.end()};
    put_u32_be(out.data() + kKekVersionOffset, to_version);
    std::memcpy(out.data() + kWrapNonceOffset, rewrapped->nonce.data(), 12);
    std::memcpy(out.data() + kWrappedDekOffset, rewrapped->wrapped.data(), 32);
    std::memcpy(out.data() + kWrapTagOffset, rewrapped->tag.data(), 16);
    return out;
}

std::expected<void, std::string> SecretCodec::init(PGconn* conn) {
    static const std::vector<PgMigration> kMigrations = {
        {1, "CREATE TABLE kek_meta ("
            "  kek_version BIGINT PRIMARY KEY,"
            "  kcv         BYTEA NOT NULL,"
            "  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),"
            "  retired_at  TIMESTAMPTZ"
            ")"},
    };
    if (!PgMigrationRunner::run(conn, "secrets", kMigrations))
        return std::unexpected{"secrets schema migration failed"};

    if (!exec_ok(conn, "BEGIN", "BEGIN (kek init)"))
        return std::unexpected{"kek init: BEGIN failed"};
    PgTxn txn{conn};
    {
        PgResult lock{PQexec(conn, kKekLockSql)};
        if (lock.status() != PGRES_TUPLES_OK)
            return std::unexpected{std::string{"kek init: advisory lock failed: "} +
                                   PQerrorMessage(conn)};
    }

    PgResult rows{PQexec(conn, "SELECT kek_version, encode(kcv, 'hex'),"
                               "       (retired_at IS NOT NULL)::int"
                               " FROM secrets.kek_meta ORDER BY kek_version")};
    if (rows.status() != PGRES_TUPLES_OK)
        return std::unexpected{std::string{"kek init: kek_meta read failed: "} +
                               PQerrorMessage(conn)};

    std::map<std::uint32_t, std::string> refs;
    std::uint32_t max_live = 0;

    const int n = PQntuples(rows.get());
    if (n == 0) {
        // First boot. Adopt-or-generate: a crash between KEK-file write and
        // the fingerprint INSERT leaves a valid fsynced key file with no
        // meta row — nothing can have been encrypted under it (encrypt
        // requires init() success), so adopting it is safe and refusing
        // would wedge boot forever.
        const std::string key_id = kek_key_id(1);
        std::optional<std::string> ref = provider_.resolve_kek(key_id);
        if (ref) {
            spdlog::warn("secret_codec: adopting existing un-registered KEK '{}' "
                         "(crashed first boot?)",
                         key_id);
        } else {
            ref = provider_.generate_kek(key_id);
            if (!ref)
                return std::unexpected{
                    "kek init: KEK generation failed (CSPRNG or key storage) — refusing to start "
                    "without a secrets KEK"};
        }
        const auto kcv = provider_.kek_check_value(*ref);
        if (!kcv)
            return std::unexpected{"kek init: check-value computation failed for new KEK"};

        const std::string kcv_hex = to_hex(std::span<const std::uint8_t>{*kcv});
        const char* values[] = {kcv_hex.c_str()};
        PgResult ins{PQexecParams(conn,
                                  "INSERT INTO secrets.kek_meta (kek_version, kcv)"
                                  " VALUES (1, decode($1, 'hex'))",
                                  1, nullptr, values, nullptr, nullptr, 0)};
        if (!ins.ok())
            return std::unexpected{std::string{"kek init: fingerprint INSERT failed: "} +
                                   PQerrorMessage(conn)};
        if (!txn.commit())
            return std::unexpected{"kek init: COMMIT failed"};

        {
            std::lock_guard lock{mu_};
            key_refs_ = {{1, *ref}};
            active_version_ = 1;
        }
        emit_audit("kek.generated", nlohmann::json{{"kek_version", 1}}.dump());
        spdlog::info("secret_codec: generated and registered secrets-kek-v1");
        return {};
    }

    // Boot verification (ADR §2): every registered, non-retired version must
    // resolve through the provider to material matching its fingerprint.
    for (int i = 0; i < n; ++i) {
        const auto version = static_cast<std::uint32_t>(std::atoll(PQgetvalue(rows.get(), i, 0)));
        const std::string kcv_hex = PQgetvalue(rows.get(), i, 1);
        const bool retired = std::strcmp(PQgetvalue(rows.get(), i, 2), "1") == 0;
        if (retired)
            continue;

        const std::string key_id = kek_key_id(version);
        const auto ref = provider_.resolve_kek(key_id);
        if (!ref)
            return std::unexpected{
                "kek_unresolvable: registered KEK '" + key_id +
                "' does not resolve through the KeyProvider. Causes: keys directory older than "
                "the database (backup skew — restore DB and keys dir as a PAIR), wrong keys "
                "directory, or a second server instance sharing this database (one KEK per "
                "database; see ADR-0010 §2)"};

        const auto kcv = provider_.kek_check_value(*ref);
        const auto expected = from_hex(kcv_hex);
        if (!kcv || !expected || expected->size() != kcv->size() ||
            !std::equal(kcv->begin(), kcv->end(), expected->begin()))
            return std::unexpected{
                "kek_corrupt: KEK '" + key_id +
                "' resolves but its check value does not match the registered fingerprint "
                "(torn/corrupt key file or foreign key material — NOT row tamper). Restore the "
                "keys directory from the backup paired with this database"};

        refs.emplace(version, *ref);
        max_live = std::max(max_live, version);
    }

    if (max_live == 0)
        return std::unexpected{"kek init: kek_meta has rows but no live (non-retired) KEK version"};

    if (!txn.commit())
        return std::unexpected{"kek init: COMMIT failed"};

    {
        std::lock_guard lock{mu_};
        key_refs_ = std::move(refs);
        active_version_ = max_live;
    }
    spdlog::info("secret_codec: verified {} registered KEK version(s); active v{}",
                 key_refs_.size(), max_live);
    return {};
}

std::expected<std::uint32_t, std::string> SecretCodec::rotate_kek(PGconn* conn) {
    std::uint32_t cur = 0;
    {
        std::lock_guard lock{mu_};
        cur = active_version_;
    }
    if (cur == 0)
        return std::unexpected{"rotate: init() has not run"};

    const std::uint32_t next = cur + 1;
    const std::string key_id = kek_key_id(next);
    const auto ref = provider_.generate_kek(key_id);
    if (!ref)
        return std::unexpected{"rotate: KEK generation failed for " + key_id};
    const auto kcv = provider_.kek_check_value(*ref);
    if (!kcv)
        return std::unexpected{"rotate: check-value computation failed for " + key_id};

    const std::string kcv_hex = to_hex(std::span<const std::uint8_t>{*kcv});
    const std::string version_str = std::to_string(next);
    const char* values[] = {version_str.c_str(), kcv_hex.c_str()};
    PgResult ins{PQexecParams(conn,
                              "INSERT INTO secrets.kek_meta (kek_version, kcv)"
                              " VALUES ($1::bigint, decode($2, 'hex'))"
                              " ON CONFLICT (kek_version) DO NOTHING",
                              2, nullptr, values, nullptr, nullptr, 0)};
    if (!ins.ok())
        return std::unexpected{std::string{"rotate: fingerprint INSERT failed: "} +
                               PQerrorMessage(conn)};
    if (std::strcmp(PQcmdTuples(ins.get()), "1") != 0) {
        // A concurrent rotation registered this version first. Our freshly
        // minted key file is an orphan with a non-matching fingerprint —
        // remove it or the next boot verification fails as kek_corrupt.
        (void)provider_.delete_key(*ref);
        return std::unexpected{"rotate: concurrent rotation detected for " + key_id +
                               " — re-run rotation"};
    }

    {
        std::lock_guard lock{mu_};
        key_refs_.emplace(next, *ref);
        active_version_ = next;
    }
    emit_audit("kek.rotated", nlohmann::json{{"kek_version", next}}.dump());
    spdlog::info("secret_codec: rotated to secrets-kek-v{}; re-wrapping stored DEKs", next);

    const auto rewrapped = rewrap_all(conn);
    if (!rewrapped)
        return std::unexpected{"rotate: minted v" + std::to_string(next) +
                               " but rewrap_all failed (" + rewrapped.error() +
                               ") — resume with rewrap_all(); completion signal is "
                               "oldest_kek_version_in_use()"};
    return next;
}

std::expected<std::size_t, std::string> SecretCodec::rewrap_all(PGconn* conn) {
    std::uint32_t target = 0;
    std::vector<SecretColumn> columns;
    {
        std::lock_guard lock{mu_};
        target = active_version_;
        columns = columns_;
    }
    if (target == 0)
        return std::unexpected{"rewrap_all: init() has not run"};

    std::size_t rewrapped_count = 0;
    std::size_t cas_skipped = 0;
    for (const auto& col : columns) {
        const std::string select = "SELECT \"" + col.pk_column + "\", \"" + col.column +
                                   "\" FROM " + rel_name(col) + " WHERE \"" + col.column +
                                   "\" IS NOT NULL";
        // Binary results: bytea arrives raw, BIGINT pks arrive as exactly
        // the canonical 8-byte-BE encoding the AAD uses.
        PgResult rows{PQexecParams(conn, select.c_str(), 0, nullptr, nullptr, nullptr, nullptr, 1)};
        if (rows.status() != PGRES_TUPLES_OK)
            return std::unexpected{"rewrap_all: scan of " + rel_name(col) +
                                   " failed: " + PQerrorMessage(conn)};

        const int n = PQntuples(rows.get());
        for (int i = 0; i < n; ++i) {
            const auto* pk_p = reinterpret_cast<const std::uint8_t*>(PQgetvalue(rows.get(), i, 0));
            const int pk_len = PQgetlength(rows.get(), i, 0);
            const auto* blob_p =
                reinterpret_cast<const std::uint8_t*>(PQgetvalue(rows.get(), i, 1));
            const int blob_len = PQgetlength(rows.get(), i, 1);
            const std::span<const std::uint8_t> blob{blob_p, static_cast<std::size_t>(blob_len)};

            if (blob.size() >= kMinBlobSize &&
                get_u32_be(blob.data() + kKekVersionOffset) == target)
                continue; // already on the active version (resume-safe)

            SecretId id{
                col.store, col.table, col.column,
                std::string{reinterpret_cast<const char*>(pk_p), static_cast<std::size_t>(pk_len)}};
            auto new_blob = rewrap(id, blob, target);
            if (!new_blob)
                return std::unexpected{"rewrap_all: rewrap failed for a row of " + rel_name(col) +
                                       ": " + new_blob.error().message};

            // Compare-and-swap (ADR §3): a plain write would silently revert
            // a concurrent operator secret-update to the old value.
            const std::string update = "UPDATE " + rel_name(col) + " SET \"" + col.column +
                                       "\" = $1 WHERE \"" + col.pk_column + "\" = $2 AND \"" +
                                       col.column + "\" = $3";
            const char* values[] = {reinterpret_cast<const char*>(new_blob->data()),
                                    reinterpret_cast<const char*>(pk_p),
                                    reinterpret_cast<const char*>(blob_p)};
            const int lengths[] = {static_cast<int>(new_blob->size()), pk_len, blob_len};
            const int formats[] = {1, 1, 1};
            PgResult upd{
                PQexecParams(conn, update.c_str(), 3, nullptr, values, lengths, formats, 0)};
            if (!upd.ok())
                return std::unexpected{"rewrap_all: CAS update on " + rel_name(col) +
                                       " failed: " + PQerrorMessage(conn)};
            if (std::strcmp(PQcmdTuples(upd.get()), "1") == 0)
                ++rewrapped_count;
            else
                ++cas_skipped; // concurrent writer re-encrypted under the active version
        }
    }
    if (cas_skipped > 0)
        spdlog::info("secret_codec: rewrap_all skipped {} row(s) updated concurrently",
                     cas_skipped);
    spdlog::info("secret_codec: rewrap_all re-wrapped {} row(s) to v{}", rewrapped_count, target);
    return rewrapped_count;
}

std::expected<std::optional<std::uint32_t>, std::string>
SecretCodec::oldest_kek_version_in_use(PGconn* conn) {
    std::vector<SecretColumn> columns;
    {
        std::lock_guard lock{mu_};
        columns = columns_;
    }
    std::optional<std::uint32_t> oldest;
    for (const auto& col : columns) {
        // Header scan: kek_version sits at a fixed offset (bytes 2..5,
        // 1-based) so "find rows wrapped under v<N>" never reads payloads.
        const std::string sql = "SELECT substring(\"" + col.column + "\" from 2 for 4) FROM " +
                                rel_name(col) + " WHERE \"" + col.column + "\" IS NOT NULL";
        PgResult rows{PQexecParams(conn, sql.c_str(), 0, nullptr, nullptr, nullptr, nullptr, 1)};
        if (rows.status() != PGRES_TUPLES_OK)
            return std::unexpected{"oldest_kek_version_in_use: scan of " + rel_name(col) +
                                   " failed: " + PQerrorMessage(conn)};
        const int n = PQntuples(rows.get());
        for (int i = 0; i < n; ++i) {
            if (PQgetlength(rows.get(), i, 0) != 4)
                continue; // shorter-than-header garbage; decrypt will report it
            const auto v =
                get_u32_be(reinterpret_cast<const std::uint8_t*>(PQgetvalue(rows.get(), i, 0)));
            if (!oldest || v < *oldest)
                oldest = v;
        }
    }
    return oldest;
}

std::expected<void, std::string> SecretCodec::retire_kek(PGconn* conn, std::uint32_t version) {
    {
        std::lock_guard lock{mu_};
        if (version == active_version_)
            return std::unexpected{"retire: refusing to retire the ACTIVE KEK version v" +
                                   std::to_string(version)};
        if (!key_refs_.contains(version))
            return std::unexpected{"retire: v" + std::to_string(version) +
                                   " is not a live registered KEK version"};
    }

    // Condition (a) (ADR §3): zero stored blobs may still reference it —
    // premature retirement is permanent, unrecoverable loss.
    std::vector<SecretColumn> columns;
    {
        std::lock_guard lock{mu_};
        columns = columns_;
    }
    std::array<std::uint8_t, 4> ver_be{};
    put_u32_be(ver_be.data(), version);
    for (const auto& col : columns) {
        const std::string sql = "SELECT count(*) FROM " + rel_name(col) + " WHERE \"" + col.column +
                                "\" IS NOT NULL AND substring(\"" + col.column +
                                "\" from 2 for 4) = $1";
        const char* values[] = {reinterpret_cast<const char*>(ver_be.data())};
        const int lengths[] = {4};
        const int formats[] = {1};
        PgResult res{PQexecParams(conn, sql.c_str(), 1, nullptr, values, lengths, formats, 0)};
        if (res.status() != PGRES_TUPLES_OK)
            return std::unexpected{"retire: reference scan of " + rel_name(col) +
                                   " failed: " + PQerrorMessage(conn)};
        if (PQntuples(res.get()) == 1 && std::atoll(PQgetvalue(res.get(), 0, 0)) > 0)
            return std::unexpected{"retire: refusing — " + rel_name(col) +
                                   " still holds blob(s) wrapped under v" +
                                   std::to_string(version) +
                                   "; run rewrap_all() and confirm with "
                                   "oldest_kek_version_in_use() first"};
    }

    const std::string version_str = std::to_string(version);
    const char* values[] = {version_str.c_str()};
    PgResult upd{PQexecParams(conn,
                              "UPDATE secrets.kek_meta SET retired_at = now()"
                              " WHERE kek_version = $1::bigint AND retired_at IS NULL"
                              " RETURNING kek_version",
                              1, nullptr, values, nullptr, nullptr, 0)};
    if (upd.status() != PGRES_TUPLES_OK || PQntuples(upd.get()) != 1)
        return std::unexpected{std::string{"retire: kek_meta update failed: "} +
                               PQerrorMessage(conn)};

    std::string ref;
    {
        std::lock_guard lock{mu_};
        if (auto it = key_refs_.find(version); it != key_refs_.end()) {
            ref = it->second;
            key_refs_.erase(it);
        }
    }
    if (!ref.empty() && !provider_.delete_key(ref))
        spdlog::warn("secret_codec: retired v{} but key deletion failed — remove '{}' manually",
                     version, kek_key_id(version));

    emit_audit("kek.retired", nlohmann::json{{"kek_version", version}}.dump());
    spdlog::info("secret_codec: retired secrets-kek-v{} (destruction recorded in kek_meta)",
                 version);
    return {};
}

std::vector<std::pair<std::pair<std::string, SecretCodec::FailureClass>, std::uint64_t>>
SecretCodec::decrypt_failure_counts() const {
    std::lock_guard lock{mu_};
    return {failure_counts_.begin(), failure_counts_.end()};
}

} // namespace yuzu::server::pg
