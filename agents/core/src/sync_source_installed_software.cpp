#include "sync_source_installed_software.hpp"

#include "local_dispatcher.hpp"

#include <openssl/evp.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <chrono>
#include <optional>
#include <string_view>
#include <utility>

namespace yuzu::agent {

namespace {

// Must match the server seam's caps (inventory_ingestion.cpp) so the server's
// parse does not truncate/drop differently from what this source hashed.
constexpr std::size_t kMaxEntries = 20000;
constexpr std::size_t kMaxFieldLen = 1024;
// Total canonical-blob ceiling — MUST equal the server seam's kMaxBlobBytes
// (inventory_ingestion.cpp); the two are comment-coordinated. Deliberately set
// BELOW the gRPC default 4 MiB max-receive-message limit (no SetMaxReceiveMessageSize
// override exists on the agent channel, the server, or the gateway hop), with
// headroom for the InventoryReport's proto/map framing + content_hashes +
// collected_at on top of the blob. At 4 MiB the wire message would exceed the
// 4 MiB receive ceiling and the RPC would be rejected before the handler runs —
// a permanent tight retry loop (governance UP-6). A 3 MiB canonical blob is
// ~60k entries; no real machine reaches it, and an over-cap host is dropped
// (governance UP-4) rather than looping. Lowering this trades "outlier host
// skips" for "outlier host loops" — the right call for installed software.
constexpr std::size_t kMaxBlobBytes = 3u * 1024 * 1024;

std::string clamp_field(std::string_view f) {
    if (f.size() > kMaxFieldLen) {
        // Truncate on a UTF-8 codepoint boundary, never mid-sequence. A raw byte cut
        // at kMaxFieldLen can split a multibyte codepoint, producing invalid UTF-8
        // that PostgreSQL's TEXT column rejects (22021) → kError → need_full → the
        // agent resends the SAME poisoned blob forever (governance UP-10). Back up
        // over trailing continuation bytes (0b10xxxxxx) to the start of the codepoint
        // that would be cut. This logic MUST match the server's parse_software_blob
        // field clamp (inventory_ingestion.cpp) byte-for-byte, or the agent's and
        // server's canonical hashes diverge → permanent always-full.
        std::size_t end = kMaxFieldLen;
        while (end > 0 && (static_cast<unsigned char>(f[end]) & 0xC0) == 0x80)
            --end;
        f = f.substr(0, end);
    }
    // Strip the canonical framing separators (and NUL) so a value can never
    // corrupt the wire blob's structure (0x1F field / 0x1E record separators) —
    // the server splits on exactly those bytes. Vanishingly rare in real
    // software names, but cheap to guarantee.
    std::string out;
    out.reserve(f.size());
    for (char c : f) {
        if (c == '\x1f' || c == '\x1e' || c == '\0')
            continue;
        out.push_back(c);
    }
    return out;
}

bool entry_less(const SwEntry& a, const SwEntry& b) {
    if (a.name != b.name)
        return a.name < b.name;
    if (a.version != b.version)
        return a.version < b.version;
    if (a.publisher != b.publisher)
        return a.publisher < b.publisher;
    return a.install_date < b.install_date;
}

bool entry_equal(const SwEntry& a, const SwEntry& b) {
    return a.name == b.name && a.version == b.version && a.publisher == b.publisher &&
           a.install_date == b.install_date;
}

} // namespace

std::string sha256_hex(const std::string& in) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    if (EVP_Digest(in.data(), in.size(), md, &len, EVP_sha256(), nullptr) != 1)
        return {};
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(static_cast<std::size_t>(len) * 2);
    for (unsigned int i = 0; i < len; ++i) {
        out.push_back(kHex[md[i] >> 4]);
        out.push_back(kHex[md[i] & 0x0f]);
    }
    return out;
}

std::vector<SwEntry> parse_installed_apps_output(const std::string& out) {
    std::vector<SwEntry> entries;
    std::size_t pos = 0;
    while (pos < out.size() && entries.size() < kMaxEntries) {
        std::size_t eol = out.find('\n', pos);
        if (eol == std::string::npos)
            eol = out.size();
        std::string_view line(out.data() + pos, eol - pos);
        while (!line.empty() && (line.back() == '\r'))
            line.remove_suffix(1);
        pos = eol + 1;
        if (line.empty())
            continue;

        // Split on '|' into up to 5 tokens.
        std::vector<std::string_view> tok;
        std::size_t fp = 0;
        while (tok.size() < 5) {
            std::size_t bar = line.find('|', fp);
            if (bar == std::string_view::npos) {
                tok.push_back(line.substr(fp));
                break;
            }
            tok.push_back(line.substr(fp, bar - fp));
            fp = bar + 1;
        }
        if (tok.empty() || tok[0] != "app")
            continue; // skip user_app|, error|, found|, etc.
        if (tok.size() < 2 || tok[1].empty() || tok[1] == "No applications found")
            continue; // sentinel / malformed

        SwEntry e;
        e.name = clamp_field(tok[1]);
        e.version = tok.size() > 2 ? clamp_field(tok[2]) : "";
        e.publisher = tok.size() > 3 ? clamp_field(tok[3]) : "";
        e.install_date = tok.size() > 4 ? clamp_field(tok[4]) : "";
        // Drop a name that became empty AFTER clamping (e.g. a separator-only
        // name). The server's parse_software_blob drops empty-name rows, so the
        // agent must too or the two canonical hashes diverge → permanent
        // always-full (governance UP-1). Mirrors the server's `!e.name.empty()`.
        if (e.name.empty())
            continue;
        entries.push_back(std::move(e));
    }
    return entries;
}

std::string installed_software_canonical_blob(std::vector<SwEntry> entries) {
    std::sort(entries.begin(), entries.end(), entry_less);
    entries.erase(std::unique(entries.begin(), entries.end(), entry_equal), entries.end());
    std::string canon;
    canon.reserve(entries.size() * 48);
    for (const auto& e : entries) {
        canon += e.name;
        canon += '\x1f';
        canon += e.version;
        canon += '\x1f';
        canon += e.publisher;
        canon += '\x1f';
        canon += e.install_date;
        canon += '\x1e';
    }
    return canon;
}

SyncSource make_installed_software_source(const YuzuPluginDescriptor* descriptor) {
    SyncSource src;
    src.name = "installed_software";
    src.interval = std::chrono::hours{24};
    src.collect = [descriptor]() -> std::optional<std::pair<std::string, std::string>> {
        if (descriptor == nullptr) {
            spdlog::debug("sync: installed_apps plugin not loaded — installed_software source idle");
            return std::nullopt;
        }
        LocalDispatcher dispatcher;
        LocalDispatcher::Result r = dispatcher.run(descriptor, "list");
        if (r.rc != 0) {
            spdlog::warn("sync: installed_apps 'list' rc={} — skipping this cycle", r.rc);
            return std::nullopt;
        }
        if (r.truncated) {
            // The capture hit LocalDispatcher's byte cap — parsing it would yield
            // a partial inventory and a hash that flip-flops. Drop this cycle
            // rather than sync wrong data (mirrors the snapshot pump).
            spdlog::warn("sync: installed_apps 'list' output truncated at the capture cap — "
                         "skipping this cycle");
            return std::nullopt;
        }
        auto entries = parse_installed_apps_output(r.captured);
        std::string blob = installed_software_canonical_blob(std::move(entries));
        if (blob.size() > kMaxBlobBytes) {
            spdlog::warn("sync: installed_software blob {} B exceeds {} B cap — skipping this "
                         "cycle (won't send an un-storable payload)",
                         blob.size(), kMaxBlobBytes);
            return std::nullopt;
        }
        std::string hash = sha256_hex(blob);
        return std::make_pair(std::move(blob), std::move(hash));
    };
    return src;
}

} // namespace yuzu::agent
