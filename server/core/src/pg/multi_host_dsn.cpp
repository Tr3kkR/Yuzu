#include "multi_host_dsn.hpp"

#include <libpq-fe.h>

#include <algorithm>
#include <cstdlib>
#include <memory>
#include <string_view>

namespace yuzu::server::pg {

namespace {

std::size_t list_len(std::string_view v) {
    return v.empty() ? 0 : static_cast<std::size_t>(std::count(v.begin(), v.end(), ',')) + 1;
}

/// Append `key=value` in the DSN's own syntax (URI query or keyword pair).
std::string append_param(const std::string& dsn, const char* key, const char* value) {
    const std::size_t s = dsn.find_first_not_of(" \t\r\n");
    const std::string_view v =
        s == std::string::npos ? std::string_view{} : std::string_view{dsn}.substr(s);
    const bool uri = v.rfind("postgres://", 0) == 0 || v.rfind("postgresql://", 0) == 0;
    if (uri)
        return dsn + (dsn.find('?') == std::string::npos ? "?" : "&") + key + "=" + value;
    return dsn + " " + key + "=" + value;
}

} // namespace

std::expected<MultiHostDsn, std::string> enforce_multi_host_read_write(const std::string& dsn) {
    MultiHostDsn out{dsn, false, 1};
    char* errmsg = nullptr;
    std::unique_ptr<PQconninfoOption, decltype(&PQconninfoFree)> opts(
        PQconninfoParse(dsn.c_str(), &errmsg), &PQconninfoFree);
    const std::unique_ptr<char, decltype(&PQfreemem)> errmsg_owner(errmsg, &PQfreemem);
    if (!opts)
        return out; // unparseable: unchanged; the pool fails it at boot

    std::string_view host, hostaddr, tsa, lbh;
    for (const PQconninfoOption* o = opts.get(); o->keyword != nullptr; ++o) {
        if (o->val == nullptr)
            continue;
        const std::string_view k{o->keyword};
        if (k == "host")
            host = o->val;
        else if (k == "hostaddr")
            hostaddr = o->val;
        else if (k == "target_session_attrs")
            tsa = o->val;
        else if (k == "load_balance_hosts")
            lbh = o->val;
    }
    // A host list may come from the environment when the DSN names none.
    if (host.empty())
        if (const char* e = std::getenv("PGHOST"))
            host = e;
    if (hostaddr.empty())
        if (const char* e = std::getenv("PGHOSTADDR"))
            hostaddr = e;
    out.hosts = std::max<std::size_t>({list_len(host), list_len(hostaddr), 1});

    const bool balanced = !lbh.empty() && lbh != "disable";
    if (out.hosts < 2 && !balanced)
        return out;
    if (tsa.empty()) {
        out.dsn = append_param(dsn, "target_session_attrs", "read-write");
        out.appended = true;
        return out;
    }
    if (tsa == "read-write" || tsa == "primary")
        return out;
    return std::unexpected(
        "a multi-host Postgres DSN needs target_session_attrs=read-write (or primary); '" +
        std::string(tsa) +
        "' lets the server's connections land on a server that cannot take writes, "
        "which /readyz cannot detect. Remove target_session_attrs (the server then uses "
        "read-write) or set it to read-write.");
}

} // namespace yuzu::server::pg
