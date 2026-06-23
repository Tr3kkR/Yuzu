#pragma once

/// @file pg_exec.hpp
/// Parameterized-query helpers shared by every Postgres-backed store — the
/// public home of the single-param `exec_param` pattern that was seeded
/// inside the migration runner (#1368 "promote exec_params into pg/"). All
/// values bind through libpq's positional `$1, $2, …` parameters
/// (`PQexecParams`), so store SQL never string-concatenates untrusted input
/// and the #1033 hand-rolled-PQexecParams boilerplate does not accrete across
/// the ~27 stores still to migrate.
///
/// Result format is text (`resultFormat = 0`); callers read columns with
/// `PQgetvalue` and check `.ok()` / `.status()` on the returned `PgResult`.

#include "pg_raii.hpp"

#include <libpq-fe.h>

#include <optional>
#include <string>
#include <vector>

namespace yuzu::server::pg {

/// Execute `sql` binding text-format parameters positionally to `$1..$N`. A
/// null `std::optional` binds SQL NULL; a set one binds its bytes. `conn` must
/// be a live connection — typically a non-empty `PgPool` lease's `get()`. The
/// caller-owned `params` must outlive only this call (the value pointers point
/// into it and are consumed synchronously by `PQexecParams`).
inline PgResult exec_params(PGconn* conn, const char* sql,
                            const std::vector<std::optional<std::string>>& params) {
    const int n = static_cast<int>(params.size());
    std::vector<const char*> values;
    values.reserve(params.size());
    for (const auto& p : params)
        values.push_back(p ? p->c_str() : nullptr);
    return PgResult{PQexecParams(conn, sql, n, /*paramTypes=*/nullptr,
                                 n > 0 ? values.data() : nullptr,
                                 /*paramLengths=*/nullptr, /*paramFormats=*/nullptr,
                                 /*resultFormat=*/0)};
}

/// Convenience overload for the common all-non-null-string case.
inline PgResult exec_params(PGconn* conn, const char* sql,
                            const std::vector<std::string>& params) {
    std::vector<std::optional<std::string>> opt;
    opt.reserve(params.size());
    for (const auto& p : params)
        opt.emplace_back(p);
    return exec_params(conn, sql, opt);
}

} // namespace yuzu::server::pg
