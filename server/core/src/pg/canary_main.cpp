// Postgres F0 link canary (#1317, ADR-0008).
//
// Connects to the DSN given as argv[1] (or YUZU_POSTGRES_DSN), runs SELECT 1,
// and prints the result plus libpq/server versions. Its only job is to prove
// that libpq builds at the pinned vcpkg baseline and links on every platform
// — static .a on Linux/macOS, DLL + import lib on Windows (see the ADR-0008
// Correction) — before the pg/ substrate (F1, #1320) is built on top of it.
//
// Exit codes: 0 = SELECT 1 succeeded, 1 = connect/query failure, 2 = no DSN.
// The exit codes are the only stable contract; stdout format is not. Note for
// CI wiring (#1318): PQconnectdb/PQexec have no client-side timeout — include
// connect_timeout=<s> in the DSN or wrap in timeout(1) before using as a
// smoke step, or a black-holed host wedges the job.

#include <cstdio>
#include <cstdlib>

#include <libpq-fe.h>

int main(int argc, char** argv) {
    const char* dsn = argc > 1 ? argv[1] : std::getenv("YUZU_POSTGRES_DSN");
    if (dsn == nullptr || dsn[0] == '\0') {
        std::fprintf(stderr,
                     "usage: yuzu_pg_canary <dsn>  (or set YUZU_POSTGRES_DSN)\n"
                     "e.g.   yuzu_pg_canary \"postgresql://yuzu:yuzu@localhost:5432/yuzu\"\n");
        return 2;
    }

    PGconn* conn = PQconnectdb(dsn);
    if (PQstatus(conn) != CONNECTION_OK) {
        std::fprintf(stderr, "canary: connect failed: %s", PQerrorMessage(conn));
        PQfinish(conn);
        return 1;
    }

    PGresult* res = PQexec(conn, "SELECT 1");
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        std::fprintf(stderr, "canary: SELECT 1 failed: %s", PQerrorMessage(conn));
        PQclear(res);
        PQfinish(conn);
        return 1;
    }

    std::printf("canary: SELECT 1 -> %s (libpq %d, server %d)\n", PQgetvalue(res, 0, 0),
                PQlibVersion(), PQserverVersion(conn));

    PQclear(res);
    PQfinish(conn);
    return 0;
}
