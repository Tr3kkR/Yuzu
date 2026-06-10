// Postgres F0 static-link canary (#1317, ADR-0008).
//
// Connects to the DSN given as argv[1] (or YUZU_POSTGRES_DSN), runs SELECT 1,
// and prints the result plus libpq/server versions. Its only job is to prove
// that libpq links — in particular statically on the Windows MSVC triplet —
// before the pg/ substrate (F1, #1320) is built on top of it.
//
// Exit codes: 0 = SELECT 1 succeeded, 1 = connect/query failure, 2 = no DSN.

#include <libpq-fe.h>

#include <cstdio>
#include <cstdlib>

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
