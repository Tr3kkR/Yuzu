// test_tar_mapdrive.cpp -- Mapped-drive capture source (capability-map §3.8).
//
// The live/history enumeration is platform-gated (WNet / NetApi / registry /
// subprocess), so coverage rides on:
//   * the PURE text parsers (parse_proc_mounts / parse_fstab / parse_smbstatus /
//     parse_win_security_logons / parse_samba_logs), exercised from captured
//     sample output — these compile and run on every OS; and
//   * an insert round-trip through TarDatabase for both origin='historical'
//     (incl. ts=0) and origin='live' rows.
// The diff (compute_mapdrive_events) is covered in test_tar_diff.cpp.

#include "tar_collectors.hpp"
#include "tar_db.hpp"
#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

using namespace yuzu::tar;

// ── /proc/mounts (Linux outbound live) ────────────────────────────────────────

TEST_CASE("mapdrive parse_proc_mounts: keeps network fstypes, decodes escapes",
          "[tar][mapdrive][parse]") {
    const std::string text =
        "//fileserver/public /mnt/pub cifs rw,vers=3.0 0 0\n"
        "nfshost:/export/home /home/nfs nfs4 rw 0 0\n"
        "/dev/sda1 / ext4 rw,relatime 0 0\n"
        "tmpfs /tmp tmpfs rw 0 0\n"
        "//srv/with\\040space /mnt/s\\040p cifs rw 0 0\n";
    auto out = parse_proc_mounts(text);
    REQUIRE(out.size() == 3); // ext4 + tmpfs are not network fstypes

    CHECK(out[0].direction == "outbound");
    CHECK(out[0].remote_path == "//fileserver/public");
    CHECK(out[0].remote_host == "fileserver");
    CHECK(out[0].local_mount == "/mnt/pub");
    CHECK(out[0].provider == "cifs");

    CHECK(out[1].remote_host == "nfshost");
    CHECK(out[1].provider == "nfs4");

    // \040 octal escapes decode to spaces in both device and mountpoint.
    CHECK(out[2].remote_path == "//srv/with space");
    CHECK(out[2].local_mount == "/mnt/s p");
    CHECK(out[2].remote_host == "srv");
}

// ── /etc/fstab (Linux outbound historic; ts=0) ────────────────────────────────

TEST_CASE("mapdrive parse_fstab: network entries only, ts=0", "[tar][mapdrive][parse]") {
    const std::string text =
        "# /etc/fstab\n"
        "UUID=abcd / ext4 defaults 0 1\n"
        "//nas/backup /mnt/backup cifs credentials=/etc/creds 0 0\n"
        "nfshost:/srv /mnt/srv nfs defaults 0 0\n";
    auto out = parse_fstab(text);
    REQUIRE(out.size() == 2);
    CHECK(out[0].ts == 0); // fstab carries no timestamp
    CHECK(out[0].entry.direction == "outbound");
    CHECK(out[0].entry.remote_host == "nas");
    CHECK(out[0].entry.provider == "cifs");
    CHECK(out[1].entry.remote_host == "nfshost");
}

// ── smbstatus -b (Linux inbound live) ─────────────────────────────────────────

TEST_CASE("mapdrive parse_smbstatus: client + user from sessions table",
          "[tar][mapdrive][parse]") {
    // Note the first session's group column ("domain users") contains a space —
    // the parenthetical IP is what makes remote_host robust to that.
    const std::string text =
        "Samba version 4.15.13\n"
        "\n"
        "PID     Username     Group        Machine                          Protocol\n"
        "-------------------------------------------------------------------------------\n"
        "3456    alice        domain users 192.168.1.50 (ipv4:192.168.1.50:44556)  SMB3_11\n"
        "3789    bob          bob          ws7 (ipv4:10.0.0.7:50012)               SMB3_11\n";
    auto out = parse_smbstatus(text);
    REQUIRE(out.size() == 2);
    CHECK(out[0].direction == "inbound");
    CHECK(out[0].username == "alice");
    CHECK(out[0].remote_host == "192.168.1.50");
    CHECK(out[0].provider == "SMB");
    CHECK(out[1].username == "bob");
    CHECK(out[1].remote_host == "10.0.0.7");
}

// ── wevtutil Security 4624/4634 (Windows inbound historic) ────────────────────

TEST_CASE("mapdrive parse_win_security_logons: 4624 type-3 kept, others filtered",
          "[tar][mapdrive][parse]") {
    const std::string text =
        "Event[0]:\n"
        "  Date: 2026-07-01T10:20:30.123\n"
        "  Event ID: 4624\n"
        "  Description:\n"
        "Subject:\n"
        "\tAccount Name:\t\tHOST$\n"
        "Logon Type:\t\t3\n"
        "New Logon:\n"
        "\tAccount Name:\t\talice\n"
        "Network Information:\n"
        "\tSource Network Address:\t192.168.1.50\n"
        "Event[1]:\n"
        "  Date: 2026-07-01T11:00:00.000\n"
        "  Event ID: 4624\n"
        "Logon Type:\t\t2\n" // interactive — must be filtered out
        "New Logon:\n"
        "\tAccount Name:\t\tbob\n"
        "\tSource Network Address:\t-\n";
    auto out = parse_win_security_logons(text);
    REQUIRE(out.size() == 1); // only the type-3 network logon survives
    CHECK(out[0].entry.direction == "inbound");
    CHECK(out[0].entry.username == "alice"); // the 2nd Account Name, not HOST$
    CHECK(out[0].entry.remote_host == "192.168.1.50");
    CHECK(out[0].ts > 0);
}

// ── Samba logs / journalctl (Linux inbound historic) ──────────────────────────

TEST_CASE("mapdrive parse_samba_logs: connect events from both log shapes",
          "[tar][mapdrive][parse]") {
    const std::string text =
        "[2026/07/01 10:20:30.123456,  3] ../../source3/smbd/service.c:1055(make_connection_snum)\n"
        "  public (ipv4:192.168.1.50:445) connect to service public initially as user alice "
        "(uid=1000, gid=1000)\n"
        "2026-07-02T08:15:00+0000 host smbd[1234]: srv (ipv4:10.0.0.9:445) connect to service srv "
        "initially as user carol\n";
    auto out = parse_samba_logs(text);
    REQUIRE(out.size() == 2);
    CHECK(out[0].entry.direction == "inbound");
    CHECK(out[0].entry.local_mount == "public");
    CHECK(out[0].entry.remote_host == "192.168.1.50");
    CHECK(out[0].entry.username == "alice");
    CHECK(out[0].ts > 0); // from the [ ... ] header timestamp
    CHECK(out[1].entry.local_mount == "srv");
    CHECK(out[1].entry.remote_host == "10.0.0.9");
    CHECK(out[1].entry.username == "carol");
    CHECK(out[1].ts > 0); // from the inline ISO timestamp
}

// ── insert round-trip: historical (incl. ts=0) + live rows ────────────────────

TEST_CASE("mapdrive insert: historical + live rows round-trip through TarDatabase",
          "[tar][mapdrive][db]") {
    yuzu::test::TempDbFile tmp{std::string_view{"tar-mapdrive-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    // MapDriveEvent field order: {ts, snapshot_id, action, direction,
    // local_mount, remote_path, remote_host, username, provider, origin}.
    std::vector<MapDriveEvent> rows = {
        {1000, 5, "historical", "outbound", "Z:", "\\\\srv\\share", "srv", "alice", "SMB",
         "historical"},
        {0, 5, "historical", "outbound", "", "\\\\nas\\pub", "nas", "bob", "SMB", "historical"},
        {2000, 6, "appeared", "inbound", "", "", "client1", "carol", "SMB", "live"},
    };
    REQUIRE(db.insert_mapdrive_events(rows));

    auto res = db.execute_query(
        "SELECT ts, action, direction, local_mount, remote_path, remote_host, username, "
        "provider, origin FROM mapdrive_live ORDER BY id");
    REQUIRE(res.has_value());
    REQUIRE(res->rows.size() == 3);

    // Historical row with a real timestamp. Assert the string columns individually
    // (remote_path/remote_host/username/provider) so a bind-order transposition in
    // insert_mapdrive_events cannot pass undetected.
    CHECK(res->rows[0][0] == "1000");
    CHECK(res->rows[0][1] == "historical");
    CHECK(res->rows[0][2] == "outbound");
    CHECK(res->rows[0][3] == "Z:");
    CHECK(res->rows[0][4] == "\\\\srv\\share"); // remote_path
    CHECK(res->rows[0][5] == "srv");            // remote_host
    CHECK(res->rows[0][6] == "alice");          // username
    CHECK(res->rows[0][7] == "SMB");            // provider
    CHECK(res->rows[0][8] == "historical");     // origin

    // Historical row with ts=0 is preserved as 0 (not dropped / defaulted away).
    CHECK(res->rows[1][0] == "0");
    CHECK(res->rows[1][3] == ""); // deviceless — empty local_mount round-trips
    CHECK(res->rows[1][8] == "historical");

    // Live inbound row.
    CHECK(res->rows[2][1] == "appeared");
    CHECK(res->rows[2][2] == "inbound");
    CHECK(res->rows[2][8] == "live");

    // Empty batch is a success (matches the arp/dns/software insert contract).
    CHECK(db.insert_mapdrive_events({}));
}

// ── \x1f key collision safety with ':' / '\\' / space fields ──────────────────

TEST_CASE("mapdrive diff: fields with ':' '\\' and spaces do not collide",
          "[tar][mapdrive][diff]") {
    std::vector<MapDriveEntry> prev;
    std::vector<MapDriveEntry> cur = {
        {"outbound", "Z:", "\\\\srv\\share one", "srv", "alice", "SMB"},
        {"outbound", "Y:", "\\\\srv\\share two", "srv", "alice", "SMB"},
        {"inbound", "", "", "srv", "alice", "SMB"}};
    auto ev = compute_mapdrive_events(prev, cur, 100, 1);
    // Three distinct mappings — no key collision despite shared host/user and the
    // ':' / '\\' / space characters in the fields.
    REQUIRE(ev.size() == 3);
}

// ── dedup_history: identity collapse keeps the earliest non-zero ts ────────────

TEST_CASE("mapdrive dedup_history: collapses by identity, keeps earliest non-zero ts",
          "[tar][mapdrive][history]") {
    auto row = [](int64_t ts, const char* host) {
        MapDriveHistoryRow r;
        r.ts = ts;
        r.entry.direction = "outbound";
        r.entry.remote_path = std::string("\\\\") + host + "\\share";
        r.entry.remote_host = host;
        r.entry.username = "alice";
        r.entry.provider = "SMB";
        return r;
    };
    // Same identity three times (ts 0, 300, 100) collapses to one row keeping the
    // smallest NON-ZERO ts (100); a distinct host stays separate.
    std::vector<MapDriveHistoryRow> in = {row(0, "srv"), row(300, "srv"), row(100, "srv"),
                                          row(0, "nas")};
    auto out = dedup_history(in);
    REQUIRE(out.size() == 2);
    // Find the srv row.
    const MapDriveHistoryRow* srv = nullptr;
    for (auto& r : out)
        if (r.entry.remote_host == "srv")
            srv = &r;
    REQUIRE(srv != nullptr);
    CHECK(srv->ts == 100); // earliest non-zero sighting wins over 0 and 300
}
