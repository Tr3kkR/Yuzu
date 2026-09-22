/**
 * privacy_permissions_macos.cpp -- macOS leg: TCC.db read-only, in-process (sqlite3_open_v2
 * SQLITE_OPEN_READONLY|SQLITE_OPEN_NOMUTEX, the app_usage_plugin.cpp precedent) -- never a
 * `sqlite3` CLI shellout (zero precedent anywhere in this tree for that shape).
 *
 * UNKNOWNS pending a real-hardware probe (see the plan): the exact `access` table schema and
 * `auth_value` integer mapping on the probed macOS version (has drifted across releases --
 * this file assumes the commonly-documented 0=denied/2=allowed/3=limited shape but treats any
 * other value as prompt_undetermined rather than guessing), and whether the shipped agent
 * identity (root LaunchDaemon today) can open TCC.db at all -- SIP-protected, so `denied` is
 * the charter's own expected outcome for an unentitled process. Whether `location` is even
 * represented in this table (vs a separate locationd mechanism) is also unconfirmed; the query
 * simply finds no matching rows for it if that's the case, which surfaces as every app reading
 * `absent` for that category -- not wrongly reported as "denied".
 *
 * REAL PROBE, this Mac (`braga`, macOS 26.6.2), 2026-09-22, via the unit test binary's own
 * ambient identity (a Terminal/VSCode-launched process, NOT the production agent identity --
 * this proves the READ MECHANISM works end to end, not that the production LaunchDaemon can
 * open TCC.db; that remains a still-open acceptance item requiring the real service identity):
 * open + query against `access` succeeded and returned real `full_disk_access` rows --
 * sshd-keygen-wrapper and com.microsoft.VSCode both `allowed` (auth_value 2);
 * com.nordvpn.macos, com.spotify.client and net.whatsapp.WhatsApp all `denied` (auth_value 0).
 * No camera/microphone/location rows were present for any queried app on this host at capture
 * time -- consistent with the query itself being schema-correct rather than silently
 * false-empty, since the identical query DID return real full_disk_access rows.
 */
#include "privacy_permissions_legs.hpp"

#if defined(__APPLE__)

#include <sqlite3.h>

#include <array>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::privacy_permissions {

namespace {

constexpr std::string_view kTccDbPath = "/Library/Application Support/com.apple.TCC/TCC.db";

struct TccService {
    std::string_view service; // literal TCC service identifier
    std::string_view category;
};

// Only the charter's four categories are mapped; every other TCC service (kTCCServiceContacts,
// kTCCServiceAppleEvents, kTCCServiceScreenCapture, ...) is out of scope by deliberate filter,
// not a decode failure -- the query below simply never asks for them.
inline constexpr std::array<TccService, 4> kTccServices{{
    {"kTCCServiceCamera", "camera"},
    {"kTCCServiceMicrophone", "microphone"},
    {"kTCCServiceLocation", "location"}, // UNCONFIRMED to exist in this table -- see file banner
    {"kTCCServiceSystemPolicyAllFiles", "full_disk_access"},
}};

class DbHandle {
public:
    DbHandle() noexcept = default;
    explicit DbHandle(sqlite3* db) noexcept : db_(db) {}
    ~DbHandle() {
        if (db_) sqlite3_close(db_);
    }
    DbHandle(const DbHandle&) = delete;
    DbHandle& operator=(const DbHandle&) = delete;
    DbHandle(DbHandle&& o) noexcept : db_(o.db_) { o.db_ = nullptr; }
    DbHandle& operator=(DbHandle&& o) noexcept {
        if (this != &o) {
            if (db_) sqlite3_close(db_);
            db_ = o.db_;
            o.db_ = nullptr;
        }
        return *this;
    }
    [[nodiscard]] sqlite3* get() const noexcept { return db_; }
    [[nodiscard]] explicit operator bool() const noexcept { return db_ != nullptr; }

private:
    sqlite3* db_{nullptr};
};

/// Opens TCC.db read-only. `err_msg` is filled from sqlite3_errmsg() on failure -- the real,
/// observed diagnostic, not a guessed one (the plan's acceptance criterion for this leg is
/// recording the ACTUAL denied/constrained outcome, not asserting one).
DbHandle open_readonly(std::string& err_msg) {
    sqlite3* raw = nullptr;
    const int rc = sqlite3_open_v2(std::string{kTccDbPath}.c_str(), &raw,
                                   SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX, nullptr);
    DbHandle db{raw}; // owns `raw` even on failure -- sqlite3 may allocate a handle just to
                      // carry the error message; RAII from here regardless of `rc`.
    if (rc != SQLITE_OK) {
        err_msg = db ? sqlite3_errmsg(db.get()) : "sqlite3_open_v2 failed";
        return DbHandle{};
    }
    sqlite3_busy_timeout(db.get(), 2000);
    sqlite3_exec(db.get(), "PRAGMA query_only=1", nullptr, nullptr, nullptr);
    return db;
}

PermissionState decode_auth_value(int v) {
    // Commonly-documented mapping across recent macOS releases; NOT verified against this
    // build's actual schema (unknown #1 in the plan). Any value outside this table is a real,
    // visible prompt_undetermined rather than a silent misclassification.
    switch (v) {
    case 0: return PermissionState::denied;
    case 2: return PermissionState::allowed;
    case 3: return PermissionState::allowed; // "limited" -- still a grant, just scoped
    default: return PermissionState::prompt_undetermined;
    }
}

} // namespace

int collect_macos_permissions(yuzu::CommandContext& ctx) {
    yuzu::shared::ConstraintAccumulator acc;
    std::vector<PermissionRow> rows;

    std::string err_msg;
    DbHandle db = open_readonly(err_msg);
    if (!db) {
        // SQLITE_CANTOPEN/SQLITE_AUTH/SQLITE_PERM on a SIP-protected file all surface through
        // sqlite3_open_v2's generic failure path -- there is no finer-grained code to branch
        // on here, so any open failure is treated as a refusal (the charter's expected
        // outcome), not as "the file doesn't exist" (never `absent` for a system file that is
        // always present on a modern macOS host).
        rows.push_back(whole_read_failed_row("macos", PermissionState::denied,
                                             "tcc_db:open_failed:" + err_msg, acc, true));
        return emit_rows(ctx, rows, acc, false);
    }

    sqlite3_stmt* raw_stmt = nullptr;
    static constexpr char kQuery[] =
        "SELECT service, client, auth_value FROM access WHERE service = ?";
    if (sqlite3_prepare_v2(db.get(), kQuery, -1, &raw_stmt, nullptr) != SQLITE_OK) {
        rows.push_back(whole_read_failed_row(
            "macos", PermissionState::unreadable,
            std::string{"tcc_db:prepare_failed:"} + sqlite3_errmsg(db.get()), acc, false));
        return emit_rows(ctx, rows, acc, false);
    }

    bool any_row_found = false;
    for (const auto& svc : kTccServices) {
        sqlite3_reset(raw_stmt);
        sqlite3_bind_text(raw_stmt, 1, svc.service.data(), static_cast<int>(svc.service.size()),
                          SQLITE_STATIC);
        for (;;) {
            const int step_rc = sqlite3_step(raw_stmt);
            if (step_rc == SQLITE_DONE) break;
            if (step_rc != SQLITE_ROW) {
                acc.add_failure(std::string{svc.category} + ":query_step_failed");
                break;
            }
            any_row_found = true;
            const auto* client = reinterpret_cast<const char*>(sqlite3_column_text(raw_stmt, 1));
            const int auth_value = sqlite3_column_int(raw_stmt, 2);
            rows.push_back({"macos", client ? client : "-", svc.category,
                            decode_auth_value(auth_value), std::to_string(auth_value), "-", "-",
                            false});
        }
    }
    sqlite3_finalize(raw_stmt);

    if (rows.empty()) {
        // Query ran cleanly but found nothing for any of the four mapped services -- a
        // definitive, honest "no grants recorded" (not a failure): absent, not unreadable.
        rows.push_back({"macos", "-", "-", PermissionState::absent, "-", "-", "-", false});
    }
    (void)any_row_found;
    return emit_rows(ctx, rows, acc, false);
}

} // namespace yuzu::privacy_permissions

#endif // defined(__APPLE__)
