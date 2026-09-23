/**
 * privacy_permissions_linux.cpp -- Linux leg: xdg-desktop-portal's PermissionStore over the
 * SESSION bus (sd_bus_open_user) -- NOT the system bus firmware_posture_linux.cpp's fwupd leg
 * uses. Zero in-tree precedent for a session-bus call anywhere in this repo (confirmed by
 * grep); this is genuinely new ground, same RAII shape (BusGuard/SdBusErrorGuard/
 * SdBusMessageGuard, hand-rolled per file, no shared sd-bus header exists) as
 * firmware_posture_linux.cpp / firewall_plugin.cpp.
 *
 * UNKNOWNS pending a real probe against a running `xdg-desktop-portal` (see the plan): the
 * exact `Lookup` method reply shape (this file assumes the documented
 * `Lookup(in s table, in s id) -> (out a{sas} permissions, out v data)`, confirm via `busctl
 * --user introspect org.freedesktop.impl.portal.PermissionStore
 * /org/freedesktop/impl/portal/PermissionStore`, mirroring firmware_posture_linux.cpp's own
 * busctl-introspect citation for fwupd), the real `table`/`id` vocabulary GNOME/KDE portal
 * backends actually use for camera/microphone/location, and whether any meaningful Linux
 * full-disk-access equivalent exists via this mechanism at all (plausibly none -- Flatpak's
 * `filesystem` portal permission is a per-directory grant, not a single boolean, so
 * full_disk_access may need to ship `unsupported` on Linux permanently).
 *
 * SCOPE -- THE AGENT'S OWN SESSION BUS ONLY: sd_bus_open_user connects to the session bus of
 * the account the agent process runs as. It never reaches another user's session, and each
 * user's portal permission store lives in that user's own session -- so this leg reports, at
 * most, the grants of the agent's own account. The agent normally runs as a system service
 * with no session bus at all, so the honest result there is UNAVAILABLE, and UNAVAILABLE says
 * nothing about any interactive user's grants.
 *
 * No daemon / no session bus (no XDG_RUNTIME_DIR/DBUS_SESSION_BUS_ADDRESS, no socket, nobody
 * listening) is the EXPECTED common case -- `unsupported` + UNAVAILABLE, no failure token. A
 * refused session-bus socket is `denied` and any other open failure `unreadable`
 * (classify_session_bus_open), never folded into "no session". Once the bus is up, every
 * mapped category gets a row: its decoded app rows, `absent` (the portal answered NotFound or
 * an empty table), or a `denied`/`unreadable` row carrying its own `<category>:<cause>` token.
 */
#include "privacy_permissions_legs.hpp"

#if defined(__linux__)

#include <array>
#include <string>
#include <string_view>
#include <vector>

#if defined(YUZU_HAVE_LIBSYSTEMD)
#include <systemd/sd-bus.h>
#endif

namespace yuzu::privacy_permissions {

namespace {

#if defined(YUZU_HAVE_LIBSYSTEMD)

constexpr const char* kPortalDest = "org.freedesktop.impl.portal.PermissionStore";
constexpr const char* kPortalPath = "/org/freedesktop/impl/portal/PermissionStore";
constexpr const char* kPortalIface = "org.freedesktop.impl.portal.PermissionStore";

struct BusGuard {
    sd_bus* bus = nullptr;
    ~BusGuard() {
        if (bus) sd_bus_flush_close_unref(bus);
    }
    BusGuard() = default;
    BusGuard(const BusGuard&) = delete;
    BusGuard& operator=(const BusGuard&) = delete;
};
struct SdBusErrorGuard {
    sd_bus_error err = SD_BUS_ERROR_NULL;
    ~SdBusErrorGuard() { sd_bus_error_free(&err); }
    SdBusErrorGuard() = default;
    SdBusErrorGuard(const SdBusErrorGuard&) = delete;
    SdBusErrorGuard& operator=(const SdBusErrorGuard&) = delete;
};
struct SdBusMessageGuard {
    sd_bus_message* m = nullptr;
    ~SdBusMessageGuard() {
        if (m) sd_bus_message_unref(m);
    }
    SdBusMessageGuard() = default;
    SdBusMessageGuard(const SdBusMessageGuard&) = delete;
    SdBusMessageGuard& operator=(const SdBusMessageGuard&) = delete;
};

struct PortalTable {
    std::string_view table; // UNCONFIRMED real portal table name -- see file banner
    std::string_view id;    // UNCONFIRMED real permission id within that table
    std::string_view category;
};

// Best-effort table/id names pending the real busctl probe. `full_disk_access` is
// deliberately absent -- no known single-boolean portal equivalent exists (see banner).
inline constexpr std::array<PortalTable, 3> kPortalLookups{{
    {"devices", "camera", "camera"},
    {"devices", "microphone", "microphone"},
    {"location", "location", "location"},
}};

/// Decodes one app's joined permission-string list (comma-joined, as `Lookup` returned them --
/// see `joined` below) into a state. UNCONFIRMED against a real portal (plan unknown #6):
/// per the documented xdg-desktop-portal permission-store convention, `devices` records use
/// `yes`/`no`/`ask`, so a genuine explicit refusal or not-yet-asked record is NOT the same as
/// a grant -- "any non-empty list = allowed" (the prior shape here) would misreport both as
/// allowed. Recognized negative/undetermined tokens are checked FIRST so the empty case can't
/// shadow them; anything else non-empty and unrecognized is prompt_undetermined, never guessed
/// as allowed -- the same never-guess discipline decode_auth_value/decode_consent_value use.
PermissionState decode_portal_permissions(std::string_view joined) {
    if (joined.empty()) return PermissionState::denied; // an explicit empty record -- no grant
    if (joined == "no") return PermissionState::denied;
    if (joined == "ask") return PermissionState::prompt_undetermined;
    if (joined == "yes") return PermissionState::allowed;
    return PermissionState::prompt_undetermined; // unrecognized token(s) -- visible, not guessed
}

enum class LookupOutcome { accounted, service_unknown };

/// One Lookup(table, id) call. Reply shape: a{sas} permissions (app_id -> [perm strings]),
/// then a variant `data` this leg ignores. Every outcome except ServiceUnknown lands as rows
/// here (`accounted`); ServiceUnknown (no portal backend registered on the bus) is returned to
/// the caller, which decides between whole-mechanism unavailability (every lookup got it,
/// CDX-P1-005) and a per-category failure (only some did).
LookupOutcome do_lookup(sd_bus* bus, const PortalTable& t, std::vector<PermissionRow>& rows,
                        yuzu::shared::ConstraintAccumulator& acc) {
    const std::string cat{t.category};
    SdBusErrorGuard err;
    SdBusMessageGuard reply;
    const int rc = sd_bus_call_method(bus, kPortalDest, kPortalPath, kPortalIface, "Lookup",
                                      &err.err, &reply.m, "ss", std::string{t.table}.c_str(),
                                      std::string{t.id}.c_str());
    if (rc < 0) {
        const std::string_view name = err.err.name ? err.err.name : "";
        if (name == "org.freedesktop.DBus.Error.ServiceUnknown")
            return LookupOutcome::service_unknown;
        if (name == "org.freedesktop.portal.Error.NotFound") {
            // The portal answered; nothing recorded for this table/id yet -- honest absence.
            rows.push_back({"linux", "-", t.category, PermissionState::absent, "-", "-", "-", false});
            return LookupOutcome::accounted;
        }
        if (name == "org.freedesktop.DBus.Error.AccessDenied") {
            rows.push_back(failure_row("linux", "-", t.category, true, cat + ":access_denied", acc));
            return LookupOutcome::accounted;
        }
        rows.push_back(failure_row("linux", "-", t.category, false, cat + ":lookup_failed", acc));
        return LookupOutcome::accounted;
    }

    // CDX-R2-004: sd_bus_message_enter_container returns >0 entered, 0 a genuine type MISMATCH
    // at the current position (NOT entered), <0 an error -- only >0 is success.
    if (sd_bus_message_enter_container(reply.m, SD_BUS_TYPE_ARRAY, "{sas}") <= 0) {
        rows.push_back(failure_row("linux", "-", t.category, false, cat + ":shape", acc));
        return LookupOutcome::accounted;
    }
    bool any = false;
    bool entry_failed = false;
    int r;
    while ((r = sd_bus_message_enter_container(reply.m, SD_BUS_TYPE_DICT_ENTRY, "sas")) > 0) {
        const char* app_id = nullptr;
        if (sd_bus_message_read(reply.m, "s", &app_id) > 0 &&
            sd_bus_message_enter_container(reply.m, SD_BUS_TYPE_ARRAY, "s") > 0) {
            std::string joined;
            const char* perm = nullptr;
            while (sd_bus_message_read(reply.m, "s", &perm) > 0) {
                if (!joined.empty()) joined += ',';
                joined += perm ? perm : "";
            }
            sd_bus_message_exit_container(reply.m);
            any = true;
            // decode_portal_permissions (CDX-P1-001): explicit no/ask/unrecognized tokens are
            // NOT allowed, only a real "yes" is.
            const auto state = decode_portal_permissions(joined);
            rows.push_back({"linux", app_id ? app_id : "-", t.category, state,
                            joined.empty() ? "-" : joined, "-", "-", false});
        } else {
            // This dict entry's key or inner array didn't match the expected shape -- reported
            // as a row below, never silently skipped.
            entry_failed = true;
        }
        sd_bus_message_exit_container(reply.m);
    }
    sd_bus_message_exit_container(reply.m);
    // 1.8: a reply that failed part-way is never `absent` -- the table was not fully read.
    if (r < 0) rows.push_back(failure_row("linux", "-", t.category, false, cat + ":shape", acc));
    if (entry_failed)
        rows.push_back(failure_row("linux", "-", t.category, false, cat + ":entry_shape", acc));
    if (!any && r >= 0 && !entry_failed)
        rows.push_back({"linux", "-", t.category, PermissionState::absent, "-", "-", "-", false});
    return LookupOutcome::accounted;
}

#endif // YUZU_HAVE_LIBSYSTEMD

} // namespace

int collect_linux_permissions(yuzu::CommandContext& ctx) {
    yuzu::shared::ConstraintAccumulator acc;
    std::vector<PermissionRow> rows;

#if defined(YUZU_HAVE_LIBSYSTEMD)
    BusGuard bus;
    const int open_rc = sd_bus_open_user(&bus.bus);
    if (open_rc < 0 || !bus.bus) {
        const int err = open_rc < 0 ? -open_rc : 0;
        const auto outcome = classify_session_bus_open(err);
        if (outcome == BusOpenOutcome::unavailable) {
            // No session bus for the agent's own account (headless, system service) -- the
            // expected common case. Honest unavailable, no token.
            rows.push_back({"linux", "-", "-", PermissionState::unsupported, "-", "-", "-", false});
            return emit_rows(ctx, rows, acc, true);
        }
        rows.push_back(outcome == BusOpenOutcome::denied
                           ? failure_row("linux", "-", "-", true, "session_bus:access_denied", acc)
                           : failure_row("linux", "-", "-", false,
                                         "session_bus:open_errno_" + std::to_string(err), acc));
        return emit_rows(ctx, rows, acc, false);
    }
    // If EVERY lookup hits ServiceUnknown, the portal backend itself is unreachable -- the same
    // whole-mechanism-unavailable shape as no-session-bus above (CDX-P1-005). If only SOME do,
    // the backend answered the others, so those categories are a real failure, not absence.
    std::vector<std::string_view> service_unknown;
    for (const auto& t : kPortalLookups)
        if (do_lookup(bus.bus, t, rows, acc) == LookupOutcome::service_unknown)
            service_unknown.push_back(t.category);
    if (service_unknown.size() == kPortalLookups.size()) {
        rows.clear();
        rows.push_back({"linux", "-", "-", PermissionState::unsupported, "-", "-", "-", false});
        return emit_rows(ctx, rows, acc, true);
    }
    for (const auto cat : service_unknown)
        rows.push_back(failure_row("linux", "-", cat, false,
                                   std::string{cat} + ":service_unknown", acc));
    // Fixed four-category vocabulary (CDX-P1-006): no known Linux portal mechanism maps to
    // full_disk_access (Flatpak's `filesystem` permission is per-directory, not one boolean),
    // so this category is declared `unsupported` explicitly on every reachable collection.
    rows.push_back({"linux", "-", "full_disk_access", PermissionState::unsupported, "-", "-", "-", false});
#else
    // Built without libsystemd (-Dsystemd_guard=auto|disabled): a build-time absence, not an
    // OS statement -- this plugin cannot know whether a portal daemon exists on this host.
    rows.push_back(failure_row("linux", "-", "-", false, "portal:not_built", acc));
#endif

    return emit_rows(ctx, rows, acc, false);
}

} // namespace yuzu::privacy_permissions

#endif // defined(__linux__)
