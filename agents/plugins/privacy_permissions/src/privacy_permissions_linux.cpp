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
 * No daemon / no session bus is the EXPECTED common case on most non-sandboxed Linux
 * desktops, per the roadmap -- `unavailable`, no failure token, never a constrained result.
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

/// One Lookup(table, id) call. Reply shape: a{sas} permissions (app_id -> [perm strings]),
/// then a variant `data` this leg ignores. A shape mismatch anywhere is `unreadable:shape`,
/// never a partial/guessed row. Returns false ONLY for ServiceUnknown (the portal backend
/// itself isn't registered on the bus at all) -- the caller treats that as a whole-mechanism
/// unavailability (CDX-P1-005), same class as no-session-bus, rather than a per-table row; a
/// true return means this call is fully accounted for in `rows`/`acc` already.
bool do_lookup(sd_bus* bus, const PortalTable& t, std::vector<PermissionRow>& rows,
               yuzu::shared::ConstraintAccumulator& acc) {
    SdBusErrorGuard err;
    SdBusMessageGuard reply;
    const int rc = sd_bus_call_method(bus, kPortalDest, kPortalPath, kPortalIface, "Lookup",
                                      &err.err, &reply.m, "ss", std::string{t.table}.c_str(),
                                      std::string{t.id}.c_str());
    if (rc < 0) {
        const std::string_view name = err.err.name ? err.err.name : "";
        // ServiceUnknown (the session bus is up but no portal backend is registered on it at
        // all) is handled by the caller as a whole-mechanism unavailability, not returned
        // here as a row -- see the function banner and CDX-P1-005.
        if (name == "org.freedesktop.DBus.Error.ServiceUnknown") return false;
        if (name == "org.freedesktop.portal.Error.NotFound") {
            // The portal answered; nothing recorded for this table/id yet -- honest absence.
            rows.push_back({"linux", "-", t.category, PermissionState::absent, "-", "-", "-", false});
            return true;
        }
        if (name == "org.freedesktop.DBus.Error.AccessDenied") {
            rows.push_back(whole_read_failed_row("linux", PermissionState::denied,
                                                 std::string{t.category} + ":access_denied", acc,
                                                 true));
            return true;
        }
        acc.add_failure(std::string{t.category} + ":lookup_failed");
        rows.push_back({"linux", "-", t.category, PermissionState::unreadable, "-", "-", "-", false});
        return true;
    }

    if (sd_bus_message_enter_container(reply.m, SD_BUS_TYPE_ARRAY, "{sas}") < 0) {
        acc.add_failure(std::string{t.category} + ":shape");
        rows.push_back({"linux", "-", t.category, PermissionState::unreadable, "-", "-", "-", false});
        return true;
    }
    bool any = false;
    int r;
    while ((r = sd_bus_message_enter_container(reply.m, SD_BUS_TYPE_DICT_ENTRY, "sas")) > 0) {
        const char* app_id = nullptr;
        sd_bus_message_read(reply.m, "s", &app_id);
        if (sd_bus_message_enter_container(reply.m, SD_BUS_TYPE_ARRAY, "s") >= 0) {
            std::string joined;
            const char* perm = nullptr;
            while (sd_bus_message_read(reply.m, "s", &perm) > 0) {
                if (!joined.empty()) joined += ',';
                joined += perm ? perm : "";
            }
            sd_bus_message_exit_container(reply.m);
            any = true;
            // decode_portal_permissions (CDX-P1-001): explicit no/ask/unrecognized tokens are
            // NOT allowed, only a real "yes" (or an unconfirmed-but-affirmative token) is.
            const auto state = decode_portal_permissions(joined);
            rows.push_back({"linux", app_id ? app_id : "-", t.category, state,
                            joined.empty() ? "-" : joined, "-", "-", false});
        }
        sd_bus_message_exit_container(reply.m);
    }
    sd_bus_message_exit_container(reply.m);
    if (r < 0) acc.add_failure(std::string{t.category} + ":shape");
    if (!any) rows.push_back({"linux", "-", t.category, PermissionState::absent, "-", "-", "-", false});
    return true;
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
        // No session bus (headless, no logged-in session) -- the expected common case on most
        // non-sandboxed Linux desktops per the roadmap. Honest unavailable, no token.
        rows.push_back({"linux", "-", "-", PermissionState::unsupported, "-", "-", "-", false});
        return emit_rows(ctx, rows, acc, true);
    }
    // If EVERY lookup hits ServiceUnknown, the portal backend itself is unreachable -- fold
    // that into the same whole-mechanism-unavailable shape as no-session-bus above (CDX-P1-005),
    // rather than the previous per-lookup absent rows that made a missing daemon
    // indistinguishable from a daemon that genuinely has no grants recorded.
    bool any_service_reachable = false;
    for (const auto& t : kPortalLookups)
        any_service_reachable = do_lookup(bus.bus, t, rows, acc) || any_service_reachable;
    if (!any_service_reachable) {
        rows.clear();
        rows.push_back({"linux", "-", "-", PermissionState::unsupported, "-", "-", "-", false});
        return emit_rows(ctx, rows, acc, true);
    }
    // Fixed four-category vocabulary (CDX-P1-006): no known Linux portal mechanism maps to
    // full_disk_access (Flatpak's `filesystem` permission is per-directory, not one boolean),
    // so this category is declared `unsupported` explicitly on every reachable collection --
    // never silently omitted, which a consumer cannot distinguish from a missed collector row.
    rows.push_back({"linux", "-", "full_disk_access", PermissionState::unsupported, "-", "-", "-", false});
#else
    // Built without libsystemd (-Dsystemd_guard=auto|disabled): a build-time absence, not an
    // OS statement -- this plugin cannot know whether a portal daemon exists on this host.
    acc.add_failure("portal:not_built");
    rows.push_back({"linux", "-", "-", PermissionState::unreadable, "-", "-", "-", false});
#endif

    if (rows.empty())
        rows.push_back({"linux", "-", "-", PermissionState::absent, "-", "-", "-", false});
    return emit_rows(ctx, rows, acc, false);
}

} // namespace yuzu::privacy_permissions

#endif // defined(__linux__)
