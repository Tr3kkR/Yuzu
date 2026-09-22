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

#if defined(YUZU_HAVE_LIBSYSTEMD)
#include <systemd/sd-bus.h>
#endif

#include <array>
#include <string>
#include <string_view>
#include <vector>

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

/// One Lookup(table, id) call. Reply shape: a{sas} permissions (app_id -> [perm strings]),
/// then a variant `data` this leg ignores. A shape mismatch anywhere is `unreadable:shape`,
/// never a partial/guessed row.
void do_lookup(sd_bus* bus, const PortalTable& t, std::vector<PermissionRow>& rows,
              yuzu::shared::ConstraintAccumulator& acc) {
    SdBusErrorGuard err;
    SdBusMessageGuard reply;
    const int rc = sd_bus_call_method(bus, kPortalDest, kPortalPath, kPortalIface, "Lookup",
                                      &err.err, &reply.m, "ss", std::string{t.table}.c_str(),
                                      std::string{t.id}.c_str());
    if (rc < 0) {
        const std::string_view name = err.err.name ? err.err.name : "";
        if (name == "org.freedesktop.DBus.Error.ServiceUnknown" ||
            name == "org.freedesktop.portal.Error.NotFound") {
            // No portal backend registered for this table/id, or nothing recorded yet --
            // honest absence, not a failure.
            rows.push_back({"linux", "-", t.category, PermissionState::absent, "-", "-", "-", false});
            return;
        }
        if (name == "org.freedesktop.DBus.Error.AccessDenied") {
            rows.push_back(whole_read_failed_row("linux", PermissionState::denied,
                                                 std::string{t.category} + ":access_denied", acc,
                                                 true));
            return;
        }
        acc.add_failure(std::string{t.category} + ":lookup_failed");
        rows.push_back({"linux", "-", t.category, PermissionState::unreadable, "-", "-", "-", false});
        return;
    }

    if (sd_bus_message_enter_container(reply.m, SD_BUS_TYPE_ARRAY, "{sas}") < 0) {
        acc.add_failure(std::string{t.category} + ":shape");
        rows.push_back({"linux", "-", t.category, PermissionState::unreadable, "-", "-", "-", false});
        return;
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
            // A non-empty permission list is treated as "allowed" (grant exists); an empty
            // one as "denied" (an explicit empty record) -- both are real, observed states,
            // never guessed.
            rows.push_back({"linux", app_id ? app_id : "-", t.category,
                            joined.empty() ? PermissionState::denied : PermissionState::allowed,
                            joined.empty() ? "-" : joined, "-", "-", false});
        }
        sd_bus_message_exit_container(reply.m);
    }
    sd_bus_message_exit_container(reply.m);
    if (r < 0) acc.add_failure(std::string{t.category} + ":shape");
    if (!any) rows.push_back({"linux", "-", t.category, PermissionState::absent, "-", "-", "-", false});
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
    for (const auto& t : kPortalLookups) do_lookup(bus.bus, t, rows, acc);
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
