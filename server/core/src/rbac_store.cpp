#include "rbac_store.hpp"

#include "management_group_store.hpp"
#include "migration_runner.hpp"
#include "sqlite_raii.hpp"

#include <spdlog/spdlog.h>
#include <sqlite3.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <shared_mutex>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace yuzu::server {

namespace {

/// Single source of truth for the identity-provider `source` values
/// `reconcile_idp_memberships` / `namespaced_group_name` recognize. Adding a
/// future IdP (e.g. "okta") here is the ONLY edit required to also reserve
/// its `okta:` prefix from local-group creation below — `kReservedIdpPrefixes`
/// is derived from this list, never maintained as a second parallel array.
/// #1832 hardening sec-L2.
constexpr std::array<std::string_view, 3> kRecognizedIdpSources = {"entra", "saml", "ad"};

/// "local:" is reserved too even though "local" itself is never a
/// `reconcile_idp_memberships` source (rejected outright — see UP-6 below):
/// a local group literally named "local:x" is confusing enough to preclude
/// pre-emptively, and doing so costs nothing.
constexpr std::string_view kLocalPrefix = "local:";

/// The reserved engine-principal namespace (auth-engine-principals design
/// §3.3 / decision log #3). Deliberately NOT folded into
/// `kRecognizedIdpSources` above: "engine" is not an identity-provider
/// source — no engine-principal role assignment is ever asserted via
/// `reconcile_idp_memberships`, and adding it to that array would wrongly
/// imply otherwise. Kept as its own guard instead, same shape as
/// `kLocalPrefix`. Also reused by `RbacStore::validate_assignment` below —
/// single literal, not re-derived per call site.
constexpr std::string_view kEnginePrefix = "engine:";

/// A `source=='local'` group create is rejected if `name` starts with one of
/// `kRecognizedIdpSources` + ':' (or `kLocalPrefix`/`kEnginePrefix`) — it
/// would otherwise be indistinguishable from (and could be used to pre-seed
/// roles for) a same-named IdP group, or collide with the reserved engine
/// namespace (§3.3: "the same rejection applies to locally created RBAC
/// group names"). #1832; engine reservation is PR 4.2.
bool has_reserved_idp_prefix(std::string_view name) {
    if (name.size() >= kLocalPrefix.size() && name.compare(0, kLocalPrefix.size(), kLocalPrefix) == 0)
        return true;
    if (name.size() >= kEnginePrefix.size() &&
        name.compare(0, kEnginePrefix.size(), kEnginePrefix) == 0)
        return true;
    for (auto source : kRecognizedIdpSources) {
        if (name.size() > source.size() && name[source.size()] == ':' &&
            name.compare(0, source.size(), source) == 0)
            return true;
    }
    return false;
}

/// Whitespace-only or empty (UP-9 input validation) — an asserted IdP group
/// entry with a blank `external_id` would otherwise create a garbage
/// `<source>:` or `<source>:   ` group row.
bool is_blank(std::string_view s) {
    for (unsigned char c : s) {
        if (!std::isspace(c))
            return false;
    }
    return true; // empty also counts as blank
}

/// Upper bound on a single asserted `external_id`'s length. Generous relative
/// to any real IdP group-id format (Entra object IDs are 36-char GUIDs); this
/// is defense-in-depth against a malformed/hostile assertion, not a format
/// constraint. #1832 hardening UP-9.
constexpr size_t kMaxExternalIdLength = 512;

/// Built-in role names an engine-principal assignment must never receive —
/// `RbacStore::validate_assignment`'s "no admin, ever" bar (design §4.2).
/// "Administrator" is RBAC's own full-access system role, seeded below with
/// description "Full access to all operations" and granted CRUD across
/// every securable type in `seed_defaults()`; it is also the RBAC-role name
/// legacy `auth::Role::admin` is displayed/mapped as at every existing
/// legacy-role↔RBAC-role site (e.g. `session->role == auth::Role::admin ?
/// "Administrator" : "Viewer"` in rest_api_v1.cpp/server.cpp), so barring
/// this one name closes both "the admin legacy role" and "any built-in
/// wildcard role" from §4.2 — today there is exactly one built-in
/// (`is_system`) role that is provably unrestricted. The literal "admin" is
/// barred too, as defense-in-depth against a caller ever threading the raw
/// legacy role string through this path instead of an RBAC role name.
/// EXTEND this set — never fork a second bar elsewhere (matches the
/// `dangerous_enforce_in_spec` single-chokepoint pattern used for Guardian's
/// analogous enforce-promotion bar) — if a future built-in role is ever
/// seeded with comparably unrestricted access. Decision log #13 additionally
/// names an independent auditor-runnable verification query (PR 4.3/4.4) so
/// this write-path bar is never the sole evidence of the invariant.
///
/// "Elevation-eligibility role" (§4.2's third bar) has no entry here: JIT
/// elevation eligibility is the per-user `users.elevation_eligible` column
/// (auth_db.cpp) — it has no RBAC-role representation to reject, and an
/// engine principal is never a `users` table row in the first place
/// (`EnginePrincipalStore` is a separate substrate), so the bar is
/// structurally satisfied without a check here.
constexpr std::array<std::string_view, 2> kEngineDisallowedRoles = {"admin", "Administrator"};

} // namespace

std::string namespaced_group_name(const std::string& source, const std::string& external_id) {
    if (source == "local")
        return external_id;
    return source + ":" + external_id;
}

// ── Construction / teardown ──────────────────────────────────────────────────

RbacStore::RbacStore(const std::filesystem::path& db_path) {
    int rc = sqlite3_open_v2(db_path.string().c_str(), &db_,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                             nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("RbacStore: failed to open {}: {}", db_path.string(), sqlite3_errmsg(db_));
        if (db_) {
            sqlite3_close(db_);
            db_ = nullptr;
        }
        return;
    }

    sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "PRAGMA busy_timeout=5000;", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "PRAGMA foreign_keys=ON;", nullptr, nullptr, nullptr);
    create_tables();
    if (!db_)
        return;
    seed_defaults();
    load_enabled_flag();
    spdlog::info("RbacStore: opened {}", db_path.string());
}

RbacStore::~RbacStore() {
    if (db_)
        sqlite3_close(db_);
}

bool RbacStore::is_open() const {
    return db_ != nullptr;
}

// ── DDL ──────────────────────────────────────────────────────────────────────

void RbacStore::create_tables() {
    static const std::vector<Migration> kMigrations = {
        {1, R"(
            CREATE TABLE IF NOT EXISTS securable_types (
                name        TEXT PRIMARY KEY,
                description TEXT NOT NULL DEFAULT '',
                is_system   INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS operations (
                id          TEXT PRIMARY KEY,
                description TEXT NOT NULL DEFAULT '',
                is_system   INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS roles (
                name        TEXT PRIMARY KEY,
                description TEXT NOT NULL DEFAULT '',
                is_system   INTEGER NOT NULL DEFAULT 0,
                created_at  INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS role_permissions (
                role_name       TEXT NOT NULL REFERENCES roles(name) ON DELETE CASCADE,
                securable_type  TEXT NOT NULL REFERENCES securable_types(name),
                operation       TEXT NOT NULL REFERENCES operations(id),
                effect          TEXT NOT NULL DEFAULT 'allow',
                PRIMARY KEY (role_name, securable_type, operation)
            );

            CREATE TABLE IF NOT EXISTS principal_roles (
                principal_type  TEXT NOT NULL,
                principal_id    TEXT NOT NULL,
                role_name       TEXT NOT NULL REFERENCES roles(name) ON DELETE CASCADE,
                PRIMARY KEY (principal_type, principal_id, role_name)
            );
            CREATE INDEX IF NOT EXISTS idx_principal_roles_lookup
                ON principal_roles(principal_type, principal_id);

            CREATE TABLE IF NOT EXISTS groups (
                name        TEXT PRIMARY KEY,
                description TEXT NOT NULL DEFAULT '',
                source      TEXT NOT NULL DEFAULT 'local',
                external_id TEXT,
                created_at  INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS group_members (
                group_name  TEXT NOT NULL REFERENCES groups(name) ON DELETE CASCADE,
                username    TEXT NOT NULL,
                PRIMARY KEY (group_name, username)
            );

            CREATE TABLE IF NOT EXISTS rbac_config (
                key     TEXT PRIMARY KEY,
                value   TEXT NOT NULL
            );
        )"},
        // #1832 — additive only: no PK/schema change, no data rewrite. Speeds
        // up reconcile_idp_memberships' source-scoped lookups (the stale-
        // membership DELETE's `groups WHERE source = ?` subquery and the
        // per-login `group_members WHERE username = ?` scans), which now run
        // on every OIDC/SAML login rather than only from the admin UI.
        {2, R"(
            CREATE INDEX IF NOT EXISTS idx_groups_source ON groups(source);
            CREATE INDEX IF NOT EXISTS idx_group_members_username ON group_members(username);
        )"},
        // #1837 — purge orphaned display-name-keyed IdP memberships. Before
        // this migration, OIDC-sourced `group_members` rows were keyed on
        // the (mutable) display name; SSO sessions now key on the stable
        // `oidc:<iss>#<sub>` principal instead (auth.cpp
        // create_oidc_session). Left in place, these rows would become BOTH
        // orphaned (never re-referenced by the new stable-keyed principal)
        // AND a resurrected confused-deputy hazard: a LOCAL user who
        // happens to share the old display name would silently inherit
        // whatever roles the stale IdP-sourced group grants. Deleting every
        // `group_members` row whose group is IdP-sourced (`groups.source !=
        // 'local'`) is additive/safe — it only removes membership rows;
        // `groups`/`roles`/`role_permissions`/local memberships are
        // untouched, and IdP membership re-populates (under the new stable
        // key) on the user's next SSO login via `reconcile_idp_memberships`.
        {3, R"(
            DELETE FROM group_members
            WHERE group_name IN (SELECT name FROM groups WHERE source != 'local');
        )"},
        // Periodic Access Reviews (#2324 review round) — retire the
        // now-superseded AuditLog:Read/AuditLog:Attest grants an earlier
        // (pre-fix) version of this PR seeded for access-review gating,
        // now replaced by the dedicated AccessReview securable. `INSERT OR
        // IGNORE` in `seed_defaults()` only ever ADDS rows, so a dev/UAT
        // rbac.db that was seeded under the earlier scheme would otherwise
        // keep these three retired grants forever — a Reviewer created
        // before the flip would still carry the live AuditLog:Read op that
        // a fresh-install Reviewer never gets, and Administrator would
        // carry a stray AuditLog:Attest op that was only ever added for
        // this feature. Scoped to EXACTLY these three (role, securable,
        // operation) tuples — Administrator's other AuditLog ops
        // (Read/Write/Delete/etc.) and every other role's AuditLog:Read
        // (Operator/PlatformEngineer/Viewer — unrelated, still legitimate)
        // are untouched. Safe no-op on a fresh DB (rows never existed).
        // One-way cleanup: like any data migration it is version-gated and
        // runs exactly once, but restoring a pre-v4 backup and re-booting
        // re-applies it — so an operator who DELIBERATELY re-grants one of
        // these three tuples (e.g. Reviewer:AuditLog:Read to let reviewers
        // also browse the audit trail) after v4 has run keeps it, but would
        // lose it on such a restore. That grant belongs on a separate role
        // or a distinct securable, not these retired access-review tuples.
        {4, R"(
            DELETE FROM role_permissions
            WHERE (role_name, securable_type, operation) IN (
                ('Administrator', 'AuditLog', 'Attest'),
                ('Reviewer', 'AuditLog', 'Read'),
                ('Reviewer', 'AuditLog', 'Attest')
            );
        )"},
    };
    if (!MigrationRunner::run(db_, "rbac_store", kMigrations)) {
        spdlog::error("RbacStore: schema migration failed, closing database");
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

// ── Seed data ────────────────────────────────────────────────────────────────

void RbacStore::seed_defaults() {
    if (!db_)
        return;

    // Config default
    sqlite3_exec(db_, "INSERT OR IGNORE INTO rbac_config VALUES ('enabled', 'false');", nullptr,
                 nullptr, nullptr);

    // Securable types
    const char* types[] = {"Infrastructure",
                           "UserManagement",
                           "InstructionDefinition",
                           "InstructionSet",
                           "Execution",
                           "Schedule",
                           "Approval",
                           "Tag",
                           "AuditLog",
                           "Response",
                           "ManagementGroup",
                           "ApiToken",
                           "Security",
                           "Policy",
                           "DeviceToken",
                           "SoftwareDeployment",
                           "License",
                           "FileRetrieval",
                           "GuaranteedState",
                           "Inventory",
                           // Periodic Access Reviews (SOC 2 CC6.2): dedicated narrow
                           // securable for the fleet-wide grant export + attestation-
                           // campaign lifecycle — deliberately separate from AuditLog so
                           // AuditLog:Read holders (e.g. Operator, PlatformEngineer) do
                           // NOT also get the grant-graph export. Seeded to
                           // Administrator (via the CRUD loop below) + the Reviewer role
                           // (Read + Attest, see the explicit grants further down).
                           "AccessReview",
                           // SLE (ADR-0024 Decision 9). DISTINCT from the existing
                           // `License` securable (Yuzu's OWN product licence, §22.3) —
                           // this gates the /api/v1/sle/* discovery reads + the erasure
                           // DELETE. (No SLE page ships yet — ADR-0024 D9 places the
                           // Licences view in-server, but it is not built; the compliance
                           // sub-views are the SAM UCE module's.) Seeding it here
                           // also grants Administrator full CRUD via the loop below.
                           "SoftwareLicensing"};
    for (auto* t : types) {
        sqlite3_stmt* s = nullptr;
        sqlite3_prepare_v2(db_,
                           "INSERT OR IGNORE INTO securable_types (name, is_system) VALUES (?, 1);",
                           -1, &s, nullptr);
        sqlite3_bind_text(s, 1, t, -1, SQLITE_TRANSIENT);
        sqlite3_step(s);
        sqlite3_finalize(s);
    }
    // R18 (ADR-0024 Decision 9): the SoftwareLicensing securable's seeded
    // description DEFUSES its name — it does NOT gate the /inventory installed-
    // software catalog (that stays under Inventory:Read). Set it when empty (a
    // fresh boot inserts the row above with an empty description; an upgrade
    // inserts the new type fresh) — `AND description = ''` keeps this idempotent
    // and never clobbers an operator-set value, matching the INSERT OR IGNORE
    // seed-once posture of the rest of seed_defaults().
    sqlite3_exec(db_,
                 "UPDATE securable_types SET description = "
                 "'gates the /api/v1/sle/* detected-licence reads and the agent-decommission "
                 "erasure; the /inventory software catalog "
                 "remains under Inventory:Read' "
                 "WHERE name = 'SoftwareLicensing' AND description = '';",
                 nullptr, nullptr, nullptr);

    // Operations. "Push" is Guardian-specific — distributes a rule set to
    // scoped agents (design doc §9.2). It is a first-class operation in
    // the catalogue (every role can be granted Push explicitly) but the
    // Administrator and ITServiceOwner cross-type seed loops below use
    // `crud_ops` (no Push) so future handlers that accidentally check
    // `perm_fn(..., "Push")` on a non-Guardian securable do not silently
    // succeed against a seeded allow. Only the Guardian REST handlers
    // consult Push; grant it explicitly per role and per type.
    //
    // "Attest" is Periodic-Access-Review-specific (SOC 2 CC6.2) — recording a
    // reviewer's attested/flagged-revoke decision on an access-review
    // campaign row. Same treatment as Push: a first-class operation in the
    // catalogue, but deliberately EXCLUDED from `crud_ops` so the
    // Administrator/ITServiceOwner/Viewer cross-type loops below never widen
    // it onto an unrelated securable — it is granted explicitly, only on
    // AccessReview, only to Administrator and the new Reviewer role.
    const char* ops[] = {"Read", "Write", "Execute", "Delete", "Approve", "Push", "Attest"};
    const char* crud_ops[] = {"Read", "Write", "Execute", "Delete", "Approve"};
    for (auto* o : ops) {
        sqlite3_stmt* s = nullptr;
        sqlite3_prepare_v2(db_, "INSERT OR IGNORE INTO operations (id, is_system) VALUES (?, 1);",
                           -1, &s, nullptr);
        sqlite3_bind_text(s, 1, o, -1, SQLITE_TRANSIENT);
        sqlite3_step(s);
        sqlite3_finalize(s);
    }

    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();

    // Built-in roles
    struct RoleSeed {
        const char* name;
        const char* desc;
    };
    RoleSeed roles[] = {
        {"Administrator", "Full access to all operations"},
        {"PlatformEngineer", "Author and manage YAML instruction definitions, sets, and schemas"},
        {"Operator", "Execute and manage instructions, schedules, and tags"},
        {"ApiTokenManager", "Create, revoke, and manage API tokens for programmatic access"},
        {"ITServiceOwner", "Admin control over devices tagged with the same IT Service"},
        {"Viewer", "Read-only access to operational data"},
        // Periodic Access Reviews (SOC 2 CC6.2): a reviewer who can read the
        // grant-graph evidence and record attestation decisions on an
        // access-review campaign, without holding any of Administrator's
        // broader write access. AccessReview:Read + AccessReview:Attest only
        // — see the grants below.
        {"Reviewer", "Read audit evidence and attest/flag access-review grants (SOC 2 CC6.2)"},
    };
    for (auto& [name, desc] : roles) {
        sqlite3_stmt* s = nullptr;
        sqlite3_prepare_v2(db_,
                           "INSERT OR IGNORE INTO roles (name, description, is_system, created_at) "
                           "VALUES (?, ?, 1, ?);",
                           -1, &s, nullptr);
        sqlite3_bind_text(s, 1, name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s, 2, desc, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(s, 3, now);
        sqlite3_step(s);
        sqlite3_finalize(s);
    }

    // Administrator: CRUD on everything + Push on GuaranteedState only.
    // Seeding Push cross-type would be a latent privilege grant that any
    // future handler reading `perm_fn(..., "Push")` on a non-Guardian
    // securable would silently accept, so Push lives as a targeted grant
    // outside the main loop.
    for (auto* t : types) {
        for (auto* o : crud_ops) {
            sqlite3_stmt* s = nullptr;
            sqlite3_prepare_v2(
                db_,
                "INSERT OR IGNORE INTO role_permissions VALUES ('Administrator', ?, ?, 'allow');",
                -1, &s, nullptr);
            sqlite3_bind_text(s, 1, t, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(s, 2, o, -1, SQLITE_TRANSIENT);
            sqlite3_step(s);
            sqlite3_finalize(s);
        }
    }
    sqlite3_exec(
        db_,
        "INSERT OR IGNORE INTO role_permissions VALUES ('Administrator', 'GuaranteedState', 'Push', 'allow');",
        nullptr, nullptr, nullptr);
    // Administrator: Attest on AccessReview (Periodic Access Reviews, SOC 2
    // CC6.2) — same targeted-grant treatment as the Push grant above; Attest
    // is deliberately excluded from `crud_ops` so it is never seeded
    // cross-type by the loop.
    sqlite3_exec(
        db_,
        "INSERT OR IGNORE INTO role_permissions VALUES ('Administrator', 'AccessReview', 'Attest', "
        "'allow');",
        nullptr, nullptr, nullptr);

    // PlatformEngineer: full CRUD on definitions, sets, and read on related types
    const char* pe_full_types[] = {"InstructionDefinition", "InstructionSet"};
    const char* pe_full_ops[] = {"Read", "Write", "Execute", "Delete"};
    for (auto* t : pe_full_types) {
        for (auto* o : pe_full_ops) {
            sqlite3_stmt* s = nullptr;
            sqlite3_prepare_v2(db_,
                               "INSERT OR IGNORE INTO role_permissions VALUES ('PlatformEngineer', "
                               "?, ?, 'allow');",
                               -1, &s, nullptr);
            sqlite3_bind_text(s, 1, t, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(s, 2, o, -1, SQLITE_TRANSIENT);
            sqlite3_step(s);
            sqlite3_finalize(s);
        }
    }
    // PlatformEngineer: read on operational types for context (incl. SLE —
    // ADR-0024 Decision 9 D-9 matrix: PlatformEngineer Read).
    const char* pe_read_types[] = {"Execution", "Schedule", "Approval",         "Tag",
                                   "AuditLog",  "Response",  "SoftwareLicensing", "Inventory"};
    for (auto* t : pe_read_types) {
        sqlite3_stmt* s = nullptr;
        sqlite3_prepare_v2(db_,
                           "INSERT OR IGNORE INTO role_permissions VALUES ('PlatformEngineer', ?, "
                           "'Read', 'allow');",
                           -1, &s, nullptr);
        sqlite3_bind_text(s, 1, t, -1, SQLITE_TRANSIENT);
        sqlite3_step(s);
        sqlite3_finalize(s);
    }
    // PlatformEngineer: read + write + delete on Policy
    {
        const char* pe_policy_ops[] = {"Read", "Write", "Delete"};
        for (auto* o : pe_policy_ops) {
            sqlite3_stmt* s = nullptr;
            sqlite3_prepare_v2(db_,
                               "INSERT OR IGNORE INTO role_permissions VALUES ('PlatformEngineer', "
                               "'Policy', ?, 'allow');",
                               -1, &s, nullptr);
            sqlite3_bind_text(s, 1, o, -1, SQLITE_TRANSIENT);
            sqlite3_step(s);
            sqlite3_finalize(s);
        }
    }

    // Operator: read/write/execute on operational types, read on audit/response
    const char* op_rwe_types[] = {"InstructionDefinition", "InstructionSet", "Execution",
                                  "Schedule", "Tag"};
    const char* op_rwe_ops[] = {"Read", "Write", "Execute"};
    for (auto* t : op_rwe_types) {
        for (auto* o : op_rwe_ops) {
            sqlite3_stmt* s = nullptr;
            sqlite3_prepare_v2(
                db_, "INSERT OR IGNORE INTO role_permissions VALUES ('Operator', ?, ?, 'allow');",
                -1, &s, nullptr);
            sqlite3_bind_text(s, 1, t, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(s, 2, o, -1, SQLITE_TRANSIENT);
            sqlite3_step(s);
            sqlite3_finalize(s);
        }
    }
    // Operator: delete on operational types
    for (auto* t : op_rwe_types) {
        sqlite3_stmt* s = nullptr;
        sqlite3_prepare_v2(
            db_,
            "INSERT OR IGNORE INTO role_permissions VALUES ('Operator', ?, 'Delete', 'allow');", -1,
            &s, nullptr);
        sqlite3_bind_text(s, 1, t, -1, SQLITE_TRANSIENT);
        sqlite3_step(s);
        sqlite3_finalize(s);
    }
    // Operator: approve on Approval
    sqlite3_exec(
        db_,
        "INSERT OR IGNORE INTO role_permissions VALUES ('Operator', 'Approval', 'Read', 'allow');",
        nullptr, nullptr, nullptr);
    sqlite3_exec(db_,
                 "INSERT OR IGNORE INTO role_permissions VALUES ('Operator', 'Approval', "
                 "'Approve', 'allow');",
                 nullptr, nullptr, nullptr);
    // Operator: read on AuditLog, Response
    sqlite3_exec(
        db_,
        "INSERT OR IGNORE INTO role_permissions VALUES ('Operator', 'AuditLog', 'Read', 'allow');",
        nullptr, nullptr, nullptr);
    sqlite3_exec(
        db_,
        "INSERT OR IGNORE INTO role_permissions VALUES ('Operator', 'Response', 'Read', 'allow');",
        nullptr, nullptr, nullptr);
    // Operator: read + execute on Policy
    sqlite3_exec(
        db_,
        "INSERT OR IGNORE INTO role_permissions VALUES ('Operator', 'Policy', 'Read', 'allow');",
        nullptr, nullptr, nullptr);
    sqlite3_exec(
        db_,
        "INSERT OR IGNORE INTO role_permissions VALUES ('Operator', 'Policy', 'Execute', 'allow');",
        nullptr, nullptr, nullptr);
    // Operator: read + execute on SoftwareDeployment
    sqlite3_exec(
        db_,
        "INSERT OR IGNORE INTO role_permissions VALUES ('Operator', 'SoftwareDeployment', 'Read', 'allow');",
        nullptr, nullptr, nullptr);
    sqlite3_exec(
        db_,
        "INSERT OR IGNORE INTO role_permissions VALUES ('Operator', 'SoftwareDeployment', 'Execute', 'allow');",
        nullptr, nullptr, nullptr);
    // Operator: read on DeviceToken
    sqlite3_exec(
        db_,
        "INSERT OR IGNORE INTO role_permissions VALUES ('Operator', 'DeviceToken', 'Read', 'allow');",
        nullptr, nullptr, nullptr);
    // Operator: read on License
    sqlite3_exec(
        db_,
        "INSERT OR IGNORE INTO role_permissions VALUES ('Operator', 'License', 'Read', 'allow');",
        nullptr, nullptr, nullptr);
    // Operator: read on Inventory — triaging a device includes seeing its
    // installed software (ADR-0016).
    sqlite3_exec(
        db_,
        "INSERT OR IGNORE INTO role_permissions VALUES ('Operator', 'Inventory', 'Read', 'allow');",
        nullptr, nullptr, nullptr);
    // Operator: read + write on SoftwareLicensing (ADR-0024 Decision 9 D-9 matrix:
    // Operator Read + Write). Write is granted now even though PR1a ships no write
    // endpoints — the matrix is seeded ONCE; entitlement CRUD arrives in PR2. NOT
    // Execute/Delete/Approve (that is ITServiceOwner's full-CRUD tier).
    sqlite3_exec(db_,
                 "INSERT OR IGNORE INTO role_permissions VALUES ('Operator', "
                 "'SoftwareLicensing', 'Read', 'allow');",
                 nullptr, nullptr, nullptr);
    sqlite3_exec(db_,
                 "INSERT OR IGNORE INTO role_permissions VALUES ('Operator', "
                 "'SoftwareLicensing', 'Write', 'allow');",
                 nullptr, nullptr, nullptr);
    // Operator: read + write on FileRetrieval
    sqlite3_exec(
        db_,
        "INSERT OR IGNORE INTO role_permissions VALUES ('Operator', 'FileRetrieval', 'Read', 'allow');",
        nullptr, nullptr, nullptr);
    sqlite3_exec(
        db_,
        "INSERT OR IGNORE INTO role_permissions VALUES ('Operator', 'FileRetrieval', 'Write', 'allow');",
        nullptr, nullptr, nullptr);

    // Operator: read + push on GuaranteedState — they can distribute an
    // existing rule set but cannot author or delete rules. Authoring is
    // privileged and lives with PlatformEngineer / Administrator.
    sqlite3_exec(
        db_,
        "INSERT OR IGNORE INTO role_permissions VALUES ('Operator', 'GuaranteedState', 'Read', 'allow');",
        nullptr, nullptr, nullptr);
    sqlite3_exec(
        db_,
        "INSERT OR IGNORE INTO role_permissions VALUES ('Operator', 'GuaranteedState', 'Push', 'allow');",
        nullptr, nullptr, nullptr);

    // PlatformEngineer: full CRUD + Push on GuaranteedState. Mirrors the
    // pattern they have for InstructionDefinition — they author the rules
    // and need to push the set to fleet for testing.
    {
        const char* gs_ops[] = {"Read", "Write", "Delete", "Push"};
        for (auto* o : gs_ops) {
            sqlite3_stmt* s = nullptr;
            sqlite3_prepare_v2(db_,
                               "INSERT OR IGNORE INTO role_permissions VALUES ('PlatformEngineer', "
                               "'GuaranteedState', ?, 'allow');",
                               -1, &s, nullptr);
            sqlite3_bind_text(s, 1, o, -1, SQLITE_TRANSIENT);
            sqlite3_step(s);
            sqlite3_finalize(s);
        }
    }

    // ApiTokenManager: read + write + delete on ApiToken
    const char* atm_ops[] = {"Read", "Write", "Delete"};
    for (auto* o : atm_ops) {
        sqlite3_stmt* s = nullptr;
        sqlite3_prepare_v2(
            db_,
            "INSERT OR IGNORE INTO role_permissions VALUES ('ApiTokenManager', 'ApiToken', ?, "
            "'allow');",
            -1, &s, nullptr);
        sqlite3_bind_text(s, 1, o, -1, SQLITE_TRANSIENT);
        sqlite3_step(s);
        sqlite3_finalize(s);
    }

    // ITServiceOwner: broad access on operational types (excludes UserManagement, Security,
    // ApiToken)
    const char* itso_types[] = {"Infrastructure",
                                "InstructionDefinition",
                                "InstructionSet",
                                "Execution",
                                "Schedule",
                                "Approval",
                                "Tag",
                                "AuditLog",
                                "Response",
                                "ManagementGroup",
                                "Policy",
                                "DeviceToken",
                                "SoftwareDeployment",
                                "License",
                                "FileRetrieval",
                                "GuaranteedState",
                                "Inventory",
                                // SLE full CRUD (ADR-0024 Decision 9 D-9 matrix:
                                // ITServiceOwner full CRUD, as for its other
                                // operational securables).
                                "SoftwareLicensing"};
    // Same Push-restriction rationale as Administrator above: CRUD cross-type,
    // Push only on GuaranteedState where it is actually consulted.
    for (auto* t : itso_types) {
        for (auto* o : crud_ops) {
            sqlite3_stmt* s = nullptr;
            sqlite3_prepare_v2(
                db_,
                "INSERT OR IGNORE INTO role_permissions VALUES ('ITServiceOwner', ?, ?, 'allow');",
                -1, &s, nullptr);
            sqlite3_bind_text(s, 1, t, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(s, 2, o, -1, SQLITE_TRANSIENT);
            sqlite3_step(s);
            sqlite3_finalize(s);
        }
    }
    sqlite3_exec(
        db_,
        "INSERT OR IGNORE INTO role_permissions VALUES ('ITServiceOwner', 'GuaranteedState', 'Push', 'allow');",
        nullptr, nullptr, nullptr);

    // Viewer: read on all except Infrastructure
    const char* viewer_types[] = {"UserManagement",
                                  "InstructionDefinition",
                                  "InstructionSet",
                                  "Execution",
                                  "Schedule",
                                  "Approval",
                                  "Tag",
                                  "AuditLog",
                                  "Response",
                                  "ManagementGroup",
                                  "ApiToken",
                                  "Security",
                                  "Policy",
                                  "DeviceToken",
                                  "SoftwareDeployment",
                                  "License",
                                  "FileRetrieval",
                                  "GuaranteedState",
                                  "Inventory",
                                  // SLE Read (ADR-0024 Decision 9 D-9 matrix: Viewer
                                  // Read). R18 upgrade note: deployments restricting
                                  // entitlement-cost visibility deny/remove this Viewer
                                  // grant before enabling the SLE sources (deny-override
                                  // wins) — see the seeded securable description.
                                  "SoftwareLicensing"};
    for (auto* t : viewer_types) {
        sqlite3_stmt* s = nullptr;
        sqlite3_prepare_v2(
            db_, "INSERT OR IGNORE INTO role_permissions VALUES ('Viewer', ?, 'Read', 'allow');",
            -1, &s, nullptr);
        sqlite3_bind_text(s, 1, t, -1, SQLITE_TRANSIENT);
        sqlite3_step(s);
        sqlite3_finalize(s);
    }

    // Reviewer (Periodic Access Reviews, SOC 2 CC6.2): AccessReview:Read
    // (browse the evidence trail) + AccessReview:Attest (record a decision
    // on a campaign row). Deliberately NOT crud_ops — a reviewer must not
    // gain Write/Delete/Approve on AccessReview, only the ability to read
    // and attest.
    sqlite3_exec(
        db_,
        "INSERT OR IGNORE INTO role_permissions VALUES ('Reviewer', 'AccessReview', 'Read', "
        "'allow');",
        nullptr, nullptr, nullptr);
    sqlite3_exec(
        db_,
        "INSERT OR IGNORE INTO role_permissions VALUES ('Reviewer', 'AccessReview', 'Attest', "
        "'allow');",
        nullptr, nullptr, nullptr);
}

void RbacStore::load_enabled_flag() {
    if (!db_)
        return;
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_, "SELECT value FROM rbac_config WHERE key='enabled';", -1, &s,
                           nullptr) == SQLITE_OK) {
        if (sqlite3_step(s) == SQLITE_ROW) {
            auto* v = reinterpret_cast<const char*>(sqlite3_column_text(s, 0));
            rbac_enabled_.store(v && std::string(v) == "true");
        }
        sqlite3_finalize(s);
    }
}

// ── Global toggle ────────────────────────────────────────────────────────────

bool RbacStore::is_rbac_enabled() const {
    return rbac_enabled_.load();
}

void RbacStore::set_rbac_enabled(bool enabled) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return;
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_, "INSERT OR REPLACE INTO rbac_config VALUES ('enabled', ?);", -1, &s,
                           nullptr) == SQLITE_OK) {
        sqlite3_bind_text(s, 1, enabled ? "true" : "false", -1, SQLITE_TRANSIENT);
        sqlite3_step(s);
        sqlite3_finalize(s);
        rbac_enabled_.store(enabled);
    }
}

bool rbac_enforcement_in_effect(const RbacStore* store) noexcept {
    // Permit the full-fleet fallback (return false) ONLY for a store that is
    // loaded AND explicitly disabled. Null / load-failed (!is_open()) fail
    // CLOSED — see the header for the #1498 rationale.
    return !(store && store->is_open() && !store->is_rbac_enabled());
}

// ── Roles CRUD ───────────────────────────────────────────────────────────────

std::vector<RbacRole> RbacStore::list_roles() const {
    std::shared_lock lock(mtx_);
    std::vector<RbacRole> result;
    if (!db_)
        return result;
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "SELECT name, description, is_system, created_at FROM roles ORDER BY "
                           "is_system DESC, name;",
                           -1, &s, nullptr) != SQLITE_OK)
        return result;
    while (sqlite3_step(s) == SQLITE_ROW) {
        RbacRole r;
        r.name = reinterpret_cast<const char*>(sqlite3_column_text(s, 0));
        r.description = reinterpret_cast<const char*>(sqlite3_column_text(s, 1));
        r.is_system = sqlite3_column_int(s, 2) != 0;
        r.created_at = sqlite3_column_int64(s, 3);
        result.push_back(std::move(r));
    }
    sqlite3_finalize(s);
    return result;
}

std::optional<RbacRole> RbacStore::get_role(const std::string& name) const {
    std::shared_lock lock(mtx_);
    if (!db_)
        return std::nullopt;
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(
            db_, "SELECT name, description, is_system, created_at FROM roles WHERE name = ?;", -1,
            &s, nullptr) != SQLITE_OK)
        return std::nullopt;
    sqlite3_bind_text(s, 1, name.c_str(), -1, SQLITE_TRANSIENT);
    std::optional<RbacRole> result;
    if (sqlite3_step(s) == SQLITE_ROW) {
        RbacRole r;
        r.name = reinterpret_cast<const char*>(sqlite3_column_text(s, 0));
        r.description = reinterpret_cast<const char*>(sqlite3_column_text(s, 1));
        r.is_system = sqlite3_column_int(s, 2) != 0;
        r.created_at = sqlite3_column_int64(s, 3);
        result = std::move(r);
    }
    sqlite3_finalize(s);
    return result;
}

std::expected<void, std::string> RbacStore::create_role(const RbacRole& role) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return std::unexpected("database not open");
    if (role.name.empty())
        return std::unexpected("role name cannot be empty");

    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(
            db_,
            "INSERT INTO roles (name, description, is_system, created_at) VALUES (?, ?, 0, ?);", -1,
            &s, nullptr) != SQLITE_OK)
        return std::unexpected(sqlite3_errmsg(db_));
    sqlite3_bind_text(s, 1, role.name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 2, role.description.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(s, 3, now);
    int rc = sqlite3_step(s);
    sqlite3_finalize(s);
    if (rc != SQLITE_DONE)
        return std::unexpected(std::string("role already exists or DB error: ") +
                               sqlite3_errmsg(db_));
    return {};
}

std::expected<void, std::string> RbacStore::update_role(const std::string& name,
                                                        const std::string& description) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return std::unexpected("database not open");
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_, "UPDATE roles SET description = ? WHERE name = ?;", -1, &s,
                           nullptr) != SQLITE_OK)
        return std::unexpected(sqlite3_errmsg(db_));
    sqlite3_bind_text(s, 1, description.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 2, name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(s);
    sqlite3_finalize(s);
    if (sqlite3_changes(db_) == 0)
        return std::unexpected("role not found");
    return {};
}

std::expected<void, std::string> RbacStore::delete_role(const std::string& name) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return std::unexpected("database not open");

    // Check system role protection inline (avoid calling get_role which takes its own lock)
    {
        sqlite3_stmt* chk = nullptr;
        if (sqlite3_prepare_v2(db_, "SELECT is_system FROM roles WHERE name = ?;", -1, &chk,
                               nullptr) != SQLITE_OK)
            return std::unexpected(sqlite3_errmsg(db_));
        sqlite3_bind_text(chk, 1, name.c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(chk) != SQLITE_ROW) {
            sqlite3_finalize(chk);
            return std::unexpected("role not found");
        }
        bool is_sys = sqlite3_column_int(chk, 0) != 0;
        sqlite3_finalize(chk);
        if (is_sys)
            return std::unexpected("cannot delete system role");
    }

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_, "DELETE FROM roles WHERE name = ? AND is_system = 0;", -1, &s,
                           nullptr) != SQLITE_OK)
        return std::unexpected(sqlite3_errmsg(db_));
    sqlite3_bind_text(s, 1, name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(s);
    sqlite3_finalize(s);
    return {};
}

// ── Permissions CRUD ─────────────────────────────────────────────────────────

std::vector<Permission> RbacStore::get_role_permissions(const std::string& role_name) const {
    std::shared_lock lock(mtx_);
    std::vector<Permission> result;
    if (!db_)
        return result;
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(
            db_,
            "SELECT role_name, securable_type, operation, effect "
            "FROM role_permissions WHERE role_name = ? ORDER BY securable_type, operation;",
            -1, &s, nullptr) != SQLITE_OK)
        return result;
    sqlite3_bind_text(s, 1, role_name.c_str(), -1, SQLITE_TRANSIENT);
    while (sqlite3_step(s) == SQLITE_ROW) {
        Permission p;
        p.role_name = reinterpret_cast<const char*>(sqlite3_column_text(s, 0));
        p.securable_type = reinterpret_cast<const char*>(sqlite3_column_text(s, 1));
        p.operation = reinterpret_cast<const char*>(sqlite3_column_text(s, 2));
        p.effect = reinterpret_cast<const char*>(sqlite3_column_text(s, 3));
        result.push_back(std::move(p));
    }
    sqlite3_finalize(s);
    return result;
}

std::expected<std::vector<Permission>, std::string>
RbacStore::get_role_permissions_checked(const std::string& role_name) const {
    std::shared_lock lock(mtx_);
    std::vector<Permission> result;
    if (!db_)
        return std::unexpected("rbac store not open");
    SqliteStmt s;
    if (sqlite3_prepare_v2(
            db_,
            "SELECT role_name, securable_type, operation, effect "
            "FROM role_permissions WHERE role_name = ? ORDER BY securable_type, operation;",
            -1, s.addr(), nullptr) != SQLITE_OK)
        return std::unexpected(std::string("prepare failed: ") + sqlite3_errmsg(db_));
    sqlite3_bind_text(s.get(), 1, role_name.c_str(), -1, SQLITE_TRANSIENT);
    int rc = SQLITE_OK;
    while ((rc = sqlite3_step(s.get())) == SQLITE_ROW) {
        Permission p;
        p.role_name = reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 0));
        p.securable_type = reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 1));
        p.operation = reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 2));
        p.effect = reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 3));
        result.push_back(std::move(p));
    }
    s.reset();
    if (rc != SQLITE_DONE)
        return std::unexpected(std::string("query failed: ") + sqlite3_errmsg(db_));
    return result;
}

std::expected<std::vector<Permission>, std::string>
RbacStore::list_all_role_permissions_checked() const {
    std::shared_lock lock(mtx_);
    std::vector<Permission> result;
    if (!db_)
        return std::unexpected("rbac store not open");
    SqliteStmt s;
    if (sqlite3_prepare_v2(
            db_,
            "SELECT role_name, securable_type, operation, effect "
            "FROM role_permissions ORDER BY role_name, securable_type, operation;",
            -1, s.addr(), nullptr) != SQLITE_OK)
        return std::unexpected(std::string("prepare failed: ") + sqlite3_errmsg(db_));
    int rc = SQLITE_OK;
    while ((rc = sqlite3_step(s.get())) == SQLITE_ROW) {
        Permission p;
        p.role_name = reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 0));
        p.securable_type = reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 1));
        p.operation = reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 2));
        p.effect = reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 3));
        result.push_back(std::move(p));
    }
    s.reset();
    if (rc != SQLITE_DONE)
        return std::unexpected(std::string("query failed: ") + sqlite3_errmsg(db_));
    return result;
}

std::expected<void, std::string> RbacStore::set_permission(const Permission& perm) {
    if (perm.effect != "allow" && perm.effect != "deny")
        return std::unexpected("effect must be 'allow' or 'deny'");
    std::unique_lock lock(mtx_);
    if (!db_)
        return std::unexpected("database not open");
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "INSERT OR REPLACE INTO role_permissions (role_name, securable_type, "
                           "operation, effect) "
                           "VALUES (?, ?, ?, ?);",
                           -1, &s, nullptr) != SQLITE_OK)
        return std::unexpected(sqlite3_errmsg(db_));
    sqlite3_bind_text(s, 1, perm.role_name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 2, perm.securable_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 3, perm.operation.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 4, perm.effect.c_str(), -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(s);
    sqlite3_finalize(s);
    if (rc != SQLITE_DONE)
        return std::unexpected(sqlite3_errmsg(db_));
    invalidate_perm_cache();
    return {};
}

std::expected<void, std::string> RbacStore::remove_permission(const std::string& role_name,
                                                              const std::string& securable_type,
                                                              const std::string& operation) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return std::unexpected("database not open");
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "DELETE FROM role_permissions WHERE role_name = ? AND securable_type = "
                           "? AND operation = ?;",
                           -1, &s, nullptr) != SQLITE_OK)
        return std::unexpected(sqlite3_errmsg(db_));
    sqlite3_bind_text(s, 1, role_name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 2, securable_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 3, operation.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(s);
    sqlite3_finalize(s);
    invalidate_perm_cache();
    return {};
}

// ── Principal-role assignments ───────────────────────────────────────────────

std::vector<PrincipalRole> RbacStore::get_principal_roles(const std::string& principal_type,
                                                          const std::string& principal_id) const {
    std::shared_lock lock(mtx_);
    std::vector<PrincipalRole> result;
    if (!db_)
        return result;
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "SELECT principal_type, principal_id, role_name FROM principal_roles "
                           "WHERE principal_type = ? AND principal_id = ? ORDER BY role_name;",
                           -1, &s, nullptr) != SQLITE_OK)
        return result;
    sqlite3_bind_text(s, 1, principal_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 2, principal_id.c_str(), -1, SQLITE_TRANSIENT);
    while (sqlite3_step(s) == SQLITE_ROW) {
        PrincipalRole pr;
        pr.principal_type = reinterpret_cast<const char*>(sqlite3_column_text(s, 0));
        pr.principal_id = reinterpret_cast<const char*>(sqlite3_column_text(s, 1));
        pr.role_name = reinterpret_cast<const char*>(sqlite3_column_text(s, 2));
        result.push_back(std::move(pr));
    }
    sqlite3_finalize(s);
    return result;
}

std::expected<std::vector<PrincipalRole>, std::string>
RbacStore::get_principal_roles_checked(const std::string& principal_type,
                                       const std::string& principal_id) const {
    std::shared_lock lock(mtx_);
    std::vector<PrincipalRole> result;
    if (!db_)
        return std::unexpected("rbac store not open");
    SqliteStmt s;
    if (sqlite3_prepare_v2(db_,
                           "SELECT principal_type, principal_id, role_name FROM principal_roles "
                           "WHERE principal_type = ? AND principal_id = ? ORDER BY role_name;",
                           -1, s.addr(), nullptr) != SQLITE_OK)
        return std::unexpected(std::string("prepare failed: ") + sqlite3_errmsg(db_));
    sqlite3_bind_text(s.get(), 1, principal_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s.get(), 2, principal_id.c_str(), -1, SQLITE_TRANSIENT);
    int rc = SQLITE_OK;
    while ((rc = sqlite3_step(s.get())) == SQLITE_ROW) {
        PrincipalRole pr;
        pr.principal_type = reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 0));
        pr.principal_id = reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 1));
        pr.role_name = reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 2));
        result.push_back(std::move(pr));
    }
    s.reset();
    if (rc != SQLITE_DONE)
        return std::unexpected(std::string("query failed: ") + sqlite3_errmsg(db_));
    return result;
}

std::expected<std::vector<PrincipalRole>, std::string>
RbacStore::list_all_principal_roles_checked() const {
    std::shared_lock lock(mtx_);
    std::vector<PrincipalRole> result;
    if (!db_)
        return std::unexpected("rbac store not open");
    SqliteStmt s;
    if (sqlite3_prepare_v2(db_,
                           "SELECT principal_type, principal_id, role_name FROM principal_roles "
                           "ORDER BY principal_type, principal_id, role_name;",
                           -1, s.addr(), nullptr) != SQLITE_OK)
        return std::unexpected(std::string("prepare failed: ") + sqlite3_errmsg(db_));
    int rc = SQLITE_OK;
    while ((rc = sqlite3_step(s.get())) == SQLITE_ROW) {
        PrincipalRole pr;
        pr.principal_type = reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 0));
        pr.principal_id = reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 1));
        pr.role_name = reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 2));
        result.push_back(std::move(pr));
    }
    s.reset();
    if (rc != SQLITE_DONE)
        return std::unexpected(std::string("query failed: ") + sqlite3_errmsg(db_));
    return result;
}

std::vector<PrincipalRole> RbacStore::get_role_members(const std::string& role_name) const {
    std::shared_lock lock(mtx_);
    std::vector<PrincipalRole> result;
    if (!db_)
        return result;
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "SELECT principal_type, principal_id, role_name FROM principal_roles "
                           "WHERE role_name = ? ORDER BY principal_type, principal_id;",
                           -1, &s, nullptr) != SQLITE_OK)
        return result;
    sqlite3_bind_text(s, 1, role_name.c_str(), -1, SQLITE_TRANSIENT);
    while (sqlite3_step(s) == SQLITE_ROW) {
        PrincipalRole pr;
        pr.principal_type = reinterpret_cast<const char*>(sqlite3_column_text(s, 0));
        pr.principal_id = reinterpret_cast<const char*>(sqlite3_column_text(s, 1));
        pr.role_name = reinterpret_cast<const char*>(sqlite3_column_text(s, 2));
        result.push_back(std::move(pr));
    }
    sqlite3_finalize(s);
    return result;
}

std::expected<void, std::string> RbacStore::validate_assignment(const std::string& principal_type,
                                                                 const std::string& principal_id,
                                                                 const std::string& role_name) {
    // F2 (Hermes pass-2 MEDIUM, worst finding): an `engine:`-prefixed
    // principal_id must ONLY ever be assigned under principal_type=="engine".
    // Without this, a caller could mint a shadow row
    // `('user', 'engine:x', role)` that `collect_roles_locked`'s user arm
    // would happily match at role-resolution time — silently attributing an
    // engine identity's permissions to whatever attacker-controlled "user"
    // lookup produces that principal_id, entirely bypassing the engine-only
    // checks below. Reject regardless of principal_type.
    if (principal_type != "engine" && principal_id.starts_with(kEnginePrefix))
        return std::unexpected(
            "principal_id in the reserved 'engine:' namespace may only be assigned under "
            "principal_type=\"engine\"");

    // Also reject any principal_type outside the recognized set — this
    // function is the single validation chokepoint for assign_role, so an
    // unrecognized principal_type (typo, or an attacker probing for an
    // unvalidated arm) must fail closed here rather than silently falling
    // through to the `{}` return below.
    if (principal_type != "user" && principal_type != "group" && principal_type != "engine")
        return std::unexpected("unrecognized principal_type '" + principal_type + "'");

    // user/group assignment behavior is completely unchanged — a hard
    // invariant, exercised by every pre-existing caller of assign_role.
    if (principal_type != "engine")
        return {};

    // Matches engine_principal_store.cpp::create's own prefix check exactly
    // (`starts_with` + non-empty-slug), so the two guards can never drift.
    if (!principal_id.starts_with(kEnginePrefix) || principal_id.size() == kEnginePrefix.size())
        return std::unexpected(
            "engine principal_id must be in the reserved 'engine:<slug>' namespace with a "
            "non-empty slug");

    for (auto disallowed : kEngineDisallowedRoles) {
        if (role_name == disallowed)
            return std::unexpected("engine principals cannot be granted the admin/full-access "
                                   "role '" +
                                   role_name + "' — no admin, ever (design §4.2)");
    }
    return {};
}

std::expected<void, std::string> RbacStore::assign_role(const PrincipalRole& pr) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return std::unexpected("database not open");
    if (auto v = validate_assignment(pr.principal_type, pr.principal_id, pr.role_name); !v)
        return std::unexpected(v.error());

    // F1 (Hermes pass-1 H1, downgraded MEDIUM by architect): generalize the
    // "no admin, ever" bar to "no built-in role, ever" for engine
    // principals. `validate_assignment` is `static` and has no DB handle, so
    // it can only bar the two hardcoded literal role names
    // (`kEngineDisallowedRoles`) — that's a manual-extend footgun for any
    // future `is_system` role (see the comment on that array). This
    // fleet-wide path DOES have DB access, so query the role's own
    // `is_system` flag (same idiom as `delete_role`'s system-role-protection
    // check above) and reject any built-in role outright. The literal check
    // in `validate_assignment` stays as defense-in-depth (the legacy "admin"
    // string isn't itself a `roles` row, so it wouldn't be caught here).
    // Residual: a custom (`is_system=0`) role that happens to be granted
    // fleet-wide/unrestricted permissions is NOT caught by this bar — that
    // is closed by the independent auditor-runnable verification query
    // (decision log #13, PR 4.3/4.4), never by trying to enumerate
    // "dangerous" permission combinations here (trivially bypassable and
    // falsely advertises completeness).
    if (pr.principal_type == "engine") {
        sqlite3_stmt* chk = nullptr;
        if (sqlite3_prepare_v2(db_, "SELECT is_system FROM roles WHERE name = ?;", -1, &chk,
                               nullptr) != SQLITE_OK)
            return std::unexpected(sqlite3_errmsg(db_));
        sqlite3_bind_text(chk, 1, pr.role_name.c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(chk) == SQLITE_ROW) {
            bool is_sys = sqlite3_column_int(chk, 0) != 0;
            sqlite3_finalize(chk);
            if (is_sys)
                return std::unexpected(
                    "engine principals cannot be granted a built-in system role '" +
                    pr.role_name + "' — no built-in role, ever (design §4.2)");
        } else {
            sqlite3_finalize(chk);
        }
    }

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(
            db_,
            "INSERT OR IGNORE INTO principal_roles (principal_type, principal_id, role_name) "
            "VALUES (?, ?, ?);",
            -1, &s, nullptr) != SQLITE_OK)
        return std::unexpected(sqlite3_errmsg(db_));
    sqlite3_bind_text(s, 1, pr.principal_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 2, pr.principal_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 3, pr.role_name.c_str(), -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(s);
    sqlite3_finalize(s);
    if (rc != SQLITE_DONE)
        return std::unexpected(sqlite3_errmsg(db_));
    invalidate_perm_cache();
    return {};
}

std::expected<void, std::string> RbacStore::unassign_role(const std::string& principal_type,
                                                          const std::string& principal_id,
                                                          const std::string& role_name) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return std::unexpected("database not open");
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "DELETE FROM principal_roles WHERE principal_type = ? AND principal_id "
                           "= ? AND role_name = ?;",
                           -1, &s, nullptr) != SQLITE_OK)
        return std::unexpected(sqlite3_errmsg(db_));
    sqlite3_bind_text(s, 1, principal_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 2, principal_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 3, role_name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(s);
    sqlite3_finalize(s);
    invalidate_perm_cache();
    return {};
}

// ── Groups CRUD ──────────────────────────────────────────────────────────────

std::vector<RbacGroup> RbacStore::list_groups() const {
    std::shared_lock lock(mtx_);
    std::vector<RbacGroup> result;
    if (!db_)
        return result;
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(
            db_,
            "SELECT name, description, source, external_id, created_at FROM groups ORDER BY name;",
            -1, &s, nullptr) != SQLITE_OK)
        return result;
    while (sqlite3_step(s) == SQLITE_ROW) {
        RbacGroup g;
        g.name = reinterpret_cast<const char*>(sqlite3_column_text(s, 0));
        g.description = reinterpret_cast<const char*>(sqlite3_column_text(s, 1));
        g.source = reinterpret_cast<const char*>(sqlite3_column_text(s, 2));
        auto* eid = reinterpret_cast<const char*>(sqlite3_column_text(s, 3));
        g.external_id = eid ? eid : "";
        g.created_at = sqlite3_column_int64(s, 4);
        result.push_back(std::move(g));
    }
    sqlite3_finalize(s);
    return result;
}

std::expected<std::vector<RbacGroup>, std::string> RbacStore::list_groups_checked() const {
    std::shared_lock lock(mtx_);
    std::vector<RbacGroup> result;
    if (!db_)
        return std::unexpected("rbac store not open");
    SqliteStmt s;
    if (sqlite3_prepare_v2(
            db_,
            "SELECT name, description, source, external_id, created_at FROM groups ORDER BY name;",
            -1, s.addr(), nullptr) != SQLITE_OK)
        return std::unexpected(std::string("prepare failed: ") + sqlite3_errmsg(db_));
    int rc = SQLITE_OK;
    while ((rc = sqlite3_step(s.get())) == SQLITE_ROW) {
        RbacGroup g;
        g.name = reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 0));
        g.description = reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 1));
        g.source = reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 2));
        auto* eid = reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 3));
        g.external_id = eid ? eid : "";
        g.created_at = sqlite3_column_int64(s.get(), 4);
        result.push_back(std::move(g));
    }
    s.reset();
    if (rc != SQLITE_DONE)
        return std::unexpected(std::string("query failed: ") + sqlite3_errmsg(db_));
    return result;
}

std::optional<std::vector<std::string>>
RbacStore::find_local_groups_with_prefix(const std::string& prefix) const {
    std::shared_lock lock(mtx_);
    std::vector<std::string> result;
    // A closed/unopened store is a scan FAILURE, not "nothing to match" —
    // signal it distinctly (nullopt) so the T8 preflight fails closed
    // instead of trusting an engaged-but-empty result.
    if (!db_)
        return std::nullopt;
    // `prefix` is code-controlled (e.g. `kEnginePrefix`), never user input —
    // fail closed (empty result) rather than trust the caller if it ever
    // carries a LIKE metacharacter, matching audit_store.cpp's action-prefix
    // guard (`%`/`_`/`\` would otherwise widen the match).
    if (prefix.empty() || prefix.find_first_of("%_\\") != std::string::npos)
        return result;
    // Scoped to `source = 'local'` — an IdP-sourced group asserting a
    // same-prefixed name is disambiguated by `principal_type` at the
    // resolution site (§3.3) and is not the namespace collision a LOCAL
    // group of that name would be; this backs the T8 startup collision
    // preflight (decision log #3), which only needs to find LOCAL create
    // paths that predate the `has_reserved_idp_prefix` guard above.
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_, "SELECT name FROM groups WHERE source = 'local' AND name LIKE ?;",
                           -1, &s, nullptr) != SQLITE_OK) {
        // G3: a prepare failure is a scan error, not "no rows" — signal it
        // distinctly so the T8 preflight fails closed instead of booting.
        spdlog::error("find_local_groups_with_prefix: failed to prepare scan statement: {}",
                     sqlite3_errmsg(db_));
        return std::nullopt;
    }
    std::string pattern = prefix + "%";
    sqlite3_bind_text(s, 1, pattern.c_str(), -1, SQLITE_TRANSIENT);
    int rc;
    while ((rc = sqlite3_step(s)) == SQLITE_ROW) {
        // Explicit length, not implicit strlen() via the NUL-terminated
        // char* — matches scim_store.cpp's row_to_resource text_col idiom
        // (a group name could in principle carry an embedded NUL from a
        // pre-hardening write path; a collision scan must not silently
        // truncate what it reports).
        const unsigned char* t = sqlite3_column_text(s, 0);
        if (t) {
            result.emplace_back(reinterpret_cast<const char*>(t),
                                static_cast<std::size_t>(sqlite3_column_bytes(s, 0)));
        }
    }
    sqlite3_finalize(s);
    // G3 (UP-2, cpp-safety): a mid-scan SQLite error (rc != SQLITE_DONE)
    // previously fell through silently, returning whatever rows had been
    // collected so far as if the scan had completed cleanly — the T8 boot
    // preflight would then read a partial (possibly empty) result as
    // "no collision" and boot with a live namespace collision undetected.
    // Signal the error distinctly via nullopt so the caller can fail closed.
    if (rc != SQLITE_DONE) {
        spdlog::error("find_local_groups_with_prefix: scan of prefix '{}' failed: {}", prefix,
                     sqlite3_errmsg(db_));
        return std::nullopt;
    }
    return result;
}

std::expected<void, std::string> RbacStore::create_group(const RbacGroup& group) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return std::unexpected("database not open");
    if (group.name.empty())
        return std::unexpected("group name cannot be empty");
    // #1832 confused-deputy guard: a source='local' create can't claim an
    // IdP namespace prefix — IdP-sourced creates (reconcile_idp_memberships,
    // or a future non-local caller of this API) are exempt since they never
    // present source=='local'.
    if (group.source == "local" && has_reserved_idp_prefix(group.name))
        return std::unexpected(
            "group name uses a reserved identity-provider or engine-principal namespace prefix "
            "(local:/entra:/saml:/ad:/engine:)");
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "INSERT INTO groups (name, description, source, external_id, "
                           "created_at) VALUES (?, ?, ?, ?, ?);",
                           -1, &s, nullptr) != SQLITE_OK)
        return std::unexpected(sqlite3_errmsg(db_));
    sqlite3_bind_text(s, 1, group.name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 2, group.description.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 3, group.source.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 4, group.external_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(s, 5, now);
    int rc = sqlite3_step(s);
    sqlite3_finalize(s);
    if (rc != SQLITE_DONE)
        return std::unexpected(std::string("group already exists or DB error: ") +
                               sqlite3_errmsg(db_));
    return {};
}

std::expected<void, std::string> RbacStore::delete_group(const std::string& name) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return std::unexpected("database not open");
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_, "DELETE FROM groups WHERE name = ?;", -1, &s, nullptr) != SQLITE_OK)
        return std::unexpected(sqlite3_errmsg(db_));
    sqlite3_bind_text(s, 1, name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(s);
    sqlite3_finalize(s);
    return {};
}

std::vector<std::string> RbacStore::get_group_members(const std::string& group_name) const {
    std::shared_lock lock(mtx_);
    std::vector<std::string> result;
    if (!db_)
        return result;
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(
            db_, "SELECT username FROM group_members WHERE group_name = ? ORDER BY username;", -1,
            &s, nullptr) != SQLITE_OK)
        return result;
    sqlite3_bind_text(s, 1, group_name.c_str(), -1, SQLITE_TRANSIENT);
    while (sqlite3_step(s) == SQLITE_ROW)
        result.emplace_back(reinterpret_cast<const char*>(sqlite3_column_text(s, 0)));
    sqlite3_finalize(s);
    return result;
}

std::expected<void, std::string> RbacStore::add_group_member(const std::string& group_name,
                                                             const std::string& username) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return std::unexpected("database not open");
    // G5 (governance hardening, UP-5): this method has zero route callers
    // today, but the group-resolution arm of role lookup would hand an
    // `engine:`-named member any role the group holds — the same shadow-
    // attribution hazard `validate_assignment`'s F2 guard closes for direct
    // role assignment (see that comment). Defense-in-depth per UP-11:
    // reject an `engine:`-prefixed username at this write surface too.
    if (username.starts_with(kEnginePrefix))
        return std::unexpected(
            "principal_id in the reserved 'engine:' namespace cannot be added as a group member");
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(
            db_, "INSERT OR IGNORE INTO group_members (group_name, username) VALUES (?, ?);", -1,
            &s, nullptr) != SQLITE_OK)
        return std::unexpected(sqlite3_errmsg(db_));
    sqlite3_bind_text(s, 1, group_name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 2, username.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(s);
    sqlite3_finalize(s);
    return {};
}

std::expected<void, std::string> RbacStore::remove_group_member(const std::string& group_name,
                                                                const std::string& username) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return std::unexpected("database not open");
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_, "DELETE FROM group_members WHERE group_name = ? AND username = ?;",
                           -1, &s, nullptr) != SQLITE_OK)
        return std::unexpected(sqlite3_errmsg(db_));
    sqlite3_bind_text(s, 1, group_name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 2, username.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(s);
    sqlite3_finalize(s);
    return {};
}

std::expected<ReconcileResult, std::string> RbacStore::reconcile_idp_memberships(
    const std::string& username, const std::string& source,
    const std::vector<std::pair<std::string, std::string>>& asserted) {
    // Cap check runs BEFORE the lock/transaction — an over-cap call mutates
    // nothing, per the documented contract.
    if (asserted.size() > kMaxIdpGroupsPerLogin)
        return std::unexpected("group_count_exceeded");

    // UP-6: the stale-membership DELETE below is scoped to
    // `groups.source = ?` and is safe ONLY because every real caller passes
    // an IdP source ("entra"/"saml"/"ad"). A miswired call with "local" (or
    // an empty source) would mass-DELETE every local group membership
    // fleet-wide on the very next reconcile. Reject outright, before the
    // lock/transaction — no mutation on this rejection either.
    //
    // F3 (Hermes pass-2 H2): reject any source that isn't a recognized IdP
    // source outright, not just "local"/empty. Without this, a caller
    // passing source="engine" (or any other unrecognized string) could mint
    // `engine:`-prefixed "IdP" groups that bypass `has_reserved_idp_prefix`
    // (which only rejects `source == "local"` writes into the reserved
    // namespace) and the collision scan below — this path never checks the
    // reserved-prefix at all. Fail closed on anything outside the
    // allowlist.
    bool recognized_source = false;
    for (auto s : kRecognizedIdpSources) {
        if (source == s) {
            recognized_source = true;
            break;
        }
    }
    if (!recognized_source)
        return std::unexpected("invalid_source");

    // UP-9: drop asserted entries whose external_id can't produce a sane
    // group name — blank/whitespace-only, or implausibly long (a
    // malformed/hostile assertion). Filtering happens BEFORE `namespaced` is
    // computed so the upsert loop and the stale-membership NOT-IN list agree
    // on exactly what "asserted" means (same invariant the original code
    // preserved for duplicate external_ids).
    std::vector<std::pair<std::string, std::string>> valid;
    valid.reserve(asserted.size());
    for (const auto& a : asserted) {
        if (is_blank(a.first)) {
            spdlog::warn(
                "reconcile_idp_memberships: skipping asserted entry with blank external_id "
                "(user='{}', source='{}')",
                username, source);
            continue;
        }
        if (a.first.size() > kMaxExternalIdLength) {
            spdlog::warn(
                "reconcile_idp_memberships: skipping asserted external_id exceeding {} bytes "
                "(user='{}', source='{}')",
                kMaxExternalIdLength, username, source);
            continue;
        }
        valid.push_back(a);
    }

    std::unique_lock lock(mtx_);
    if (!db_)
        return std::unexpected("database not open");

    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();

    // Namespaced names computed once: reused for the upsert loop below AND
    // for the stale-membership DELETE's NOT IN list, so the two agree on
    // exactly what "asserted" means even if a caller passes duplicate
    // external_ids.
    std::vector<std::string> namespaced;
    namespaced.reserve(valid.size());
    for (const auto& a : valid)
        namespaced.push_back(namespaced_group_name(source, a.first));

    if (sqlite3_exec(db_, "BEGIN IMMEDIATE;", nullptr, nullptr, nullptr) != SQLITE_OK)
        return std::unexpected(std::string("begin failed: ") + sqlite3_errmsg(db_));
    // Rolls back on every early return (incl. an exception) until commit()
    // succeeds; SqliteStmt owners below finalize first (reverse destruction
    // order) so the rollback never runs against a connection with live
    // statements.
    SqliteTxn txn(db_);

    ReconcileResult result;

    {
        SqliteStmt ins_group;
        if (sqlite3_prepare_v2(db_,
                               "INSERT OR IGNORE INTO groups (name, description, source, "
                               "external_id, created_at) VALUES (?, ?, ?, ?, ?);",
                               -1, ins_group.addr(), nullptr) != SQLITE_OK)
            return std::unexpected(std::string("prepare failed: ") + sqlite3_errmsg(db_));
        // sec-L1: verify the (possibly pre-existing) group row's source
        // before joining a membership to it. `INSERT OR IGNORE` above never
        // overwrites a pre-existing row, so a name collision with a
        // DIFFERENT-source row (e.g. a local group literally named
        // `entra:<gid>`, created before the `create_group` reserved-prefix
        // guard existed) leaves that row exactly as it was — this check is
        // what stops the membership INSERT that follows from joining it.
        SqliteStmt check_source;
        if (sqlite3_prepare_v2(db_, "SELECT source FROM groups WHERE name = ?;", -1,
                               check_source.addr(), nullptr) != SQLITE_OK)
            return std::unexpected(std::string("prepare failed: ") + sqlite3_errmsg(db_));
        // RETURNING (not sqlite3_changes()) carries the "was a NEW row
        // inserted" signal in the step result itself — #1033.
        SqliteStmt ins_member;
        if (sqlite3_prepare_v2(db_,
                               "INSERT OR IGNORE INTO group_members (group_name, username) "
                               "VALUES (?, ?) RETURNING 1;",
                               -1, ins_member.addr(), nullptr) != SQLITE_OK)
            return std::unexpected(std::string("prepare failed: ") + sqlite3_errmsg(db_));

        for (size_t i = 0; i < valid.size(); ++i) {
            const auto& external_id = valid[i].first;
            const auto& display = valid[i].second;
            const auto& name = namespaced[i];
            const auto description = std::string("IdP-provisioned group (") + source + "): " +
                                     (display.empty() ? external_id : display);

            sqlite3_reset(ins_group.get());
            sqlite3_bind_text(ins_group.get(), 1, name.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(ins_group.get(), 2, description.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(ins_group.get(), 3, source.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(ins_group.get(), 4, external_id.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(ins_group.get(), 5, now);
            if (sqlite3_step(ins_group.get()) != SQLITE_DONE)
                return std::unexpected(std::string("group upsert failed: ") + sqlite3_errmsg(db_));

            sqlite3_reset(check_source.get());
            sqlite3_bind_text(check_source.get(), 1, name.c_str(), -1, SQLITE_TRANSIENT);
            bool source_mismatch = false;
            if (sqlite3_step(check_source.get()) == SQLITE_ROW) {
                const auto* existing =
                    reinterpret_cast<const char*>(sqlite3_column_text(check_source.get(), 0));
                if (existing && source != existing)
                    source_mismatch = true;
            }
            if (source_mismatch) {
                spdlog::warn(
                    "reconcile_idp_memberships: NOT joining '{}' to pre-existing group '{}' — "
                    "row source differs from reconcile source '{}' (confused-deputy guard)",
                    username, name, source);
                continue;
            }

            sqlite3_reset(ins_member.get());
            sqlite3_bind_text(ins_member.get(), 1, name.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(ins_member.get(), 2, username.c_str(), -1, SQLITE_TRANSIENT);
            int rc = sqlite3_step(ins_member.get());
            if (rc == SQLITE_ROW) {
                ++result.added;
            } else if (rc != SQLITE_DONE) {
                return std::unexpected(std::string("membership upsert failed: ") +
                                       sqlite3_errmsg(db_));
            }
        }
    }

    // Remove stale IdP memberships: any group_members row for this user whose
    // group is owned by THIS source and was NOT re-asserted this login. The
    // `group_name IN (SELECT name FROM groups WHERE source = ?)` scoping is
    // what makes this DELETE structurally incapable of touching a
    // source='local' membership — see the "local membership untouched"
    // unit test. An empty `asserted` (IdP now reports zero groups for this
    // user) removes ALL of the user's source-scoped memberships, which is the
    // deprovisioning-bypass fix: the next SSO login after a full IdP-group
    // removal drops every role that flowed through that source. #1832.
    // RETURNING (not sqlite3_changes()) carries the removed-row count in the
    // step results — #1033.
    {
        std::string sql = "DELETE FROM group_members "
                          "WHERE username = ? "
                          "AND group_name IN (SELECT name FROM groups WHERE source = ?)";
        if (!namespaced.empty()) {
            sql += " AND group_name NOT IN (";
            for (size_t i = 0; i < namespaced.size(); ++i)
                sql += (i == 0 ? "?" : ",?");
            sql += ")";
        }
        sql += " RETURNING group_name;";

        SqliteStmt del;
        if (sqlite3_prepare_v2(db_, sql.c_str(), -1, del.addr(), nullptr) != SQLITE_OK)
            return std::unexpected(std::string("prepare failed: ") + sqlite3_errmsg(db_));
        sqlite3_bind_text(del.get(), 1, username.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(del.get(), 2, source.c_str(), -1, SQLITE_TRANSIENT);
        int idx = 3;
        for (const auto& name : namespaced)
            sqlite3_bind_text(del.get(), idx++, name.c_str(), -1, SQLITE_TRANSIENT);
        int rc;
        while ((rc = sqlite3_step(del.get())) == SQLITE_ROW)
            ++result.removed;
        if (rc != SQLITE_DONE)
            return std::unexpected(std::string("stale-membership delete failed: ") +
                                   sqlite3_errmsg(db_));
    }

    if (txn.commit() != SQLITE_OK)
        return std::unexpected(std::string("commit failed: ") + sqlite3_errmsg(db_));

    invalidate_perm_cache();
    return result;
}

// ── Authorization check ──────────────────────────────────────────────────────

std::vector<std::string> RbacStore::collect_roles_locked(const std::string& username) const {
    std::vector<std::string> roles;
    if (!db_)
        return roles;

    sqlite3_stmt* s = nullptr;
    // Three-way UNION: direct user grant, group-membership grant, and (PR
    // 4.2, design §4.1) direct engine-principal grant. The first two
    // branches are BYTE-IDENTICAL to their pre-PR-4.2 form — a hard
    // invariant — because the third branch is purely additive and safe:
    // an `engine:` principal_id can never match a human username (§3.3
    // reserves the namespace at every creation surface) and a human/group
    // name never carries the `engine:` prefix, so this UNION arm can only
    // ever contribute rows for an actual `principal_type='engine'` caller.
    if (sqlite3_prepare_v2(db_,
                           "SELECT role_name FROM principal_roles "
                           "WHERE principal_type = 'user' AND principal_id = ? "
                           "UNION "
                           "SELECT pr.role_name FROM principal_roles pr "
                           "JOIN group_members gm ON pr.principal_type = 'group' AND "
                           "pr.principal_id = gm.group_name "
                           "WHERE gm.username = ? "
                           "UNION "
                           "SELECT role_name FROM principal_roles "
                           "WHERE principal_type = 'engine' AND principal_id = ?;",
                           -1, &s, nullptr) != SQLITE_OK)
        return roles;
    sqlite3_bind_text(s, 1, username.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 2, username.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 3, username.c_str(), -1, SQLITE_TRANSIENT);
    while (sqlite3_step(s) == SQLITE_ROW)
        roles.emplace_back(reinterpret_cast<const char*>(sqlite3_column_text(s, 0)));
    sqlite3_finalize(s);
    return roles;
}

std::string RbacStore::perm_cache_key(const std::string& user, const std::string& type,
                                      const std::string& op) const {
    return user + ":" + type + ":" + op;
}

void RbacStore::invalidate_perm_cache() {
    std::lock_guard lock(cache_mtx_);
    perm_cache_.clear();
    ++write_generation_;
}

bool RbacStore::check_permission(const std::string& username, const std::string& securable_type,
                                 const std::string& operation) const {
    // Fast path: check permission cache (G3-PERF-004)
    auto key = perm_cache_key(username, securable_type, operation);
    {
        std::lock_guard cache_lock(cache_mtx_);
        if (cache_generation_ == write_generation_) {
            auto it = perm_cache_.find(key);
            if (it != perm_cache_.end())
                return it->second;
        } else {
            // Mutations happened since last cache read — clear stale entries
            perm_cache_.clear();
            cache_generation_ = write_generation_;
        }
    }

    std::shared_lock lock(mtx_);
    if (!db_)
        return false;

    auto roles = collect_roles_locked(username);
    if (roles.empty())
        return false;

    // Build a parameterized IN clause for the collected roles
    std::string placeholders;
    for (size_t i = 0; i < roles.size(); ++i) {
        if (i > 0)
            placeholders += ',';
        placeholders += '?';
    }

    std::string sql = "SELECT effect FROM role_permissions "
                      "WHERE securable_type = ? AND operation = ? AND role_name IN (" +
                      placeholders + ");";

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &s, nullptr) != SQLITE_OK)
        return false;

    sqlite3_bind_text(s, 1, securable_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 2, operation.c_str(), -1, SQLITE_TRANSIENT);
    for (size_t i = 0; i < roles.size(); ++i)
        sqlite3_bind_text(s, static_cast<int>(3 + i), roles[i].c_str(), -1, SQLITE_TRANSIENT);

    bool has_allow = false;
    while (sqlite3_step(s) == SQLITE_ROW) {
        auto* effect = reinterpret_cast<const char*>(sqlite3_column_text(s, 0));
        if (effect && std::string(effect) == "deny") {
            sqlite3_finalize(s);
            return false; // deny overrides everything
        }
        if (effect && std::string(effect) == "allow")
            has_allow = true;
    }
    sqlite3_finalize(s);

    // Store result in cache
    {
        std::lock_guard cache_lock(cache_mtx_);
        if (cache_generation_ == write_generation_)
            perm_cache_[key] = has_allow;
    }
    return has_allow;
}

std::vector<Permission> RbacStore::get_effective_permissions(const std::string& username) const {
    std::shared_lock lock(mtx_);
    std::vector<Permission> result;
    if (!db_)
        return result;

    auto roles = collect_roles_locked(username);
    if (roles.empty())
        return result;

    std::string placeholders;
    for (size_t i = 0; i < roles.size(); ++i) {
        if (i > 0)
            placeholders += ',';
        placeholders += '?';
    }

    std::string sql = "SELECT role_name, securable_type, operation, effect FROM role_permissions "
                      "WHERE role_name IN (" +
                      placeholders + ") ORDER BY securable_type, operation;";

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &s, nullptr) != SQLITE_OK)
        return result;

    for (size_t i = 0; i < roles.size(); ++i)
        sqlite3_bind_text(s, static_cast<int>(1 + i), roles[i].c_str(), -1, SQLITE_TRANSIENT);

    while (sqlite3_step(s) == SQLITE_ROW) {
        Permission p;
        p.role_name = reinterpret_cast<const char*>(sqlite3_column_text(s, 0));
        p.securable_type = reinterpret_cast<const char*>(sqlite3_column_text(s, 1));
        p.operation = reinterpret_cast<const char*>(sqlite3_column_text(s, 2));
        p.effect = reinterpret_cast<const char*>(sqlite3_column_text(s, 3));
        result.push_back(std::move(p));
    }
    sqlite3_finalize(s);
    return result;
}

// ── Reference data ───────────────────────────────────────────────────────────

std::vector<std::string> RbacStore::list_securable_types() const {
    std::shared_lock lock(mtx_);
    std::vector<std::string> result;
    if (!db_)
        return result;
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_, "SELECT name FROM securable_types ORDER BY name;", -1, &s,
                           nullptr) != SQLITE_OK)
        return result;
    while (sqlite3_step(s) == SQLITE_ROW)
        result.emplace_back(reinterpret_cast<const char*>(sqlite3_column_text(s, 0)));
    sqlite3_finalize(s);
    return result;
}

std::vector<std::string> RbacStore::list_operations() const {
    std::shared_lock lock(mtx_);
    std::vector<std::string> result;
    if (!db_)
        return result;
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_, "SELECT id FROM operations ORDER BY id;", -1, &s, nullptr) !=
        SQLITE_OK)
        return result;
    while (sqlite3_step(s) == SQLITE_ROW)
        result.emplace_back(reinterpret_cast<const char*>(sqlite3_column_text(s, 0)));
    sqlite3_finalize(s);
    return result;
}

// ── Scoped permission check ──────────────────────────────────────────────────

bool RbacStore::check_scoped_permission(const std::string& username,
                                        const std::string& securable_type,
                                        const std::string& operation,
                                        const std::string& agent_id,
                                        const ManagementGroupStore* mgmt_store) const {
    // Note: does NOT hold its own lock. Delegates to check_permission /
    // resolve_perm_groups / the mgmt-store, which each acquire their own lock.

    // 1. Global permission first (honors a global deny → false). A global ALLOW
    //    short-circuits — matches #1715(b): a global allow overrides a group deny.
    if (check_permission(username, securable_type, operation))
        return true;

    // 2. No mgmt store or agent → cannot do the scoped check.
    if (!mgmt_store || agent_id.empty())
        return false;

    // 3. Resolve the user's allow/deny groups ONCE via the shared INV-7 resolver
    //    (the SAME classification the ADR-0017 list-read primitives use), then
    //    intersect with the agent's reachable groups (its groups + ancestors —
    //    ancestor-ward admit). A matching DENY anywhere in that set overrides
    //    (deny wins within the agent's scoped set); else a matching ALLOW admits.
    //    Fail-closed: any store error → false, never a silent admit.
    auto pg = resolve_perm_groups(username, securable_type, operation, mgmt_store);
    if (!pg)
        return false;

    auto groups = mgmt_store->get_agent_groups(agent_id);
    std::unordered_set<std::string> reachable;
    for (const auto& gid : groups) {
        reachable.insert(gid);
        for (const auto& aid : mgmt_store->get_ancestor_ids(gid))
            reachable.insert(aid);
    }
    if (reachable.empty())
        return false;

    for (const auto& g : pg->deny_groups)
        if (reachable.contains(g))
            return false; // deny overrides within the agent's scoped set
    for (const auto& g : pg->allow_groups)
        if (reachable.contains(g))
            return true;
    return false;
}

// ── ADR-0017 admit-then-filter list gate ─────────────────────────────────────

std::expected<std::vector<std::string>, std::string>
RbacStore::user_rbac_group_names(const std::string& username) const {
    std::shared_lock lock(mtx_);
    std::vector<std::string> groups;
    if (!db_)
        return std::unexpected("rbac store not open");
    SqliteStmt s;
    if (sqlite3_prepare_v2(db_, "SELECT group_name FROM group_members WHERE username = ?;", -1,
                           s.addr(), nullptr) != SQLITE_OK)
        return std::unexpected(std::string("prepare failed: ") + sqlite3_errmsg(db_));
    sqlite3_bind_text(s.get(), 1, username.c_str(), -1, SQLITE_TRANSIENT);
    int rc = SQLITE_OK;
    while ((rc = sqlite3_step(s.get())) == SQLITE_ROW) {
        if (auto* g = reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 0)))
            groups.emplace_back(g);
    }
    s.reset();
    if (rc != SQLITE_DONE)
        return std::unexpected(std::string("query failed: ") + sqlite3_errmsg(db_));
    return groups;
}

std::expected<std::unordered_map<std::string, int>, std::string>
RbacStore::role_effects_for(const std::string& securable_type, const std::string& operation) const {
    std::shared_lock lock(mtx_);
    std::unordered_map<std::string, int> role_effect; // -1 deny (wins), 1 allow, 0 none
    if (!db_)
        return std::unexpected("rbac store not open");
    SqliteStmt s;
    if (sqlite3_prepare_v2(db_,
                           "SELECT role_name, effect FROM role_permissions "
                           "WHERE securable_type = ? AND operation = ?;",
                           -1, s.addr(), nullptr) != SQLITE_OK)
        return std::unexpected(std::string("prepare failed: ") + sqlite3_errmsg(db_));
    sqlite3_bind_text(s.get(), 1, securable_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s.get(), 2, operation.c_str(), -1, SQLITE_TRANSIENT);
    int rc = SQLITE_OK;
    while ((rc = sqlite3_step(s.get())) == SQLITE_ROW) {
        const auto* role = reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 0));
        const auto* effect = reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 1));
        if (!role || !effect)
            continue;
        int& e = role_effect[role];
        if (std::string_view(effect) == "deny")
            e = -1; // deny wins within a role, regardless of order
        else if (std::string_view(effect) == "allow" && e == 0)
            e = 1;
    }
    s.reset();
    if (rc != SQLITE_DONE)
        return std::unexpected(std::string("query failed: ") + sqlite3_errmsg(db_));
    return role_effect;
}

std::expected<RbacStore::PermGroups, std::string>
RbacStore::resolve_perm_groups(const std::string& username, const std::string& securable_type,
                               const std::string& operation,
                               const ManagementGroupStore* mgmt_store) const {
    if (!mgmt_store)
        return std::unexpected("management group store unavailable");

    auto rbac_groups = user_rbac_group_names(username);
    if (!rbac_groups)
        return std::unexpected(rbac_groups.error());

    auto assignments = mgmt_store->get_assignments_for_principal(username, *rbac_groups);
    if (!assignments)
        return std::unexpected(assignments.error());

    // Per-role deny-wins verdict for THIS (sec,op) via ONE targeted query
    // (ADR-0017 perf F5) — resolve_perm_groups runs per-agent in fleet-list
    // loops, so materializing the whole role_permissions table per call was a
    // hot-path regression.
    auto role_effect_r = role_effects_for(securable_type, operation);
    if (!role_effect_r)
        return std::unexpected(role_effect_r.error());
    const auto& role_effect = *role_effect_r;

    PermGroups pg;
    std::unordered_set<std::string> allow_seen, deny_seen;
    for (const auto& a : *assignments) {
        auto it = role_effect.find(a.role_name);
        if (it == role_effect.end() || it->second == 0)
            continue;
        if (it->second == -1) {
            if (deny_seen.insert(a.group_id).second)
                pg.deny_groups.push_back(a.group_id);
        } else if (allow_seen.insert(a.group_id).second) {
            pg.allow_groups.push_back(a.group_id);
        }
    }
    return pg;
}

std::expected<std::vector<std::string>, std::string>
RbacStore::expand_visible_set(const PermGroups& pg, const ManagementGroupStore* mgmt_store) const {
    if (!mgmt_store)
        return std::unexpected("management group store unavailable");
    if (pg.allow_groups.empty())
        return std::vector<std::string>{}; // holds nothing via groups → empty (INV-2)

    auto allow_agents = mgmt_store->get_member_agents_in_subtrees(pg.allow_groups);
    if (!allow_agents)
        return std::unexpected(allow_agents.error());

    if (!pg.deny_groups.empty()) {
        auto deny_agents = mgmt_store->get_member_agents_in_subtrees(pg.deny_groups);
        if (!deny_agents)
            return std::unexpected(deny_agents.error());
        std::unordered_set<std::string> denied(deny_agents->begin(), deny_agents->end());
        std::vector<std::string> visible;
        visible.reserve(allow_agents->size());
        for (auto& a : *allow_agents)
            if (!denied.contains(a))
                visible.push_back(std::move(a));
        allow_agents = std::move(visible);
    }
    std::sort(allow_agents->begin(), allow_agents->end());
    allow_agents->erase(std::unique(allow_agents->begin(), allow_agents->end()),
                        allow_agents->end());
    return allow_agents;
}

bool RbacStore::holds_permission_via_any_group(const std::string& username,
                                               const std::string& securable_type,
                                               const std::string& operation,
                                               const ManagementGroupStore* mgmt_store) const {
    auto pg = resolve_perm_groups(username, securable_type, operation, mgmt_store);
    if (!pg)
        return false; // fail-closed on any store error
    return !pg->allow_groups.empty();
}

std::expected<std::vector<std::string>, std::string>
RbacStore::visible_agents_for_permission(const std::string& username,
                                         const std::string& securable_type,
                                         const std::string& operation,
                                         const ManagementGroupStore* mgmt_store) const {
    auto pg = resolve_perm_groups(username, securable_type, operation, mgmt_store);
    if (!pg)
        return std::unexpected(pg.error());
    return expand_visible_set(*pg, mgmt_store);
}

ListReadAuthorization RbacStore::authorize_list_read(const std::string& username,
                                                     const std::string& securable_type,
                                                     const std::string& operation,
                                                     const ManagementGroupStore* mgmt_store) const {
    ListReadAuthorization out; // DenyAll by default — the INV-1 fail-closed default.

    // Legacy-open: RBAC loaded AND explicitly disabled → full-fleet read (every
    // authenticated user is a legacy superuser under RBAC-off). A null / load-
    // failed store returns true from rbac_enforcement_in_effect (enforce) and
    // falls through to the RBAC path, which denies — never AdmitAll on a corrupt
    // store (INV-1).
    if (!rbac_enforcement_in_effect(this)) {
        out.decision = ListReadDecision::AdmitAll;
        return out;
    }

    // #1715(b): a global ALLOW overrides any group deny → unfiltered read.
    if (check_permission(username, securable_type, operation)) {
        out.decision = ListReadDecision::AdmitAll;
        return out;
    }

    // #1715(a): additive — a group allow admits even against a global deny/absent.
    auto pg = resolve_perm_groups(username, securable_type, operation, mgmt_store);
    if (!pg || pg->allow_groups.empty()) {
        out.decision = ListReadDecision::DenyAll; // INV-1/INV-5: error or no grant → deny
        return out;
    }
    auto visible = expand_visible_set(*pg, mgmt_store);
    if (!visible) {
        out.decision = ListReadDecision::DenyAll; // fail-closed on a subtree-read error
        return out;
    }
    out.decision = ListReadDecision::AdmitScoped;
    out.visible_agents = std::move(*visible);
    return out;
}

bool RbacStore::check_role_has_permission(const std::string& role_name,
                                          const std::string& securable_type,
                                          const std::string& operation) const {
    // Delegates to get_role_permissions which acquires its own shared_lock
    auto perms = get_role_permissions(role_name);
    for (const auto& p : perms) {
        if (p.securable_type == securable_type && p.operation == operation) {
            if (p.effect == "deny")
                return false;
            if (p.effect == "allow")
                return true;
        }
    }
    return false;
}

} // namespace yuzu::server
