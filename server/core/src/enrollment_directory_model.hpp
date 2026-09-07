#pragma once

/// @file enrollment_directory_model.hpp
///
/// #4031 (API-parity Batch A): shared pure builder functions for the
/// directory-sync (AD/Entra), enrollment (auto-approve rules + pending
/// agents), and OIDC SSO config read surfaces, per docs/api-twin-recipe.md
/// §1. No `httplib.h`, no MCP-specific includes — pure functions of a
/// store/struct value, returning `nlohmann::json`.
///
/// Genuinely multi-consumer today: `directory_user_row_json` and
/// `directory_status_json` — REST v1, MCP, AND the legacy `/api/directory/*`
/// route all call the same function (verified: `discovery_routes.cpp`,
/// `mcp_server.cpp`, `enrollment_directory_routes.cpp`). The other three
/// (`auto_approve_rule_row_json`, `pending_agent_row_json`, `oidc_config_json`)
/// have NO dashboard-fragment consumer today — `settings_routes.cpp`'s
/// `render_auto_approve_fragment`/`render_pending_fragment`/
/// `render_directory_fragment` independently re-derive equivalent facts by
/// hand rather than calling these functions. That independent duplication is
/// exactly the anti-pattern §1 warns against, and is what let
/// `pending_agent_row_json`'s REST v1 caller silently diverge from the
/// fragment's population (the fragment filters out `approved` agents, the
/// route originally didn't — fixed as a Gate 4 finding in #4031's hardening
/// round; see the route's own comment in `enrollment_directory_routes.cpp`).
/// Routing the three fragment renderers through these builders would make
/// the lockstep real rather than asserted — tracked as a follow-up, not done
/// here.
///
/// NAMING TRAP (see the #4031 issue text and discovery_routes.cpp's own
/// header comment): `GET /fragments/settings/directory` renders OIDC SSO
/// config, NOT the AD/Entra directory-sync feature, despite its path. The
/// builder for that route is named `oidc_config_json`, never anything with
/// "directory" in it, and its RBAC securable is the freshly-minted
/// `OidcConfig` — never the unrelated `Directory` securable seeded for the
/// two functions below it in this file.

#include <yuzu/server/auto_approve.hpp> // auth::AutoApproveRule
#include <yuzu/server/auth.hpp>         // auth::PendingAgent

#include <nlohmann/json.hpp>

#include <cstddef>
#include <vector>

namespace yuzu::server {

struct DirectoryUser;
struct DirectoryGroup;
struct SyncStatus;
struct Config; // server.hpp — only ::oidc_* fields are read

// ── Directory sync (AD/Entra) — Directory:Read ─────────────────────────────

/// One row of `GET /api/(v1/)directory/users`. Mirrors the legacy
/// `/api/directory/users` handler's per-user shape exactly (id, display_name,
/// email, upn, enabled, groups, synced_at) — genuinely PII (email/UPN).
nlohmann::json directory_user_row_json(const DirectoryUser& u);

/// `GET /api/(v1/)directory/status` — provider/status/counts/last_error plus
/// the full synced-groups array (id, display_name, description, mapped_role,
/// synced_at). Mirrors the legacy handler's shape exactly.
nlohmann::json directory_status_json(const SyncStatus& status,
                                     const std::vector<DirectoryGroup>& groups);

// ── Enrollment (auto-approve rules + pending agents) — Enrollment:Read ────

/// One row of the auto-approve rule list. `index` is the rule's position in
/// `AutoApproveEngine::list_rules()` — the only stable handle the engine
/// exposes for the existing toggle/delete mutation routes (no rule id), so
/// the read twin surfaces the same index a caller would need to act on it.
nlohmann::json auto_approve_rule_row_json(const auth::AutoApproveRule& rule, std::size_t index);

/// One row of the pending-agent queue. `requested_at` is serialised as a
/// Unix-epoch-seconds integer, matching `auth.cpp`'s existing
/// `pa.requested_at.time_since_epoch()` conversion for the on-disk format.
nlohmann::json pending_agent_row_json(const auth::PendingAgent& agent);

// ── OIDC SSO config — OidcConfig:Read (NOT Directory:Read — see file header) ─

/// `GET /api/v1/settings/oidc` and the `/fragments/settings/directory`
/// fragment's underlying data. Masks the client secret the same way the
/// existing fragment does: `client_secret_configured` (bool) reports whether
/// one is set, never the value itself, including partially or in placeholder
/// form — `render_directory_fragment()` (settings_routes.cpp) never echoes it
/// either, only a "********" UI placeholder computed client-side from this
/// same boolean fact.
nlohmann::json oidc_config_json(const Config& cfg);

} // namespace yuzu::server
