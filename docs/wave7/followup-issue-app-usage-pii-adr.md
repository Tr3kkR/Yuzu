# Follow-up issue text (NOT posted — for the integrator/Alex to file)

**Title:** ADR: PII classification, per-subject DSAR, and retention policy for usage-class TAR data and the `app_usage` server projection

**Labels:** `compliance`, `enterprise`, `phase-7-scale` (from `gh label list --repo Tr3kkR/Yuzu`; no dedicated `privacy` or `gdpr` label exists today — `compliance` is the closest fit)

**Body:**

Wave 7 PR7.2 ships the TAR `usage` source (a derived per-executable run-count/
duration fold, default-on alongside `power`/`removable`) and its centralized
server projection, `app_usage_store` (`GET /api/v1/forensics/agents/{id}/app-usage`,
MCP `get_agent_app_usage`). Both are documented as **usage-class / behavioral-
adjacent telemetry**, works-council co-determination-relevant on personally-
assigned devices, in `docs/user-manual/app-usage.md` and
`docs/enterprise-readiness-soc2-first-customer.md`.

This PR does **not** resolve two open items, accepted as risk by Alex on
2026-09-06:

1. **No PII-classification ADR exists yet** for usage-class TAR data as a category
   (this source, plus the existing `procperf`/`netqual`/`netconn`/`power`/
   `removable` sources it joins). Today each source's user-manual page and the
   SOC 2 data inventory state its posture individually; there is no single ADR
   that classifies the category, states the legal basis relied on, or sets a
   fleet-wide retention policy for it.
2. **No per-subject DSAR (GDPR Art. 17) erasure path exists** for any usage-class
   store, `app_usage_store` included. This release wires `app_usage_store` into
   the agent-decommission cascade as its sixth store: a whole-device
   `DELETE /api/v1/sle/agents/{id}`, gated on the promoted
   `Decommission:Delete` securable (Administrator + a targeted ITServiceOwner
   grant), erases both `usage_state` and `agent_last_used` for that agent,
   alongside the fleet's other per-agent stores. What remains open is strictly
   **row-level / per-subject erasure** — asking "erase everything this person's
   usage touched" without decommissioning the whole device. That is the same
   pre-existing gap already tracked for the fleet's other usage-class stores
   under **#1666**; this source does not widen it, and does not introduce a new
   gap of its own.

**Ask:** an ADR that (a) classifies usage-class TAR data as a category (legal
basis, data class, cross-jurisdiction posture for works-council/co-determination
regimes), (b) sets a fleet-wide retention policy applicable across sources in the
category rather than per-source ad hoc defaults, and (c) scopes a row-level/
per-subject DSAR erasure path — for `app_usage_store` specifically and, ideally,
as a reusable pattern for the fleet's other usage-class stores tracked under
#1666.

**Not in scope for this issue:** the whole-device decommission cascade itself —
it already covers `app_usage_store` as of this release; only row-level /
per-subject erasure remains open.
