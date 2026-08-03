#pragma once

#include <sqlite3.h>

#include <cstdint>
#include <expected>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server {

/// WHICH surface minted a ticket (#2442). `ApprovalManager` is one shared store
/// with three mint paths, and a ticket was previously matched on
/// (definition_id, scope_expression) alone — so an instruction definition named
/// `mcp.<tool>` whose approval scope equalled a tool's canonical argument JSON
/// was consumable through the MCP recall, and vice versa. Recording the minting
/// surface makes the namespaces separable, and gives audit a clean per-surface
/// split.
enum class ApprovalOrigin {
    /// A mint that predates this enum, or one that has not declared itself:
    /// today ONLY the MCP gate, which cannot be updated to declare `kMcp` while
    /// mcp_server.cpp is frozen for a parallel rebase. Kept honest rather than
    /// mislabelled — a ticket recorded `instruction` when MCP minted it would be
    /// false evidence. Tighten to `kMcp` when the MCP mint declares itself.
    kUnspecified,
    /// The interactive REST/dashboard instruction-approval gate
    /// (workflow_routes.cpp).
    kInstruction,
    /// A scheduled-fire submission (schedule_runner.cpp).
    kSchedule,
    /// The MCP approval-ticket gate (mcp_server.cpp). Not yet passed by that
    /// caller — see kUnspecified.
    kMcp,
    /// Column text this build does not recognise — written by a newer binary and
    /// read back after a rollback, say. NEVER written by this build. It exists so
    /// that decoding an unknown value cannot land on kUnspecified, which #2442
    /// exempts from the redemption guard: a DENY predicate whose decode folds
    /// unknown into the allow value fails open however carefully the predicate
    /// itself is written.
    kUnrecognised,
};

/// Column text for `origin`. `kUnspecified` stores the empty string, which is
/// also what migration v5 back-fills into pre-existing rows, so "no declared
/// origin" reads identically whether the row predates the column or the caller
/// stayed silent.
const char* to_string(ApprovalOrigin origin);
ApprovalOrigin approval_origin_from_string(std::string_view text);

/// True iff the ticket's recorded origin names a minting surface that is NOT
/// MCP. This is the whole of the #2442 anti-forgery rule, stated once because it
/// has to mean the same thing everywhere it is asked.
///
/// It is a DENY predicate for the MCP recall, and it is deliberately phrased
/// over the ORIGIN rather than over the definition id. The forgery it stops is a
/// ticket minted on one surface being redeemed on another; the `mcp.` id prefix
/// was only ever a proxy for that, and a proxy with two defects. It could not
/// tell a pre-existing operator definition from a hostile one, so it refused
/// content it could not help — see the removed mint-side check in `submit`. And
/// it would stop covering the real case the moment the MCP mint stopped building
/// its id as `"mcp." + tool_name`, which nothing forces it to keep doing.
///
/// `kUnspecified` is ALLOWED, and that is the loose end. It has to be: the MCP
/// mint itself still records `kUnspecified` (see the enum above), and rows
/// predating migration v5 carry `''`, which decodes to it — the migration adds
/// the column with `DEFAULT ''` and deliberately does NOT back-fill a surface it
/// cannot know. So a ticket minted by ANY surface before v5 ran is still
/// redeemable here.
///
/// Those rows age out on the 7-day approval expiry, but that sweep is LAZY — it
/// runs inside `submit()` and nowhere else, so an approval queue receiving no new
/// mint ages nothing out. It also sits AFTER the pending-cap check in `submit`,
/// so a queue saturated at the cap never reaches it either, and approved-
/// unconsumed rows do not count toward that cap and so cannot drain it. The
/// residual is bounded by 7 days AND a subsequent SUCCESSFUL submission, not by
/// 7 days alone. There is no API that retires an approved-unconsumed ticket —
/// approve/reject both refuse a non-pending row.
///
/// The exemption closes when the MCP mint declares `kMcp` and this allow-set
/// narrows from two values to one — the same unfreeze that the `kUnspecified`
/// comment above waits on. That narrowing must land AFTER a documented drain:
/// at the instant it ships, every `''` row becomes unredeemable, including
/// legitimate already-approved MCP tickets, which is the same stranding this
/// change exists to remove. Until then the guard is complete for every mint made
/// after v5 by a surface that declares itself, which is both non-MCP surfaces.
///
/// EXTENDING THIS: the shape for a second redeeming surface is
/// `may_redeem(ticket_origin, redeeming_surface)` — widen this function, do not
/// add a sibling. ADR-0031/0032/0033 contemplate engines and a separate
/// presentation binary redeeming core-minted grants, and a parallel
/// `declares_non_gateway_surface` would be a fork of a single-chokepoint rule.
/// Written as an ALLOW-LIST switch rather than `!= kMcp && != kUnspecified`, and
/// deliberately with no `default:`. Adding a fifth ApprovalOrigin then fails the
/// build HERE, at the security gate, instead of silently inheriting whichever
/// side of the inequality it happens to land on. The trailing `return true` is
/// unreachable today and denies, which is the correct direction for the one
/// value a future compiler could reach: a bit pattern outside the enumerators.
[[nodiscard]] constexpr bool declares_non_mcp_surface(ApprovalOrigin origin) {
    switch (origin) {
    case ApprovalOrigin::kMcp:
    case ApprovalOrigin::kUnspecified:
        return false;
    case ApprovalOrigin::kInstruction:
    case ApprovalOrigin::kSchedule:
    case ApprovalOrigin::kUnrecognised:
        return true;
    }
    return true;
}

struct Approval {
    std::string id;
    std::string definition_id;
    std::string status;
    std::string submitted_by;
    int64_t submitted_at{0};
    std::string reviewed_by;
    int64_t reviewed_at{0};
    std::string review_comment;
    std::string scope_expression;
    // One-time-consumption stamp for the MCP approval-ticket flow (#289 / Issue
    // 13.5): epoch-seconds when an approved ticket was recalled-and-executed,
    // 0 while unconsumed. Additive column (migration v2) — keeps the eventual
    // Postgres port trivial.
    int64_t consumed_at{0};
    // WHO consumed the ticket (PR #1796 review H3/N2, SOC-2 CC7.2): the
    // principal whose recall executed the gated tool. Empty while unconsumed.
    // Additive column (migration v3). Completes the ticket's evidence chain:
    // submitted_by → reviewed_by → consumed_by.
    std::string consumed_by;
    /// Empty for an interactively-submitted ticket (workflow_routes.cpp) or an
    /// MCP-minted one (mcp_server.cpp); set to the owning schedule's id for a
    /// scheduled-fire submission (M-02, #1806) so
    /// ScheduleRunner::fire_with_approval can match a ticket to the ONE
    /// schedule occurrence that asked for it, instead of to every schedule
    /// sharing the same (submitted_by, definition_id, scope_expression)
    /// tuple. Additive column (migration v4).
    std::string schedule_id;
    /// Which surface minted this ticket (#2442). Additive column (migration
    /// v5); pre-existing rows read back as kUnspecified.
    ApprovalOrigin origin{ApprovalOrigin::kUnspecified};
};

struct ApprovalQuery {
    std::string status;
    std::string submitted_by;
};

/// Why a precondition-guarded consume did not consume (#2443). The caller needs
/// these apart: a precondition denial must be reported to the operator as
/// "state moved, mint a fresh ticket" with the ticket still recallable, whereas
/// kNotConsumable means the one-time capability is spent. Distinguishing them by
/// parsing the message string would be a fragile seam, so the kind is typed.
///
/// OBLIGATION ON EVERY CALLER — half discharged, and the remaining half is
/// named here so it is not rediscovered by a reviewer a third time.
///
/// The MCP recall answers ONE response body for every failure kind, and that is
/// deliberate: it is what stops the recall being an oracle for which approval
/// ids exist. The AUDIT DETAIL is the opposite case, and it is now branched on
/// the kind (`mcp_server.cpp`, the `switch` on `ConsumeFailure`) — before #2442
/// every failure was recorded as "already used", which for a foreign-origin
/// refusal asserted a ticket state the approvals row contradicts.
///
/// STILL OWED: the client-facing REMEDIATION is unconditional — "submit a new
/// request without approval_id to obtain a fresh approval ticket". That is
/// correct for kNotConsumable and kForeignOrigin, and WRONG for kPrecondition
/// and kStoreError: both leave the ticket recallable, and telling the operator
/// to discard a live human-approved capability is the burn class #2443 exists to
/// close. It cannot be fixed by varying the text per kind without reopening the
/// oracle, so it needs a deliberate design decision — probably a retryable
/// signal that does not name why. Whoever wires the first real precondition owns
/// this.
///
/// A kPrecondition or kForeignOrigin denial still emits no audit ROW of its own,
/// only the caller's `denied` row plus a server log line.
enum class ConsumeFailure {
    kPrecondition,  ///< precondition denied — ticket UNTOUCHED, still recallable
    kNotConsumable, ///< absent / not approved / already consumed (the CAS lost)
    kStoreError,    ///< store unavailable, missing argument, or a SQLite failure
    /// The ticket was minted by a declared non-MCP surface (#2442). Ticket
    /// UNTOUCHED — a refused forgery must not burn a real operator's ticket.
    /// This is a security event, not an operational one: it is logged at warn
    /// with the origin named, while the CALLER is expected to keep reporting it
    /// indistinguishably from kNotConsumable, so the recall is not an oracle for
    /// which ids exist. Distinct from kNotConsumable so the log and any future
    /// audit row can tell a forgery attempt from a replay.
    kForeignOrigin,
};

struct ConsumeError {
    ConsumeFailure kind{ConsumeFailure::kStoreError};
    std::string message;
};

/// A cheap, read-only recheck of the state a ticket's effect depends on,
/// evaluated between the ticket match and the consuming CAS (#2443). Returning
/// an error denies the recall WITHOUT consuming; the string is operator-facing
/// (it reaches the MCP error envelope's remediation), so say what drifted.
///
/// Two constraints on what you may write there. The message must not echo any
/// field of the `Approval` it is handed: `definition_id` and `scope_expression`
/// are caller-supplied, and the MCP envelope and audit detail are documented as
/// carrying no caller-derived text. And the callback must not decide AUTHORITY —
/// that stays in the core approval gate, which can audit it. This seam is for
/// state the effect depends on (a rotation already resolved, a device gone),
/// not for re-deciding who may act.
using ConsumePrecondition = std::function<std::expected<void, std::string>(const Approval&)>;

class ApprovalManager {
public:
    explicit ApprovalManager(sqlite3* db);
    ~ApprovalManager() = default;

    ApprovalManager(const ApprovalManager&) = delete;
    ApprovalManager& operator=(const ApprovalManager&) = delete;

    void create_tables();

    /// `schedule_id` (M-02, #1806): empty for the interactive submit path;
    /// the owning schedule's id for a scheduled-fire submission — see the
    /// `Approval::schedule_id` doc comment for why this matters.
    ///
    /// `origin` (#2442) declares the minting surface, and is RECORDED here
    /// rather than enforced here. Minting is a legitimate act by a legitimately
    /// authorised caller; the illegitimate act is redeeming that ticket on a
    /// different surface, so the refusal lives at the redemption — see
    /// `declares_non_mcp_surface` and `consume_ticket`.
    ///
    /// This function used to refuse a `mcp.`-prefixed definition_id from a
    /// declared non-MCP origin. That check was removed deliberately: it stopped
    /// the forgery, but it also failed closed on every PRE-EXISTING operator
    /// definition under the prefix, on a path the store cannot tell apart from
    /// an attack. On the scheduler that meant a permanently dropped occurrence
    /// whose row is indistinguishable from a successful run in every field
    /// `GET /api/schedules` exposes, with no safe rebuild available. Do not
    /// reinstate it: the redemption guard closes the same hole and strands
    /// nothing. Authoring a NEW definition under the prefix is still refused, at
    /// `instruction_store.cpp` and `instruction_yaml.cpp`.
    std::expected<std::string, std::string>
    submit(const std::string& definition_id, const std::string& submitted_by,
           const std::string& scope_expression, const std::string& schedule_id = "",
           ApprovalOrigin origin = ApprovalOrigin::kUnspecified);

    std::vector<Approval> query(const ApprovalQuery& q = {}) const;

    /// Single-approval lookup by id (read-only). Two callers: the versioned
    /// GET /api/v1/approvals/{id} status_url target (query()'s LIMIT 100 would
    /// false-404 an id that has aged past the top window), and the MCP
    /// approval-ticket recall path (#289), which reads
    /// status/definition_id/scope_expression/consumed_at to validate a ticket
    /// before consuming it. Returns std::nullopt when no row matches; does NOT
    /// touch the lifecycle (submit/approve/reject/consume are elsewhere).
    /// True iff the store is usable (schema migrated). False after a failed
    /// migration — feeds the /readyz + /healthz conjunction so a broken approval
    /// schema fails the probe instead of serving errors behind a green light
    /// (governance sre-BLOCKING-1). The handle is borrowed; this never closes it.
    bool is_open() const { return db_ != nullptr; }

    std::optional<Approval> get(const std::string& id) const;

    /// get() with the store failure kept apart from the row simply not being
    /// there. Both read back as nullopt through get(), which is fine for a
    /// caller that 404s either way, and NOT fine for one deciding whether a
    /// one-time capability is spent — see consume_ticket's pre-consume recheck,
    /// which uses this.
    std::expected<std::optional<Approval>, std::string> get_checked(const std::string& id) const;

    /// Newest PENDING approval matching (definition_id, submitted_by,
    /// scope_expression), or nullopt. The MCP approval-ticket mint dedup key
    /// (#289 / governance UP-1): reusing an extant pending ticket makes the mint
    /// idempotent and stops a supervised token flooding the global pending cap.
    std::optional<Approval> find_pending(const std::string& definition_id,
                                         const std::string& submitted_by,
                                         const std::string& scope_expression) const;

    int pending_count() const;

    /// Count of PENDING approvals submitted by one principal. Backs the MCP
    /// mint's per-submitter sub-cap (governance sec8-MEDIUM-1): dedup alone does
    /// not stop an adaptive flood (a nonce key defeats the args-hash), so the
    /// mint bounds any single supervised token's share of the GLOBAL cap.
    int pending_count_for(const std::string& submitted_by) const;

    std::expected<void, std::string> approve(const std::string& id, const std::string& reviewer,
                                             const std::string& comment);

    std::expected<void, std::string> reject(const std::string& id, const std::string& reviewer,
                                            const std::string& comment);

    /// Atomically consume an APPROVED, not-yet-consumed approval as a one-time
    /// MCP ticket (#289). Returns ok() iff THIS call transitioned consumed_at
    /// 0→now — the CAS (`WHERE status='approved' AND consumed_at=0 RETURNING 1`)
    /// carries the match signal in the step return code, so there is no
    /// `sqlite3_changes()` race on the shared FULLMUTEX connection (#1033). A
    /// replay of an already-consumed ticket, or an absent/non-approved id,
    /// returns unexpected. The caller validates definition_id + args BEFORE
    /// calling; this method guards the double-consume (concurrent-recall) race so
    /// a mutating tool executes at most once per ticket.
    ///
    /// `consumed_by` records WHO recalled the ticket (PR #1796 H3/N2, SOC-2
    /// CC7.2) — the caller passes the authenticated principal; it is stored in
    /// the same CAS UPDATE so the who and the when can never disagree.
    std::expected<void, std::string> consume_ticket(const std::string& id,
                                                    const std::string& consumed_by);

    /// consume_ticket with a pre-consume recheck (#2443). A ticket can sit
    /// approved-but-unconsumed for up to the 7-day TTL, so the state its effect
    /// assumes may have moved on (the canonical case: an engine-key rotation the
    /// ticket confirms has already resolved). Without a recheck the recall
    /// matches, CONSUMES, and only then does the handler fail — burning a
    /// human-approved one-time capability on a no-op and forcing a fresh
    /// approval round.
    ///
    /// Order: match the row → reject a non-consumable one → evaluate
    /// `precondition` → CAS. A precondition denial returns
    /// ConsumeFailure::kPrecondition and leaves the row untouched, so the same
    /// ticket is still recallable once the operator resolves the drift.
    ///
    /// `precondition` runs WITHOUT `mtx_` held, deliberately: it inspects state
    /// OUTSIDE this store (rotation status, device state — never authority; see
    /// ConsumePrecondition), which no lock
    /// here can freeze, so holding the store mutex across an arbitrary caller
    /// callback would buy no atomicity while adding a lock-order hazard and
    /// serialising the store behind caller I/O. The consequence is honest rather
    /// than hidden: this NARROWS the drift window, it does not close it — state
    /// can still move between a passing recheck and the CAS, and a handler must
    /// stay correct when it does. The CAS remains the sole one-time-consumption
    /// guard, so a concurrent recall still loses exactly as before.
    ///
    /// An empty `precondition` behaves exactly like the two-argument overload.
    std::expected<void, ConsumeError> consume_ticket(const std::string& id,
                                                     const std::string& consumed_by,
                                                     const ConsumePrecondition& precondition);

private:
    std::expected<void, std::string> set_review_status(const std::string& id,
                                                       const std::string& status,
                                                       const std::string& reviewer,
                                                       const std::string& comment);

    sqlite3* db_;
    mutable std::mutex mtx_; // protects all db_ access (G4-UHP-MCP-005)
};

} // namespace yuzu::server
