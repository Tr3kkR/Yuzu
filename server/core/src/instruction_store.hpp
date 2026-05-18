#pragma once

#include <sqlite3.h>

#include <atomic>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <string>
#include <shared_mutex>
#include <vector>

namespace yuzu::server {

struct InstructionDefinition {
    std::string id;
    std::string name;
    std::string version;
    std::string type; // "question" or "action"
    std::string plugin;
    std::string action;
    std::string description;
    bool enabled{true};
    std::string instruction_set_id;
    int gather_ttl_seconds{300};
    int response_ttl_days{90};
    std::string created_by;
    int64_t created_at{0};
    int64_t updated_at{0};
    // Extended fields (Phase 2)
    std::string yaml_source;      // verbatim YAML (source of truth)
    std::string parameter_schema; // JSON Schema for parameters
    std::string result_schema;    // result column definitions JSON
    std::string approval_mode;    // "auto", "role-gated", "always"
    std::string concurrency_mode; // "per-device", "per-definition", etc.
    std::string platforms;        // comma-separated: "windows,linux,darwin"
    std::string min_agent_version;
    std::string required_plugins; // comma-separated
    std::string readable_payload; // e.g. "Inspect service '${serviceName}'"
    // Issue #253: spec.visualization serialized as JSON. Empty (or "{}") means
    // the definition has no visualization configured and the
    // /api/v1/executions/{id}/visualization endpoint returns 404 for it.
    std::string visualization_spec;
    // Issue #254 (8.2): spec.responseTemplates serialized as a JSON array of
    // template objects. Empty (or "[]") means no operator-defined templates;
    // the response-templates engine synthesises a __default__ from
    // result_schema / plugin columns at read time.
    std::string response_templates_spec;
};

struct InstructionQuery {
    std::string name_filter;
    std::string plugin_filter;
    std::string type_filter;
    std::string set_id_filter;
    bool enabled_only{false};
    int limit{100};
};

struct InstructionSet {
    std::string id;
    std::string name;
    std::string description;
    std::string created_by;
    int64_t created_at{0};
};

class InstructionStore {
public:
    explicit InstructionStore(const std::filesystem::path& db_path);
    ~InstructionStore();

    InstructionStore(const InstructionStore&) = delete;
    InstructionStore& operator=(const InstructionStore&) = delete;

    bool is_open() const;

    /// When true, `import_definition_json` rejects payloads that lack a
    /// `signature` field. Payloads WITH a signature are always verified
    /// regardless of the flag — failed verification rejects unconditionally.
    /// Defaults to true since #1073 / W7.4 sibling-gap closure: unsigned
    /// instruction imports are a fleet-wide arbitrary-code-execution surface
    /// (an operator with InstructionDefinition:Write can publish a malicious
    /// definition that executes on every targeted agent). Operators with
    /// legacy unsigned import flows must explicitly opt out via the
    /// `--allow-unsigned-definitions` / `YUZU_ALLOW_UNSIGNED_DEFINITIONS`
    /// server flag, which calls `set_require_signed_definitions(false)` and
    /// emits a `server.unsigned_definitions_allowed` startup audit event —
    /// exact parity with #802 / `--allow-unsigned-packs`.
    ///
    /// Atomic for the same reason as ProductPackStore::require_signed_packs_:
    /// the setter is called at startup before any concurrent reader, but
    /// TSAN cannot prove that; atomic load/store with relaxed memory order
    /// silences TSAN and future-proofs against any later runtime-toggle
    /// endpoint.
    void set_require_signed_definitions(bool require) {
        require_signed_definitions_.store(require, std::memory_order_relaxed);
    }
    bool require_signed_definitions() const {
        return require_signed_definitions_.load(std::memory_order_relaxed);
    }

    // Definitions
    std::vector<InstructionDefinition> query_definitions(const InstructionQuery& q = {}) const;
    std::optional<InstructionDefinition> get_definition(const std::string& id) const;
    std::expected<std::string, std::string> create_definition(const InstructionDefinition& def);
    std::expected<void, std::string> update_definition(const InstructionDefinition& def);
    bool delete_definition(const std::string& id);

    // Import/Export
    std::string export_definition_json(const std::string& id) const;

    /// Parse a JSON-encoded InstructionDefinition envelope and create it.
    ///
    /// SECURITY SCOPE (#1073): this method gates the **import** surface
    /// — definitions that arrive from outside the operator's authoring
    /// session, e.g. CI-built packs, content distributed via the
    /// supply chain, manifests fetched from a registry. The signature
    /// + `require_signed_definitions_` gate authenticates the publisher,
    /// not the operator pushing the import. Failed verification rejects
    /// regardless of the flag.
    ///
    /// **NOT in scope of this method:** the authoring surfaces
    /// (`POST /api/instructions`, `POST /api/instructions/yaml`, and
    /// `PUT /api/instructions/{id}`) that go through `create_definition`
    /// /`update_definition` directly. Those surfaces trust the
    /// `InstructionDefinition:Write` RBAC permission as the author
    /// trust boundary (the operator IS the source — there is no supply
    /// chain to authenticate). See follow-up issue for the architectural
    /// question of whether the authoring surfaces should ALSO require
    /// signed envelopes (operator-decision-required, UX trade-off).
    ///
    /// Wire format for signing:
    ///   * Optional top-level `signature` field — hex-encoded Ed25519
    ///     signature over the `yaml_source` field's bytes verbatim.
    ///   * Optional top-level `publicKey` field — hex-encoded Ed25519
    ///     public key (64 hex chars / 32 bytes).
    ///   * `yaml_source` is the authoritative signed-content carrier
    ///     (mirrors ProductPack's YAML-document signing model). If the
    ///     import lacks `yaml_source` the signature can never verify.
    ///   * Both fields present + valid signature → accept.
    ///   * Both present + invalid signature → reject (tampered).
    ///   * Neither present → unsigned; gated by `require_signed_definitions_`.
    ///   * Exactly one present → reject (incomplete signing metadata).
    ///   * Field present but wrong JSON type (non-string) → reject as
    ///     `incomplete signing metadata` (distinct error message).
    ///   * Signature/publicKey wrong length → reject before allocation
    ///     (DoS amplification guard).
    std::expected<std::string, std::string> import_definition_json(const std::string& json);

    /// Trusted-content variant — bypasses the signature gate. ONLY for
    /// build-time-baked content (the `kBundledDefinitions` boot seed in
    /// `bundled_content.cpp`), where the authenticity of the bytes is
    /// established by the build-time linkage into the binary itself, not
    /// by a runtime signature. The operator-facing
    /// `--allow-unsigned-definitions` flag controls the public path only;
    /// it does NOT affect this trusted path. Callers MUST be internal
    /// boot-time code — there is no REST / MCP / network surface for this
    /// method by design.
    std::expected<std::string, std::string> import_definition_json_trusted(const std::string& json);

    // Instruction Sets
    std::vector<InstructionSet> list_sets() const;
    std::expected<std::string, std::string> create_set(const InstructionSet& s);
    bool delete_set(const std::string& id);

private:
    sqlite3* db_{nullptr};
    mutable std::shared_mutex mtx_; // protects db_ access (G3-ARCH-003)
    /// Security-by-default since #1073 (W7.4 sibling-gap closure): imports
    /// without a `signature` field are rejected by `import_definition_json`.
    /// See setter doc above for the operator opt-out flag.
    std::atomic<bool> require_signed_definitions_{true};

    // Internal variants called under existing lock (no re-lock)
    std::optional<InstructionDefinition> get_definition_impl(const std::string& id) const;
    std::expected<std::string, std::string>
    create_definition_impl(const InstructionDefinition& def);

    /// Shared implementation behind `import_definition_json` and
    /// `import_definition_json_trusted`. When `check_signature` is true,
    /// runs the #1073 Ed25519 signature gate against `signature` +
    /// `publicKey` + `yaml_source` JSON fields before parsing the
    /// definition. When false, bypasses the gate entirely. Public callers
    /// must use one of the two named entry points so the trust boundary
    /// is explicit at every call site.
    std::expected<std::string, std::string> import_definition_json_impl(const std::string& json,
                                                                        bool check_signature);
};

} // namespace yuzu::server
