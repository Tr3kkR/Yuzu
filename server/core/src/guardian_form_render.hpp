#pragma once

/// @file guardian_form_render.hpp
///
/// Schema-driven rendering + form-decode for the Guardian "New Guard" authoring
/// modal. The form is one consumer of the compiled-in schema catalog
/// (`guardian_schema_registry.hpp`, also published at
/// `GET /api/v1/guaranteed-state/schemas`): the operator picks a **trigger type**
/// and only that trigger's fields are shown, rendered from the catalog. So when a
/// new trigger/assertion type is added to the catalog it appears in the form with
/// no UI change — only the friendly trigger label is UI-curated.
///
/// Two halves, one source of truth:
///   * `render_guard_form()` — the modal card HTML (trigger selector + per-type
///     param fieldsets + remediation + collapsed resilience). Pure.
///   * `assemble_spark_assertion()` — the submit half. Given the chosen trigger
///     (= assertion type) and a form-value getter, it reads exactly that type's
///     param keys from the catalog, validates the required ones, and derives the
///     paired spark from the assertion family (registry-* → registry-change,
///     file-* → file-change). The result feeds `guardian::derive_rule_spec`, the
///     same path the REST create uses — dashboard and API produce identical specs.
///
/// Param field NAMES are namespaced by trigger type (`<type>__<key>`, see
/// `form_field_name`) so two triggers can carry a same-named param (registry's
/// `expected` vs file-exists's `expected`, both types' `path`) without the
/// inactive fieldset's value shadowing the active one in the POST — independent of
/// how the bundled htmx serialises disabled controls.

#include <functional>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace yuzu::server::guardian {

/// The structured spark + assertion blocks decoded from the create-form POST, or
/// an `error` (unknown trigger type / missing required field) to surface inline.
struct SparkAssertion {
    nlohmann::json spark;     ///< {type, params:{}} — derived from the assertion family
    nlohmann::json assertion; ///< {type, params:{...}} — the chosen trigger's params
    std::optional<std::string> error;
};

/// HTML for the "New Guard" modal card (header + form body + footer). Trigger
/// selector and per-type param fields are rendered from the schema catalog;
/// remediation + resilience are carried as stable hand-authored controls. Pure.
/// `error_html`, when non-empty, is injected at the top of the body (the re-render
/// path after a validation/store failure).
std::string render_guard_form(const std::string& error_html = "");

/// Decode a create-form submission into spark + assertion blocks. `assertion_type`
/// is the chosen trigger (e.g. "file-hash-equals"); `get(name)` returns the posted
/// form value for `name` ("" if absent). Reads the type's param keys from the
/// catalog, omitting empty optionals (defaults apply downstream) and erroring on a
/// missing required key or an unknown type.
SparkAssertion assemble_spark_assertion(const std::string& assertion_type,
                                        const std::function<std::string(const std::string&)>& get);

/// The POST field name for a trigger type's param (`<assertion_type>__<key>`).
/// Shared by the renderer and the decoder so they cannot disagree.
std::string form_field_name(const std::string& assertion_type, const std::string& param_key);

/// Optional edit context for render_baseline_form. When `baseline_id` is non-empty
/// the form renders in EDIT mode: the name is pre-filled, the `selected` member-guard
/// names are pre-rendered as removable chips, and the form POSTs to the update route
/// (`/fragments/guardian/baseline/<id>`) instead of create. Empty = create mode.
struct BaselineFormEdit {
    std::string baseline_id;
    std::string name;
    std::vector<std::string> selected; ///< member guard NAMES to pre-chip
};

/// HTML for the "New Baseline" / "Edit Baseline" modal card. `guard_names` seeds a
/// `<datalist>` so the Member-guards field is a type-to-filter dropdown of existing
/// guards (multi-select via chips, JS-side). Device targeting (management-group
/// assignment) is set elsewhere and deferred. `edit` (when its baseline_id is set)
/// switches the card to edit mode — pre-filled name + member chips, posting to the
/// update route. Pure.
std::string render_baseline_form(const std::vector<std::string>& guard_names,
                                 const BaselineFormEdit& edit = {});

} // namespace yuzu::server::guardian
