- **New Definition panel: canonical YAML that passes Validate now Saves** (#1993).
  `POST /api/instructions/yaml` previously extracted `name`/`plugin`/`action` by raw
  substring scanning against a flat, undocumented schema, so a definition in the
  canonical nested format (`metadata.id`, `spec.execution.plugin/action` — the shape
  used by the docs, the bundled importer, and every built-in definition) validated
  green but failed to save with "Missing required fields". Save and validate-yaml now
  share one schema-aware parser (`instruction_yaml`) that accepts both the canonical
  nested schema and the panel's flat form, honours `metadata.id` as the definition ID,
  applies the same defaults as the bundled importer, and reports the specific missing
  field instead of a blanket error.
