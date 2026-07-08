- **New Definition panel: canonical YAML that passes Validate now Saves** (#1993).
  `POST /api/instructions/yaml` previously extracted `name`/`plugin`/`action` by raw
  substring scanning against a flat, undocumented schema, so a definition in the
  canonical nested format (`metadata.id`, `spec.execution.plugin/action` — the shape
  used by the docs, the bundled importer, and every built-in definition) validated
  green but failed to save with "Missing required fields". Save and validate-yaml now
  share one schema-aware parser (`instruction_yaml`) that accepts both the canonical
  nested schema and the panel's flat form, honours `metadata.id` as the definition ID
  on create (duplicate ids now return **409** with a denied audit row instead of
  minting a silent second copy; on update a mismatched `metadata.id` is rejected),
  applies the same defaults as the bundled importer, and reports the specific missing
  field instead of a blanket error. The Save path now emits `instruction.create` /
  `instruction.update` audit events and `instruction.created`/`.updated` analytics
  events like every sibling write surface, and explicit definition ids are bounded
  to `[A-Za-z0-9._-]{1,128}` at the store chokepoint.
