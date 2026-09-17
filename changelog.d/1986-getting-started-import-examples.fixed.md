- **Getting Started: the three "Import it via the API" examples now work on a default
  server** (#1986). They previously posted a hand-assembled flat JSON body to
  `POST /api/instructions/import` — never sending the YAML file the reader had just
  created, and failing anyway because that endpoint rejects unsigned imports by
  default. The tutorial now posts the YAML file itself to the authoring endpoint
  (`POST /api/instructions/yaml --data-urlencode "yaml_source@<file>.yaml"`), documents
  the `--allow-unsigned-definitions` / signed-envelope requirement of the import
  endpoint, and uses the definitions' canonical `metadata.id`s throughout the
  follow-on steps.
