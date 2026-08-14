- **`minLength` joins the MCP pre-approval input-schema catalogue.** The subset compiler
  that validates tool arguments before an approval ticket is minted or consumed could
  bound a string's ceiling but not its floor, so a property could be declared required and
  still be satisfied by `""`. Operands are checked when the schema compiles, so a schema
  the gate cannot fully enforce stays unbootable rather than partially enforced. Like
  `maxLength` it counts bytes — exact at `minLength: 1` (the not-empty case), but not a
  character-count guarantee above that.
