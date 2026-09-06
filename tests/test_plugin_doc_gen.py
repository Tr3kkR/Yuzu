#!/usr/bin/env python3
"""Unit tests for tools/plugin-doc-gen/plugin_doc_gen.py's pure functions.

Inline fixtures only — no repository state, no build. The tree-level gate
(every README's fences byte-match the sources, hash freshness, the ratchet)
is tests/test_plugin_readmes.py.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools" / "plugin-doc-gen"))

import plugin_doc_gen as g  # noqa: E402

MATRIX = """intro text
<!-- BEGIN GENERATED: capmatrix-gen (#2204) — do not hand-edit; regenerate with
     tools/capmatrix-gen, verified by scripts/ci/check-capability-matrix.sh -->
| Plugin | Action | OS | Support | Rung | Mechanism | Fallback |
|---|---|---|---|---|---|---|
| alpha | probe | linux | unsupported | - | - | not bound on any reachable host |
| alpha | probe | macos | constrained | 1 | IOKit thing | identity only |
| alpha | probe | windows | supported | 1 | IOCTL thing | - |
| beta | list | linux | supported | 2 | argv runner | - |
| beta | list | macos | supported | 2 | argv runner | - |
| beta | list | windows | supported | 1 | COM | - |
<!-- END GENERATED -->
| not | a | row | after | the | block | x |
"""

FRAGMENT = """
inline constexpr std::array<CommandCapability, 2> kRows{{
    {
        .plugin = "alpha",
        .action = "probe",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "beta", .action = "list",
        .dispatch_class = DispatchClass::Mutating, .mutability = Mutability::Reversible,
        .securable = "Security", .operation = authz::Operation::Write,
        .risk_tier = authz::RiskTier::High, .execute_gate = ExecuteGate::AdminOrApproval,
    },
}};
"""

PLUGIN_TU = '''
class AlphaPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "alpha"; }
    std::string_view version() const noexcept override { return "1.2.3"; }
    std::string_view description() const noexcept override {
        return "Probes things "
               "and reports them";
    }
};
'''

PLUGIN_TU_CONST = '''
namespace { constexpr const char* kName = "gamma"; constexpr const char* kVersion = "0.9.0"; }
class GammaPlugin final : public yuzu::Plugin {
    std::string_view name() const noexcept override { return kName; }
    std::string_view version() const noexcept override { return kVersion; }
};
'''

SAMPLE = """captured: macos 26.5.1 · bare-metal · 2026-09-06 · euid 501 · leg-hash pending
== action=probe
row|one
row|two
[result_status] CONSTRAINED / PARTIAL / macos:iokit:health_unread

== action=danger key=value path="/Applications/Some App"
[not captured] Destructive/Irreversible: not executed on a live host
"""

README = """# alpha

<!-- BEGIN GENERATED: plugin-doc-gen header -->
old
<!-- END GENERATED -->

## How it works

Reads things.

```mermaid
flowchart LR
  A --> B
```

## OS capability

<!-- BEGIN GENERATED: plugin-doc-gen capability -->
<!-- END GENERATED -->

## Privileges and prerequisites

| OS | Runs as | Extra grant needed | Measured | If the read is refused |
|---|---|---|---|---|
| Windows | svc | none | 2026-09-01 | denied row |

## Data contract

### Result status

| Status | Completeness | Provenance | When |
|---|---|---|---|
| `OK` | — | — | clean |

### Where the data goes

- **Instruction result.** store
- **Siblings:** none

## Caveats and known gaps

1. **One.** first
2. **Two.** second
"""


def _defs(columns):
    return [g.Definition(id="x.alpha.probe", display_name="Probe", description="d", plugin="alpha",
                         action="probe", platforms=["windows"], approval_mode="auto",
                         execute_roles=["r"], author_roles=["a"], gather={}, parameters={},
                         columns=columns, path="content/definitions/alpha.yaml")]


class MatrixParsing(unittest.TestCase):
    def test_rows_grouped_and_dashes_blanked(self):
        m = g.parse_matrix_block(MATRIX)
        self.assertEqual(set(m), {"alpha", "beta"})
        leg = m["alpha"]["probe"]["linux"]
        self.assertEqual((leg.support, leg.rung, leg.mechanism), ("unsupported", "", ""))
        self.assertEqual(leg.fallback, "not bound on any reachable host")
        self.assertEqual(m["beta"]["list"]["windows"].mechanism, "COM")

    def test_rows_after_end_marker_are_ignored(self):
        self.assertNotIn("not", g.parse_matrix_block(MATRIX))

    def test_missing_block_raises(self):
        with self.assertRaises(ValueError):
            g.parse_matrix_block("no block here")

    def test_best_support_order(self):
        m = g.parse_matrix_block(MATRIX)
        self.assertEqual(g.best_support(m["alpha"], "windows"), "supported")
        self.assertEqual(g.best_support(m["alpha"], "macos"), "constrained")
        self.assertEqual(g.best_support(m["alpha"], "linux"), "unsupported")
        self.assertEqual(g.best_support({}, "linux"), "undeclared")


class CapabilityParsing(unittest.TestCase):
    def test_rows_and_enum_tails(self):
        rows = g.parse_capability_fragment(FRAGMENT, "frag.hpp")
        self.assertEqual([(r.plugin, r.action) for r in rows], [("alpha", "probe"), ("beta", "list")])
        self.assertEqual(rows[0].securable, "Inventory")
        self.assertEqual(rows[0].operation, "Read")
        self.assertEqual(rows[0].execute_gate, "None")
        self.assertEqual(rows[1].dispatch_class, "Mutating")
        self.assertEqual(rows[1].risk_tier, "High")
        self.assertEqual(rows[1].execute_gate, "AdminOrApproval")


class IdentityParsing(unittest.TestCase):
    def test_literal_identity_with_adjacent_strings(self):
        ident = g.parse_plugin_identity(PLUGIN_TU)
        self.assertEqual(ident, {"name": "alpha", "version": "1.2.3",
                                 "description": "Probes things and reports them"})

    def test_constant_identity_resolved(self):
        ident = g.parse_plugin_identity(PLUGIN_TU_CONST)
        self.assertEqual(ident["name"], "gamma")
        self.assertEqual(ident["version"], "0.9.0")
        self.assertIsNone(ident["description"])


class DefinitionParsing(unittest.TestCase):
    def test_only_definitions_with_plugin_and_action(self):
        docs = [
            {"kind": "InstructionSet", "metadata": {"id": "s"}},
            {"kind": "InstructionDefinition", "metadata": {"id": "x.a", "displayName": "A",
                                                            "description": "multi\n  line"},
             "spec": {"execution": {"plugin": "alpha", "action": "probe"},
                      "platforms": ["windows", "darwin"],
                      "approval": {"mode": "auto"},
                      "permissions": {"executeRoles": ["r1"], "authorRoles": ["a1"]},
                      "gather": {"ttlSeconds": 120},
                      "parameters": {"type": "object", "properties": {"p": {"type": "string"}},
                                     "required": ["p"]},
                      "result": {"columns": [{"name": "c", "type": "string", "values": ["x", "y"],
                                              "example": "x", "platforms": ["windows"]}]}}},
            {"kind": "InstructionDefinition", "metadata": {"id": "bad"}, "spec": {}},
        ]
        defs = g.parse_definition_docs(docs, "content/definitions/alpha.yaml")
        self.assertEqual(len(defs), 1)
        d = defs[0]
        self.assertEqual(d.description, "multi line")
        self.assertEqual(d.columns[0]["values"], ["x", "y"])
        self.assertEqual(d.columns[0]["platforms"], ["windows"])
        self.assertEqual(d.gather, {"ttlSeconds": 120})


class SampleParsing(unittest.TestCase):
    def test_stamp_actions_status_and_not_captured(self):
        s = g.parse_sample(SAMPLE, "macos")
        self.assertEqual(s.stamp["os_version"], "26.5.1")
        self.assertEqual(s.stamp["host_class"], "bare-metal")
        self.assertEqual(s.stamp["privilege"], "euid 501")
        self.assertEqual(s.stamp["leg_hash"], "pending")
        self.assertEqual([a["action"] for a in s.actions], ["probe", "danger"])
        self.assertEqual(s.actions[0]["rows"], ["row|one", "row|two"])
        self.assertEqual(s.actions[0]["result_status"]["provenance"], "macos:iokit:health_unread")
        self.assertEqual(s.actions[1]["params"], 'key=value path="/Applications/Some App"')
        self.assertEqual(s.actions[1]["not_captured"], "Destructive/Irreversible: not executed on a live host")
        self.assertIsNone(s.actions[1]["result_status"])

    def test_bad_stamp_rejected(self):
        with self.assertRaises(ValueError):
            g.parse_sample("== action=x\nrow\n", "linux")

    def test_trim(self):
        rows = [f"r{i}" for i in range(15)]
        out = g.trim_rows(rows, 12)
        self.assertEqual(len(out), 13)
        self.assertEqual(out[-1], "… 12 of 15 rows shown")
        self.assertEqual(g.trim_rows(rows[:3], 12), rows[:3])


class LegHash(unittest.TestCase):
    def test_stable_and_sensitive_to_mechanism_not_fallback(self):
        m = g.parse_matrix_block(MATRIX)
        cols = [{"name": "c", "type": "string"}]
        h1 = g.leg_hash(m["alpha"], _defs(cols))
        self.assertEqual(len(h1), 12)
        self.assertEqual(h1, g.leg_hash(m["alpha"], _defs(cols)))
        m["alpha"]["probe"]["windows"].fallback = "reworded"
        self.assertEqual(h1, g.leg_hash(m["alpha"], _defs(cols)))
        m["alpha"]["probe"]["windows"].mechanism = "different"
        self.assertNotEqual(h1, g.leg_hash(m["alpha"], _defs(cols)))

    def test_sensitive_to_column_shape_only(self):
        m = g.parse_matrix_block(MATRIX)
        h1 = g.leg_hash(m["alpha"], _defs([{"name": "c", "type": "string", "example": "1"}]))
        h2 = g.leg_hash(m["alpha"], _defs([{"name": "c", "type": "string", "example": "2"}]))
        h3 = g.leg_hash(m["alpha"], _defs([{"name": "c", "type": "int64"}]))
        self.assertEqual(h1, h2)
        self.assertNotEqual(h1, h3)


class Splicing(unittest.TestCase):
    def test_replace_and_report_missing(self):
        out, missing = g.splice(README, {"header": "NEW", "capability": "CAP"}, g.README_BLOCKS)
        self.assertIn("<!-- BEGIN GENERATED: plugin-doc-gen header -->\nNEW\n<!-- END GENERATED -->", out)
        self.assertIn("<!-- BEGIN GENERATED: plugin-doc-gen capability -->\nCAP\n<!-- END GENERATED -->", out)
        self.assertNotIn("old", out)
        self.assertEqual(missing, ["inputs", "outputs", "samples", "source"])

    def test_idempotent(self):
        once, _ = g.splice(README, {"header": "NEW"})
        twice, _ = g.splice(once, {"header": "NEW"})
        self.assertEqual(once, twice)


class HandSections(unittest.TestCase):
    def test_sections_split_and_manifest_shape(self):
        sec = g.split_sections(README)
        self.assertIn("## How it works", sec)
        self.assertIn("### Result status", sec)
        m = g.hand_sections_to_manifest(README)
        self.assertEqual(m["how_it_works"], "Reads things.")
        self.assertEqual(m["privileges"], [{"os": "Windows", "runs_as": "svc", "grant": "none",
                                            "measured": "2026-09-01", "if_refused": "denied row"}])
        self.assertEqual(m["result_status"][0]["status"], "`OK`")
        self.assertEqual(m["where_the_data_goes"], ["**Instruction result.** store", "**Siblings:** none"])
        self.assertEqual(m["caveats"], ["**One.** first", "**Two.** second"])

    def test_fenced_headings_are_not_sections(self):
        text = "## Real\n\n```\n## not a heading\n```\n\n## Other\nx"
        self.assertEqual(set(g.split_sections(text)), {"## Real", "## Other"})


class Rendering(unittest.TestCase):
    def _doc(self):
        m = g.parse_matrix_block(MATRIX)
        rows = g.parse_capability_fragment(FRAGMENT, "frag.hpp")
        return g.PluginDoc(name="alpha", version="1.2.3", description="Probes",
                           legs=m["alpha"], cap_rows=[r for r in rows if r.plugin == "alpha"],
                           definitions=_defs([{"name": "c", "type": "string", "values": ["x"],
                                               "example": "x", "platforms": ["darwin"],
                                               "description": "col"}]),
                           samples={"macos": g.parse_sample(SAMPLE, "macos")},
                           source={"plugin": ["agents/plugins/alpha/src/a.cpp"], "definitions": [],
                                   "capability_rows": ["frag.hpp"], "tests": [], "privilege_row": False,
                                   "changelog": []},
                           readme_path="agents/plugins/alpha/README.md")

    def test_header_platforms_and_security(self):
        h = g.render_header(self._doc())
        self.assertIn("Windows ✅ · macOS 🟡 constrained · Linux ⛔ unsupported", h)
        self.assertIn("securable `Inventory` · operation Read · risk Low · dispatch ReadOnly · approval gate None", h)
        self.assertIn("Collector · read-only · on-demand", h)
        self.assertIn("`probe` (definition `x.alpha.probe`)", h)

    def test_capability_matrix_and_limits(self):
        c = g.render_capability(self._doc())
        self.assertIn("| `probe` | ✅ supported · rung 1 · IOCTL thing | 🟡 constrained · rung 1 · IOKit thing | ⛔ unsupported |", c)
        self.assertIn("- **`probe` / Linux** — not bound on any reachable host", c)

    def test_outputs_table_uses_optional_keys(self):
        o = g.render_outputs(self._doc())
        self.assertIn("**`x.alpha.probe` — `c`**", o)
        self.assertIn("| `c` | string | `x` | macOS | `x` | col |", o)

    def test_inputs_none(self):
        self.assertEqual(g.render_inputs(self._doc()), "The action takes no parameters.")

    def test_samples_block_and_not_captured(self):
        s = g.render_samples(self._doc())
        self.assertIn("**macOS** — captured: macos 26.5.1 · bare-metal · 2026-09-06 · euid 501 · leg-hash pending", s)
        self.assertIn("== action=probe\nrow|one\nrow|two\n[result_status] CONSTRAINED / PARTIAL / macos:iokit:health_unread", s)
        self.assertIn('== action=danger key=value path="/Applications/Some App"\n[not captured] Destructive/Irreversible', s)

    def test_manifest_round_trip(self):
        doc = self._doc()
        m = g.build_manifest(doc, README)
        self.assertEqual(m["manifest_version"], g.MANIFEST_VERSION)
        self.assertEqual(m["platforms"], {"windows": "supported", "macos": "constrained", "linux": "unsupported"})
        self.assertEqual(m["security"][0]["securable"], "Inventory")
        self.assertEqual(m["actions"][0]["legs"]["macos"]["mechanism"], "IOKit thing")
        self.assertEqual(m["how_it_works"], "Reads things.")
        self.assertEqual(m["samples"]["macos"]["actions"][1]["not_captured"],
                         "Destructive/Irreversible: not executed on a live host")
        self.assertEqual(m["leg_hash"], g.leg_hash(doc.legs, doc.definitions))

    def test_index_and_nav(self):
        idx = g.render_index([self._doc()])
        self.assertIn("| `alpha` | ✅ 🟡 ⛔ | Probes | [README](../../agents/plugins/alpha/README.md) |", idx)
        nav = g.render_nav([self._doc()])
        self.assertIn("{ file: 'agents/plugins/alpha/README', slug: 'plugins/alpha', title: 'alpha' }", nav)


if __name__ == "__main__":
    unittest.main()
