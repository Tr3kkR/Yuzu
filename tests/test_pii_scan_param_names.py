#!/usr/bin/env python3
"""test_pii_scan_param_names.py — pii_scan definition<->plugin parameter-name
drift gate.

A real bug this test exists to make structurally impossible to ship again:
content/definitions/pii_scan.yaml declared a parameter as `watchPath` for
`enable_realtime`/`disable_realtime`, but pii_scan_plugin.cpp read
`params.get("watch_path", ...)` — a different string. Every real dispatch
of the shipped InstructionDefinition failed with `pii_scan.no_watch_path`;
only an undocumented raw caller who happened to guess the internal name
could ever have exercised the action at all. Nothing mechanically checked
that the two files agreed on parameter names.

This script parses every `parameters.properties` key declared across
content/definitions/pii_scan.yaml's InstructionDefinitions and asserts each
one appears as a literal `params.get("<name>", ...)` string somewhere in
agents/plugins/pii_scan/src/pii_scan_plugin.cpp. Deliberately scoped to
pii_scan only (not generalized across every plugin in one pass) — a
cross-plugin version of this check needs to account for legitimately
different patterns other plugins use (parameters forwarded only via a
trigger's own config_json, parameters read through a helper function
rather than a direct params.get() call, etc.) that would need individual
verification before being folded into a blanket gate; scoping this to the
one plugin with a demonstrated real bug keeps the check both safe to add
now and directly targeted at what actually shipped broken.

Runnable standalone: `python3 tests/test_pii_scan_param_names.py`.
Hermetic — reads only source files already on disk under this repository;
no subprocess, no network, no clock. Requires PyYAML, an existing hard
build dependency (see embed_content.py).
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

try:
    import yaml  # type: ignore[import-not-found]
except ImportError:
    print(
        "ERROR: test_pii_scan_param_names.py requires PyYAML "
        "(already a hard build dependency — see embed_content.py). "
        "Install with `pip install pyyaml`.",
        file=sys.stderr,
    )
    sys.exit(1)

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFINITION_PATH = REPO_ROOT / "content" / "definitions" / "pii_scan.yaml"
PLUGIN_SOURCE_PATH = REPO_ROOT / "agents" / "plugins" / "pii_scan" / "src" / "pii_scan_plugin.cpp"

_PARAMS_GET_RE = re.compile(r'params\.get\(\s*"([^"]+)"')


def parse_declared_param_names(definition_path: Path) -> dict[str, set[str]]:
    """Every `definition_id -> {declared parameter names}` across every
    InstructionDefinition document in the file.
    """
    declared: dict[str, set[str]] = {}
    with definition_path.open(encoding="utf-8") as f:
        docs = list(yaml.safe_load_all(f))
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        metadata = doc.get("metadata") or {}
        def_id = metadata.get("id")
        spec = doc.get("spec")
        if not def_id or not isinstance(spec, dict):
            continue
        params = spec.get("parameters") or {}
        properties = params.get("properties") or {}
        if isinstance(properties, dict):
            declared[def_id] = set(properties.keys())
    return declared


def parse_plugin_param_reads(plugin_source_path: Path) -> set[str]:
    """Every string literal passed as the first argument to `params.get(...)`
    anywhere in the plugin source file.
    """
    text = plugin_source_path.read_text(encoding="utf-8")
    return set(_PARAMS_GET_RE.findall(text))


class PiiScanParamNameConsistency(unittest.TestCase):
    def test_every_declared_parameter_is_read_by_name(self) -> None:
        declared = parse_declared_param_names(DEFINITION_PATH)
        self.assertTrue(declared, f"no InstructionDefinitions found in {DEFINITION_PATH}")

        read_names = parse_plugin_param_reads(PLUGIN_SOURCE_PATH)
        self.assertTrue(
            read_names, f"no params.get(...) calls found in {PLUGIN_SOURCE_PATH} — parser broken?"
        )

        missing: list[tuple[str, str]] = []
        for def_id, param_names in sorted(declared.items()):
            for name in sorted(param_names):
                if name not in read_names:
                    missing.append((def_id, name))

        self.assertFalse(
            missing,
            "content/definitions/pii_scan.yaml declares a parameter name the plugin never "
            "reads via params.get(...) under that exact name (definition_id, parameter):\n"
            + "\n".join(f"  {def_id}: {name!r}" for def_id, name in missing)
            + f"\n\nplugin source reads these names: {sorted(read_names)}",
        )


if __name__ == "__main__":
    unittest.main()
