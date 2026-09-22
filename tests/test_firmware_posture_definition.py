#!/usr/bin/env python3
"""test_firmware_posture_definition.py -- ties the C++ row-format contract
(`firmware|field|value|source`, tested in tests/unit/test_firmware_posture_parsers.cpp
against a hard-coded column list) to the definition YAML that actually ships it, so a
reordered or renamed result column fails here rather than only in a dashboard.
"""
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFINITION = REPO_ROOT / "content" / "definitions" / "firmware_posture.yaml"

# firmware_posture_parsers.hpp format_row: "firmware|" + field + "|" + value + "|" + source.
# The server decoder keeps field 0 as the row's discriminator (row_kind), so it must lead.
EXPECTED_COLUMNS = ["row_kind", "field", "value", "source"]


def _result_columns() -> list[str]:
    doc = yaml.safe_load(DEFINITION.read_text(encoding="utf-8"))
    return [c["name"] for c in doc["spec"]["result"]["columns"]]


def test_row_kind_is_the_first_declared_column():
    assert _result_columns()[0] == "row_kind"


def test_result_columns_match_the_wire_row_the_plugin_emits():
    assert _result_columns() == EXPECTED_COLUMNS
