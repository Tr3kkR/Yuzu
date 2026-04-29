#!/usr/bin/env python3
"""Build-time YAML→JSON converter for shipped Yuzu content.

Walks a content tree of .yaml files (InstructionDefinition,
InstructionSet, ProductPack), normalises each doc into the JSON envelope
shape that ``InstructionStore::import_definition_json`` and
``InstructionStore::create_set`` expect, and emits a .cpp file with two
``std::vector<std::string>`` constants the server iterates on startup.

Why build-time conversion: YAML parsing in C++ requires yaml-cpp, which
has known Windows MSVC build risk (#625) and would add a vcpkg
dependency. PyYAML is already present in every supported build env
(Linux/macOS/Windows MSYS2), and the conversion result is content-
addressable from the input tree, so embedding the JSON in the binary
keeps the air-gapped install story whole.

Usage:
    embed_content.py <content_root> <output.cpp>

Where <content_root> contains subdirectories ``definitions/`` and
``packs/`` of .yaml files. Multi-document YAML (``---`` separators)
is handled.
"""

from __future__ import annotations  # 'dict | None' type hints under py 3.9

import json
import re
import sys
from pathlib import Path

# PyYAML graceful fallback: required for content embedding, but missing
# from a build host the developer hasn't provisioned (e.g. fresh Windows
# MSYS2) shouldn't hard-fail the entire build. Emit empty bundle arrays
# and a build-time warning; the server will boot with no auto-imported
# content rather than failing to compile. (Gate 3 xp-S2.)
try:
    import yaml  # type: ignore[import-not-found]
    _YAML_OK = True
except ImportError:
    yaml = None  # type: ignore[assignment]
    _YAML_OK = False


def to_string_list(v):
    if v is None:
        return ""
    if isinstance(v, list):
        return ",".join(str(x) for x in v)
    return str(v)


def def_envelope(doc: dict, yaml_source: str) -> dict | None:
    """Convert an InstructionDefinition YAML doc to the JSON envelope
    accepted by InstructionStore::import_definition_json.

    Returns None if the doc is missing required fields (id, plugin, action)
    so the caller can skip silently rather than crash startup."""
    meta = doc.get("metadata") or {}
    spec = doc.get("spec") or {}
    exec_ = spec.get("execution") or {}
    approval = spec.get("approval") or {}
    gather = spec.get("gather") or {}

    # action may be on `spec.execution.action` or fall back to spec.action.
    action = exec_.get("action") or spec.get("action") or ""
    plugin = exec_.get("plugin") or spec.get("plugin") or ""
    id_ = meta.get("id") or ""
    if not (id_ and plugin and action):
        return None

    env = {
        "id": id_,
        "name": meta.get("displayName") or meta.get("name") or id_,
        "version": str(meta.get("version") or "1.0.0"),
        "type": spec.get("type") or "question",
        "plugin": plugin,
        "action": str(action).lower(),
        "description": meta.get("description") or "",
        "enabled": True,
        "platforms": to_string_list(spec.get("platforms")),
        "approval_mode": approval.get("mode") or "auto",
        "concurrency_mode": exec_.get("concurrency") or "per-device",
        "gather_ttl_seconds": int(gather.get("ttlSeconds") or 300),
        "yaml_source": yaml_source,
        "created_by": "system",
    }

    # Schemas: stringify nested objects so the store can persist them
    # verbatim and the engine parses them at query time.
    if spec.get("parameters") is not None:
        env["parameter_schema"] = json.dumps(spec["parameters"])
    if spec.get("result") is not None:
        env["result_schema"] = json.dumps(spec["result"])

    # Visualization — passed as a structured object; the store's normalise
    # step in import_definition_json wraps singular into a 1-element array.
    viz = spec.get("visualization") or spec.get("visualizations")
    if viz is not None:
        env["visualization"] = viz

    if spec.get("readablePayload"):
        env["readable_payload"] = spec["readablePayload"]

    return env


def set_envelope(doc: dict) -> dict | None:
    meta = doc.get("metadata") or {}
    id_ = meta.get("id") or ""
    if not id_:
        return None
    return {
        "id": id_,
        "name": meta.get("displayName") or meta.get("name") or id_,
        "description": meta.get("description") or "",
        "created_by": "system",
    }


def split_docs(text: str) -> list[str]:
    """Split a YAML file on ``---`` separators, mirroring the C++
    side's split_yaml_documents — preserves the original byte ranges
    so we can use them as the verbatim ``yaml_source`` for each doc."""
    parts = re.split(r"(?m)^---\s*$", text)
    # Drop empty lead-in (file starting with ---)
    return [p for p in parts if p.strip()]


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: embed_content.py <content_root> <output.cpp>",
              file=sys.stderr)
        return 1
    root = Path(sys.argv[1])
    out_path = Path(sys.argv[2])

    defs_json: list[str] = []
    sets_json: list[str] = []
    bad_defs: list[tuple[str, str]] = []  # (path, reason) — fail loudly at build

    if not _YAML_OK:
        # PyYAML missing on this build host — emit empty bundle so the
        # translation unit compiles, but warn loudly. Server will boot
        # with no auto-imported content. (Gate 3 xp-S2.)
        print(
            "WARNING: PyYAML not installed; bundled content will be empty. "
            "Install with: pip install pyyaml (or `pacman -S python-yaml` "
            "on MSYS2). See docs/windows-build.md for the supported path.",
            file=sys.stderr,
        )
    elif not root.is_dir():
        # Empty content root (e.g. when running outside the source tree)
        # is fine: emit an empty bundle so the build still produces a
        # valid translation unit.
        pass
    else:
        yaml_files = sorted(
            list((root / "definitions").rglob("*.yaml")) +
            list((root / "packs").rglob("*.yaml"))
        )
        seen_def_ids: set[str] = set()
        seen_set_ids: set[str] = set()

        for yf in yaml_files:
            text = yf.read_text(encoding="utf-8")
            for doc_text in split_docs(text):
                try:
                    doc = yaml.safe_load(doc_text)
                except yaml.YAMLError as e:
                    print(f"WARN {yf}: YAML parse error: {e}", file=sys.stderr)
                    continue
                if not isinstance(doc, dict):
                    continue
                kind = doc.get("kind")
                if kind == "InstructionDefinition":
                    env = def_envelope(doc, doc_text)
                    if env is None:
                        # Required field missing — capture for fail-loud
                        # exit at end of pass. Silently skipping at build
                        # time becomes an unexplained "errored" line at
                        # operator startup. (Gate 3 QE-S3.)
                        meta = (doc.get("metadata") or {})
                        spec = (doc.get("spec") or {})
                        exec_ = (spec.get("execution") or {})
                        bad_defs.append((
                            str(yf),
                            f"missing required field(s): "
                            f"id={meta.get('id')!r} "
                            f"plugin={(exec_.get('plugin') or spec.get('plugin'))!r} "
                            f"action={(exec_.get('action') or spec.get('action'))!r}",
                        ))
                        continue
                    if env["id"] not in seen_def_ids:
                        seen_def_ids.add(env["id"])
                        defs_json.append(json.dumps(env))
                elif kind == "InstructionSet":
                    env = set_envelope(doc)
                    if env and env["id"] not in seen_set_ids:
                        seen_set_ids.add(env["id"])
                        sets_json.append(json.dumps(env))
                # ProductPack and other kinds: skipped here. The pack's
                # member docs are imported via their own kind dispatch.

        if bad_defs:
            print(
                f"ERROR: embed_content.py: {len(bad_defs)} "
                f"InstructionDefinition doc(s) missing required fields:",
                file=sys.stderr,
            )
            for path, reason in bad_defs:
                print(f"  {path}: {reason}", file=sys.stderr)
            return 1

    # Emit C++. Each JSON string becomes a raw string literal in a
    # std::vector<std::string>. Picking ")BCT(" as the raw-string
    # delimiter — chosen for impossibility in any sane content YAML.
    DELIM = "BCT"
    out = bytearray()
    out += f"// AUTO-GENERATED from {root.name}/ by embed_content.py — do not edit.\n".encode("utf-8")
    out += f"// Definitions: {len(defs_json)}, Sets: {len(sets_json)}.\n\n".encode("ascii")
    out += b"#include <string>\n#include <vector>\n\n"
    out += b"namespace yuzu::server {\n\n"

    out += b"extern const std::vector<std::string> kBundledDefinitions = {\n"
    for j in defs_json:
        # Sanity check: rule out delimiter collision in the JSON.
        if f"){DELIM}\"" in j:
            print(f"ERROR: JSON envelope contains raw-string delimiter {DELIM}",
                  file=sys.stderr)
            return 1
        out += b'    R"' + DELIM.encode() + b"(" + j.encode("utf-8") + b")" + DELIM.encode() + b'",\n'
    out += b"};\n\n"

    out += b"extern const std::vector<std::string> kBundledSets = {\n"
    for j in sets_json:
        if f"){DELIM}\"" in j:
            print(f"ERROR: JSON envelope contains raw-string delimiter {DELIM}",
                  file=sys.stderr)
            return 1
        out += b'    R"' + DELIM.encode() + b"(" + j.encode("utf-8") + b")" + DELIM.encode() + b'",\n'
    out += b"};\n\n"

    out += b"}  // namespace yuzu::server\n"

    out_path.write_bytes(bytes(out))
    print(f"embed_content.py: wrote {out_path} "
          f"({len(defs_json)} definitions, {len(sets_json)} sets)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
