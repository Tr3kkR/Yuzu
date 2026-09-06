#!/usr/bin/env python3
"""Plugin README gate (docs/plugin-readme-standard.md) — meson `docs` suite.

Hermetic: parses the checked-in tree, builds nothing. Enforces:

1. README-existence ratchet — the number of agents/plugins/<x>/ directories
   WITHOUT a README.md may equal or fall below RATCHET_BASELINE_MISSING, never
   rise. Lower the baseline in the same PR that adds READMEs (PR D.2 takes it
   to 0); raising it means a plugin directory landed undocumented, which is
   exactly the regression this gate exists to block.
2. For every README present: the eight headings in order, the Data-contract
   subsections in order, hand-written sections non-empty, all six generated
   fences present.
3. Generated artefacts byte-match the sources (README fences, the catalog
   index, the site nav fragment, the content/plugin-docs manifests) — the same
   contract scripts/ci/check-capability-matrix.sh enforces for the capability
   matrix, delegated to plugin_doc_gen.check_repo.
4. Samples: every OS whose legs include a supported or constrained action has
   a parseable docs/samples/<os>.txt whose leg-hash is current or `pending`.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools" / "plugin-doc-gen"))

import plugin_doc_gen as g  # noqa: E402

# Every plugin directory minus the pilots (disk_actions, firewall). DECREASE
# this as READMEs land; it cannot be increased without a reviewed decision.
RATCHET_BASELINE_MISSING = 49

TITLE_ORDER = list(g.HEADINGS)
DATA_CONTRACT_ORDER = ["### Inputs", "### Outputs", "### Result status", "### Where the data goes"]


def _heading_lines(text: str) -> list[str]:
    out, in_fence = [], False
    for line in text.splitlines():
        if line.startswith("```"):
            in_fence = not in_fence
        elif not in_fence and (line.startswith("## ") or line.startswith("### ")):
            out.append(line.strip())
    return out


def _ordered_subsequence(haystack: list[str], needles: list[str]) -> bool:
    it = iter(haystack)
    return all(any(h == n for h in it) for n in needles)


class Ratchet(unittest.TestCase):
    def test_missing_readme_count_never_grows(self):
        names = g.plugin_dirs(REPO_ROOT)
        missing = [n for n in names if not (REPO_ROOT / "agents" / "plugins" / n / "README.md").exists()]
        self.assertLessEqual(
            len(missing), RATCHET_BASELINE_MISSING,
            f"{len(missing)} plugin directories have no README.md (baseline "
            f"{RATCHET_BASELINE_MISSING}): {sorted(missing)}. A new plugin ships with "
            "agents/plugins/<name>/README.md per docs/plugin-readme-standard.md.")
        if len(missing) < RATCHET_BASELINE_MISSING:
            self.fail(
                f"only {len(missing)} plugin directories lack a README — lower "
                f"RATCHET_BASELINE_MISSING in tests/test_plugin_readmes.py to {len(missing)} "
                "in this PR so the gate keeps ratcheting down.")


class ReadmeShape(unittest.TestCase):
    def test_every_readme_follows_the_section_contract(self):
        problems = []
        for name in g.documented_plugins(REPO_ROOT):
            path = REPO_ROOT / "agents" / "plugins" / name / "README.md"
            text = path.read_text(encoding="utf-8")
            rel = path.relative_to(REPO_ROOT).as_posix()
            first = next((l for l in text.splitlines() if l.strip()), "")
            if first.strip() != f"# {name}":
                problems.append(f"{rel}: first line must be '# {name}', got {first!r}")
            heads = _heading_lines(text)
            if not _ordered_subsequence(heads, TITLE_ORDER):
                problems.append(f"{rel}: the eight sections must appear in order {TITLE_ORDER}; found {heads}")
            if not _ordered_subsequence(heads, DATA_CONTRACT_ORDER):
                problems.append(f"{rel}: Data contract subsections must appear in order {DATA_CONTRACT_ORDER}")
            sections = g.split_sections(text)
            for hand in g.HAND_SECTIONS:
                body = g.strip_generated(sections.get(hand, ""))
                if not body.strip():
                    problems.append(f"{rel}: hand-written section '{hand}' is empty")
            for block in g.README_BLOCKS:
                if f"<!-- BEGIN GENERATED: plugin-doc-gen {block} -->" not in text:
                    problems.append(f"{rel}: missing fence 'plugin-doc-gen {block}'")
        self.assertFalse(problems, "\n".join(problems))


class GeneratedArtefacts(unittest.TestCase):
    def test_fences_index_nav_and_manifests_are_current(self):
        errors, warnings = g.check_repo(REPO_ROOT)
        for w in warnings:
            print(f"warning: {w}", file=sys.stderr)
        self.assertFalse(errors, "\n\n".join(errors))


class Samples(unittest.TestCase):
    def test_every_supported_leg_has_a_capture(self):
        matrix = g.parse_matrix_block((REPO_ROOT / "docs" / "os-capability-matrix.md").read_text(encoding="utf-8"))
        problems = []
        for name in g.documented_plugins(REPO_ROOT):
            legs = matrix.get(name, {})
            for os_name in g.OS_ORDER:
                if g.best_support(legs, os_name) not in ("supported", "constrained"):
                    continue
                sp = REPO_ROOT / "agents" / "plugins" / name / "docs" / "samples" / f"{os_name}.txt"
                if not sp.exists():
                    problems.append(f"{name}: {os_name} leg is {g.best_support(legs, os_name)} but "
                                    f"docs/samples/{os_name}.txt is missing (rule 5)")
                    continue
                try:
                    s = g.parse_sample(sp.read_text(encoding="utf-8"), os_name)
                except ValueError as e:
                    problems.append(f"{name}: {e}")
                    continue
                declared = set(legs)
                captured = {a["action"] for a in s.actions}
                if not captured & declared:
                    problems.append(f"{name}/{os_name}: sample captures none of the declared actions {sorted(declared)}")
        self.assertFalse(problems, "\n".join(problems))


if __name__ == "__main__":
    unittest.main()
