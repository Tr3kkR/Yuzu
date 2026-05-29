#!/usr/bin/env python3
"""
check-hookify-rules.py -- validate Yuzu's hookify guardrail rules (fails LOUDLY).

Hookify rule files live at .claude/hookify.*.local.md and encode project
invariants (see CLAUDE.md). They are force-tracked via a .gitignore negation so
they reach the whole team. The failure mode they guard against is *silent*: a
broken rule looks installed but never fires. This check turns every such silent
failure into a loud, blocking error.

Checks, per rule file:
  1. ASCII-only. hookify's config_loader opens rule files with open(path, 'r')
     and NO encoding=, so on a Windows (cp1252) host any non-ASCII char raises a
     decode error that the loader catches and SILENTLY SKIPS the rule. ASCII is
     the only portable guarantee. (memory: reference_hookify_ascii_only)
  2. YAML frontmatter present and parseable.
  3. Required fields: name, enabled, event.
  4. Valid event / action enum values.
  5. Every regex pattern (simple `pattern` + regex_match conditions) compiles.

Exit 0 = all rules OK. Exit 1 = at least one rule is broken. Exit 2 = env problem.

Usage:  python3 scripts/check-hookify-rules.py
"""
import glob
import os
import re
import sys

VALID_EVENTS = {"bash", "file", "stop", "prompt", "all"}
VALID_ACTIONS = {"warn", "block"}


def fail(path, msg):
    print(f"  FAIL  {os.path.basename(path)}: {msg}")


def main():
    # Pin to repo root so the glob works regardless of caller cwd.
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(root)

    files = sorted(glob.glob(os.path.join(".claude", "hookify.*.local.md")))
    if not files:
        print("check-hookify-rules: no .claude/hookify.*.local.md files (nothing to check)")
        return 0

    try:
        import yaml
    except ImportError:
        print("check-hookify-rules: PyYAML missing "
              "(pip install pyyaml / pacman -S python-yaml)", file=sys.stderr)
        return 2

    errors = 0
    for path in files:
        # 1. ASCII-only -- the cp1252 silent-skip guard. Read as ASCII; the first
        #    non-ASCII byte is exactly what the loader chokes on at runtime.
        try:
            with open(path, "r", encoding="ascii") as f:
                text = f.read()
        except UnicodeDecodeError as e:
            byte = e.object[e.start]
            fail(path, f"non-ASCII byte 0x{byte:02x} at offset {e.start} -- "
                       f"hookify's loader silently skips this rule on Windows/cp1252. "
                       f"Use ASCII only ([WARN]/[BLOCK], '--', '->').")
            errors += 1
            continue

        # 2. Frontmatter present + parses.
        parts = text.split("---")
        if len(parts) < 3:
            fail(path, "no YAML frontmatter block delimited by ---")
            errors += 1
            continue
        try:
            meta = yaml.safe_load(parts[1])
        except yaml.YAMLError as e:
            fail(path, f"frontmatter is not valid YAML: {e}")
            errors += 1
            continue
        if not isinstance(meta, dict):
            fail(path, "frontmatter did not parse to a mapping")
            errors += 1
            continue

        # 3. Required fields.
        for field in ("name", "enabled", "event"):
            if field not in meta:
                fail(path, f"missing required field '{field}'")
                errors += 1

        # 4. Enum values.
        ev = meta.get("event")
        if ev is not None and ev not in VALID_EVENTS:
            fail(path, f"event '{ev}' not in {sorted(VALID_EVENTS)}")
            errors += 1
        act = meta.get("action")
        if act is not None and act not in VALID_ACTIONS:
            fail(path, f"action '{act}' not in {sorted(VALID_ACTIONS)}")
            errors += 1

        # 5. Regex patterns compile.
        patterns = []
        if meta.get("pattern"):
            patterns.append(meta["pattern"])
        for cond in meta.get("conditions", []) or []:
            if cond.get("operator") == "regex_match" and cond.get("pattern"):
                patterns.append(cond["pattern"])
        for pat in patterns:
            try:
                re.compile(pat)
            except re.error as e:
                fail(path, f"pattern does not compile: {pat!r} ({e})")
                errors += 1

    if errors:
        print(f"\ncheck-hookify-rules: {errors} error(s) across {len(files)} rule file(s)")
        return 1
    print(f"check-hookify-rules: {len(files)} hookify rule file(s) OK "
          f"(ASCII, valid frontmatter, regex compiles)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
