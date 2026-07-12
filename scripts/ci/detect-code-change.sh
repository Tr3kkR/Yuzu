#!/usr/bin/env bash
# detect-code-change.sh — classify a PR's changed-file list as code vs docs-only
# for the ci.yml docs-only gate (issue #1978).
#
# Reads changed file paths from stdin (one per line) and prints exactly "true"
# or "false" (the code_changed value) to stdout. Nothing else goes to stdout;
# all diagnostics go to stderr.
#
#   arg $1  authoritative total changed-file count (GitHub's
#           pull_request.changed_files). Guards the "List pull requests files"
#           REST endpoint's 3000-file cap: if the piped list is shorter than
#           this count the list was truncated, and we FAIL CLOSED to "true"
#           (build) rather than trust a partial view that might hide a code
#           file past the cap.
#
# The docs-only ignore set mirrors the pull_request `paths-ignore` ci.yml used
# to carry, with GitHub's root-anchored filter semantics — a bare `*.md`,
# `LICENSE`, or `.gitignore` pattern matches ONLY the repository root, never a
# nested path:
#   - docs/**                        (any depth under docs/)
#   - root-level *.md                (README.md, but NOT sdk/README.md)
#   - LICENSE, .gitignore            (root only)
#   - .github/runner-inventory.json
#   - .github/workflows/runner-inventory-sentinel.yml
# Anything else -> code_changed=true. Fail-closed throughout: any uncertainty
# (empty list, truncated list) builds rather than silently skipping the matrix.
#
# KEEP IN SYNC: this ignore set must match the `push:` trigger's paths-ignore
# in .github/workflows/ci.yml — editing one without the other diverges PR-time
# and post-merge build behaviour.
#
# Run tests:  bash tests/shell/test_detect_code_change.sh
set -euo pipefail

expected_total="${1:-}"

mapfile -t files || true
count=${#files[@]}

emit() { printf '%s\n' "$1"; exit 0; }

# Fail-closed: nothing to classify.
if (( count == 0 )); then
  echo "detect-code-change: empty file list -> building (fail-closed)" >&2
  emit true
fi

# Fail-closed: the files API is capped at 3000 entries. If the caller passed
# the authoritative changed-file count and it does not match what we received,
# the list is truncated (or otherwise inconsistent) and a code file may sit
# beyond the cap — build rather than trust the partial list.
if [[ "$expected_total" =~ ^[0-9]+$ ]] && (( count != expected_total )); then
  echo "detect-code-change: received $count of $expected_total files (truncated/mismatch) -> building (fail-closed)" >&2
  emit true
fi

for f in "${files[@]}"; do
  [[ -z "$f" ]] && continue
  case "$f" in
    docs/*) ;;                                        # docs/** (any depth)
    LICENSE|.gitignore) ;;                             # root-only exact match
    .github/runner-inventory.json) ;;
    .github/workflows/runner-inventory-sentinel.yml) ;;
    *.md)
      # GitHub's `*.md` filter is root-only; a nested .md is NOT ignored.
      if [[ "$f" == */* ]]; then
        echo "detect-code-change: nested markdown is code-side per old paths-ignore -> building: $f" >&2
        emit true
      fi
      ;;
    *)
      echo "detect-code-change: non-docs path -> building: $f" >&2
      emit true
      ;;
  esac
done

emit false
