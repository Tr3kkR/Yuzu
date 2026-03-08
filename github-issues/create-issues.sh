#!/usr/bin/env bash
# create-issues.sh — Batch-create GitHub issues from markdown files
#
# Prerequisites:
#   - gh CLI authenticated: `gh auth login`
#   - Run from the repository root
#
# Usage:
#   ./github-issues/create-issues.sh
#   ./github-issues/create-issues.sh --dry-run    # Preview without creating
#   ./github-issues/create-issues.sh --repo owner/repo  # Specify repo explicitly

set -euo pipefail

DRY_RUN=false
REPO_FLAG=""
CREATED=0
FAILED=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=true; shift ;;
        --repo) REPO_FLAG="--repo $2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

for issue_file in "$SCRIPT_DIR"/[0-9]*.md; do
    [ -f "$issue_file" ] || continue

    filename="$(basename "$issue_file")"

    # Extract YAML front matter
    title=$(sed -n 's/^title: "\(.*\)"/\1/p' "$issue_file" | head -1)
    labels=$(sed -n 's/^labels: \(.*\)/\1/p' "$issue_file" | head -1)

    if [ -z "$title" ]; then
        echo "SKIP: $filename (no title found)"
        continue
    fi

    # Extract body (everything after the closing ---)
    body=$(awk 'BEGIN{found=0; count=0} /^---$/{count++; if(count==2){found=1; next}} found{print}' "$issue_file")

    # Build label flags
    label_flags=""
    if [ -n "$labels" ]; then
        IFS=',' read -ra LABEL_ARRAY <<< "$labels"
        for label in "${LABEL_ARRAY[@]}"; do
            label=$(echo "$label" | xargs)  # trim whitespace
            label_flags="$label_flags --label \"$label\""
        done
    fi

    if $DRY_RUN; then
        echo "DRY RUN: Would create issue:"
        echo "  Title:  $title"
        echo "  Labels: $labels"
        echo "  File:   $filename"
        echo ""
    else
        echo "Creating: $title"

        # Create labels if they don't exist (ignore errors for existing labels)
        if [ -n "$labels" ]; then
            IFS=',' read -ra LABEL_ARRAY <<< "$labels"
            for label in "${LABEL_ARRAY[@]}"; do
                label=$(echo "$label" | xargs)
                gh label create "$label" $REPO_FLAG 2>/dev/null || true
            done
        fi

        # Create the issue
        if gh issue create \
            --title "$title" \
            --body "$body" \
            $(echo $label_flags) \
            $REPO_FLAG; then
            CREATED=$((CREATED + 1))
            echo "  OK"
        else
            FAILED=$((FAILED + 1))
            echo "  FAILED"
        fi

        # Rate limit: GitHub API allows 30 requests/min for issue creation
        sleep 2
    fi
done

if ! $DRY_RUN; then
    echo ""
    echo "Done: $CREATED created, $FAILED failed"
fi
