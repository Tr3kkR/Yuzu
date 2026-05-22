# Issue Tracker

Issues and PRDs for this repo live in GitHub Issues at `github.com/Tr3kkR/Yuzu`.

Use GitHub tooling from inside the clone so the repository is inferred from `origin`.

## Common Operations

- Create: `gh issue create --repo Tr3kkR/Yuzu --title "..." --body "..."`
- Read: `gh issue view <number> --repo Tr3kkR/Yuzu --comments`
- List: `gh issue list --repo Tr3kkR/Yuzu --state open --json number,title,body,labels,comments`
- Comment: `gh issue comment <number> --repo Tr3kkR/Yuzu --body "..."`
- Label: `gh issue edit <number> --repo Tr3kkR/Yuzu --add-label "..."`
- Close: `gh issue close <number> --repo Tr3kkR/Yuzu --comment "..."`

When a skill says "publish to the issue tracker", create a GitHub issue in `Tr3kkR/Yuzu`.

When a skill says "fetch the relevant ticket", read the GitHub issue with comments and labels.
