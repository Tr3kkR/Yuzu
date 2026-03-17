# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| main    | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in Yuzu, please report it responsibly:

1. **Do not** open a public GitHub issue for security vulnerabilities
2. Use [GitHub's private vulnerability reporting](https://github.com/Tr3kkR/Yuzu/security/advisories/new) to submit a report
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Affected components (agent, server, SDK, plugins)
   - Potential impact
   - Suggested fix (if any)

## Response

- We aim to acknowledge reports within 48 hours
- We will work with reporters to understand and validate the issue
- Fixes will be prioritised based on severity

## Security Hardening Tracking

Security hardening work is tracked in the roadmap issue index (`docs/roadmap.md`), including:
- **#146** HTTPS for Web Dashboard
- **#154** Granular RBAC System
- **#157** Token-Based API Authentication

For implementation status details and code-level findings, see `SECURITY_REVIEW.md`.
