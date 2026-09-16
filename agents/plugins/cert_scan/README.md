# cert_scan

<!-- BEGIN GENERATED: plugin-doc-gen header -->
| | |
|---|---|
| **What it does** | SSL/TLS certificate and private-key discovery -- walks every local user's home directory for certificate material, CSRs, and private keys that escaped managed custody. Never emits raw key material, only structural metadata. |
| **Version** | 1.0.0 |
| **Kind** | Collector · read-only · gathered (security.cert_scan.scan) |
| **Platforms** | Windows ✅ · macOS ✅ · Linux ✅ |
| **Actions** | `scan` (definition `security.cert_scan.scan`) |
| **Security** | securable `Security` · operation Read · risk Medium · dispatch ReadOnly · approval gate None |
| **Roles** | execute: compliance-officer, endpoint-admin, endpoint-operator, security-admin · author: content-author |
<!-- END GENERATED -->

## How it works

`scan` walks either an operator-supplied `paths` list or, by default, every local user's home directory on the host — auto-discovered per-OS (Windows: every `HKLM\...\ProfileList` profile via `win_profiles.hpp`, filtering system SIDs; macOS: every `/Users/*` entry except `Shared`/`Guest`; Linux: every `/home/*` entry plus `/root`). The walk is a depth-capped `std::filesystem::recursive_directory_iterator` that never follows symlinks (the iterator's own default behaviour, not a manual check added on top). A file is a scan candidate if its extension is in a fixed allowlist (`.pem .crt .cer .key .p12 .pfx .jks .keystore .csr`) OR its immediate parent directory is named `.ssh` — the second arm exists because the single most common private-key shape on disk, OpenSSH's default `~/.ssh/id_rsa`/`id_ed25519`, carries no extension at all.

Content classification (`cert_scan_rules.hpp`) is marker-text driven for PEM content: private-key headers (PKCS#8, traditional RSA/EC/DSA, OpenSSH), certificate blocks (parsed via `certificates_x509.hpp`, reused directly from the `certificates` plugin), and CSR headers are each detected independently, so one file can yield more than one finding (e.g. a combined cert+key bundle). Encryption status comes from marker text alone for PKCS#8/traditional formats (`ENCRYPTED PRIVATE KEY` vs `PRIVATE KEY`; a `Proc-Type: 4,ENCRYPTED` header for the traditional formats) and from decoding the OpenSSH key's own binary `ciphername` field for OpenSSH keys (`ciphername == "none"` means unencrypted). Non-PEM (binary) candidates are classified by signature: JKS keystores by their `0xFEEDFEED` magic, `.der`/`.cer` content by attempting an actual X.509 parse (`certificates_x509::parse_der_cert` — succeeds only for a genuine single certificate), and `.p12`/`.pfx` content by a DER-SEQUENCE-byte + extension combination (a real, disclosed weak signal — the PKCS#12 ASN.1 structure is not deep-parsed in this version).

Severity: **CRITICAL** an unencrypted private key; **HIGH** an encrypted private key, or a PKCS#12/JKS container; **MEDIUM** an expired or self-signed certificate; **LOW** a valid certificate; **INFO** a certificate signing request. Certificates never have their key material anywhere near this plugin — `certificates_x509.hpp` only ever extracts subject/issuer/validity/serial/thumbprint fields. A private-key or container finding never includes so much as its first byte, only a classification label.

```mermaid
flowchart LR
  OP[Operator / MCP cert_scan.scan] --> SRV[Server<br/>authz: Security.Read]
  SRV -- gRPC mTLS --> HOST[Agent plugin host] --> EX[cert_scan.execute]
  EX --> DISC[discover_home_directories<br/>per-OS, or operator paths]
  DISC --> WALK[recursive_directory_iterator<br/>depth-capped, no symlink-follow]
  WALK --> CAND{is_candidate_file<br/>extension allowlist OR .ssh}
  CAND -->|PEM marker text| CLASSIFY[classify_content<br/>keys / certs / CSR]
  CAND -->|binary| BINCLASSIFY[classify_binary_content<br/>JKS magic / DER parse / PKCS12 signature]
  CLASSIFY --> ROWS[severity\|kind\|filePath\|subject\|issuer\|notBefore\|notAfter\|serial\|thumbprint]
  BINCLASSIFY --> ROWS
  ROWS --> RS[(ResponseStore)]
  RS --> API[REST /api/responses · MCP]
```

## OS capability

<!-- BEGIN GENERATED: plugin-doc-gen capability -->
| Action | Windows | macOS | Linux |
|---|---|---|---|
| `scan` | ✅ supported · rung 1 · ProfileList registry read (win_profiles.hpp) for home-directory discovery, then std::filesystem walk; in-process libcrypto PEM/DER parse (certificates_x509.hpp) | ✅ supported · rung 1 · std::filesystem walk of /Users/* (excluding Shared/Guest); in-process libcrypto PEM/DER parse (certificates_x509.hpp) | ✅ supported · rung 1 · std::filesystem walk of /home/* + /root; in-process libcrypto PEM/DER parse (certificates_x509.hpp) |

**Declared limits per leg** (descriptor fallback text, verbatim):

- **`scan` / Windows** — Per-user filesystem read access beyond the registry discovery hop is unmeasured on this build host -- a permission-denied degrades honestly (silent skip, enumerate_files' skip_permission_denied option), but the common-case outcome is not yet confirmed. See the plugin README's Caveats.
<!-- END GENERATED -->

## Privileges and prerequisites

| OS | Runs as | Extra grant needed | Measured | If the read is refused |
|---|---|---|---|---|
| Windows | Agent service account. Home-directory discovery reads `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList` (already-established read, shared with `users`/`installed_apps`/`license_scan`); the subsequent per-user FILESYSTEM read (as opposed to registry-hive access, which those other plugins use) of another local user's home directory is genuinely new territory for this codebase — no existing plugin precedent measures whether the agent service account's ACLs permit reading another standard user's `%USERPROFILE%` tree by default. | None requested by this plugin. | **Not yet measured on this host** — see Caveats. | A per-file/per-directory access-denied is skipped silently (`enumerate_files`'s `skip_permission_denied` directory option, plus per-entry error-code checks); the walk continues over the rest of the tree and over other users' homes. |
| macOS | Agent daemon (root LaunchDaemon, `docs/agent-privilege-model.md`). Reading another user's home directory unprivileged-but-as-root is the same access shape `autoruns`'s `collect_user_launchagents` already exercises for `/Users/*`. | None. | Not yet captured on this host — see Caveats. | Same silent-skip behaviour as Windows. |
| Linux | Agent daemon. Same `/home/*` enumeration shape `autoruns`'s Linux collector already exercises; reading a `0700`-permission home directory the agent account doesn't own degrades honestly to finding nothing there, per `docs/agent-privilege-model.md`'s existing precedent for `installed_apps`/`license_scan`. | None. | Not yet captured on this host — see Caveats. | Same silent-skip behaviour as Windows. |

Binaries: none — file access is entirely `std::filesystem`/`std::ifstream`, no subprocess is ever spawned. Network: none beyond the agent's existing gRPC channel to report findings.

## Data contract

### Inputs

<!-- BEGIN GENERATED: plugin-doc-gen inputs -->
| Definition | Parameter | Type | Required | Default | Constraints | Description |
|---|---|---|---|---|---|---|
| `security.cert_scan.scan` | `paths` | string | no | - | - | Comma-separated list of directories to scan. Empty/absent (the default) auto-discovers every local user's home directory on this OS: Windows via the ProfileList registry, Linux via /home/* plus /root, macOS via /Users/* (excluding Shared/Guest). |
| `security.cert_scan.scan` | `maxDepth` | string | no | - | - | Integer recursion depth cap for the directory walk (default 12). |
<!-- END GENERATED -->

### Outputs

`scan` writes pipe-delimited rows via `ctx.write_output`: `severity|kind|filePath|subject|issuer|notBefore|notAfter|serial|thumbprint`, one row per finding, plus a final `summary` row giving files-scanned/findings counts. `subject`/`issuer`/`notBefore`/`notAfter`/`serial`/`thumbprint` are populated only for `kind=certificate` — every other kind (`private_key_unencrypted`, `private_key_encrypted`, `pkcs12_container`, `jks_keystore`, `certificate_signing_request`) leaves them at `certificates_x509::CertFields`'s own `"(unknown)"`/`"(none)"` defaults, since those kinds carry no certificate fields at all.

<!-- BEGIN GENERATED: plugin-doc-gen outputs -->
**`security.cert_scan.scan` — `severity|kind|filePath|subject|issuer|notBefore|notAfter|serial|thumbprint`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `severity` | string | - | all | - | - |
| `kind` | string | - | all | - | - |
| `filePath` | string | - | all | - | - |
| `subject` | string | - | all | - | - |
| `issuer` | string | - | all | - | - |
| `notBefore` | string | - | all | - | - |
| `notAfter` | string | - | all | - | - |
| `serial` | string | - | all | - | - |
| `thumbprint` | string | - | all | - | - |
<!-- END GENERATED -->

### Result status

| Status | Completeness | Provenance | When |
|---|---|---|---|
| `INFO` | Complete | `cert_scan:summary` | The final summary row — always emitted, even when zero findings were produced. |

### Where the data goes

- **Instruction result.** Findings land in the `ResponseStore` like any other instruction result, retained per the normal response-retention policy, readable via `GET /api/responses` and MCP.
- **Not consumed by** daily-sync, TAR, DEX, or metrics — this is a one-shot scan action, not a background collector feeding those pipelines. Any cross-scan analytics/trending/mapping (e.g. "which endpoints have accumulated the most Critical findings over time") is downstream work against the typed `result.columns` schema (`docs/data-architecture.md`), not something this plugin computes or persists itself.
- **Sensitivity.** A finding's `filePath` identifies exactly where on a specific device a private key or certificate lives; for a Critical/High finding this is itself sensitive operational-security information (an attacker who compromises an operator session learns where an exploitable key sits), even though the underlying key bytes are never in the row. Certificate fields (`subject`/`issuer`) can reveal internal hostnames/organisation names present in a self-issued cert's DN.
- **Siblings:** the `certificates` plugin reads the OS certificate STORE (Windows cert store / macOS Keychain / Linux `openssl`); this plugin reads certificate/key **files** on disk in user home directories — a different surface with no overlap in what each observes. `pii_scan` established the filesystem-walk convention (`std::filesystem::recursive_directory_iterator`, symlinks never followed) this plugin's collector reuses.

## Sample output

<!-- BEGIN GENERATED: plugin-doc-gen samples -->
**Windows** — captured: windows 11 Pro (10.0.26200) · bare-metal · 2026-09-16 · not measured (capture did not complete) · leg-hash pending

```
== action=scan
[not captured] agent-context: plugin-capture hangs indefinitely on this development host during yuzu_agent_core.dll static initialization (before any plugin code runs) — reproduced previously against an unrelated, already-shipped plugin (chargen) with the same tool, confirming this is an environment-level issue with plugin-capture/agent-core startup on this host, not a cert_scan defect. The action itself was verified end-to-end via unit tests (tests/unit/test_cert_scan_rules.cpp, tests/unit/test_cert_scan_collect.cpp) and a real MSVC build/link/run on Windows.
```

**macOS** — captured: macos not built · bare-metal · 2026-09-16 · not measured (capture did not complete) · leg-hash pending

```
== action=scan
[not captured] agent-context: this plugin was developed and built on Windows only in this environment — no macOS build exists to capture against. See docs/samples/windows.txt for why even the Windows leg's capture did not complete.
```

**Linux** — captured: linux not built · container · 2026-09-16 · not measured (capture did not complete) · leg-hash pending

```
== action=scan
[not captured] agent-context: this plugin was developed and built on Windows only in this environment — no Linux build exists to capture against. See docs/samples/windows.txt for why even the Windows leg's capture did not complete.
```
<!-- END GENERATED -->

## Caveats and known gaps

1. **PKCS#12/JKS containers are not deep-parsed.** A `.p12`/`.pfx`/`.jks`/`.keystore` finding is a signature/extension match only (DER-SEQUENCE byte + extension, or the JKS magic bytes) — the plugin does not open the container (which would need a passphrase for PKCS#12, or Java's own JKS format logic) to confirm it genuinely holds a key, or to extract its own certificate metadata. A same-extensioned non-PKCS12 DER file would still be flagged for `.p12`/`.pfx`.
2. **Self-signed detection is a string compare, not a signature check.** `is_self_signed` compares the rendered subject and issuer DN strings; it does not call `X509_check_issued()` (which would need the issuer's own certificate, not available to a discovery scan that sees one certificate at a time). A certificate whose issuer DN happens to equal its subject DN but was not actually self-signed would be misclassified — a disclosed, narrow edge case.
3. **PEM parsing has two disclosed multi-block edge cases.** `certificates_x509::parse_pem_certs` (reused unmodified from the `certificates` plugin) reads whichever PEM block comes first in the file and stops immediately if it isn't a `CERTIFICATE` block — a key-before-certificate bundle therefore reports the key but misses the certificate (the conventional ordering, certificate(s) first then key, is unaffected). Separately, a file concatenating two same-format traditional keys (e.g. two `-----BEGIN RSA PRIVATE KEY-----` blocks) with different encryption states reports only the first block's encryption status. Both are rare shapes in practice; see `cert_scan_rules.hpp`'s `classify_content()` doc comment.
4. **Windows per-user filesystem ACL behaviour is unmeasured.** Every existing Yuzu plugin that reads "every local user's data" on Windows does so via the registry (`ProfileList`/`HKEY_USERS` hive access); this plugin is the first to read another local user's home directory as a **filesystem** tree. Whether the agent service account can read a standard user's `%USERPROFILE%` files by default (vs. needing SeBackupPrivilege the way the existing offline-hive-mount ladder does) has not been measured on a real multi-user Windows host in this environment — a permission-denied degrades honestly (silent skip, see Privileges above) either way, but the *common case* outcome is not yet confirmed.
5. **Sample captures pending.** This README ships without real per-OS `plugin-capture` output (see Sample output above) — the plugin has been verified via its own unit test suite (`tests/unit/test_cert_scan_rules.cpp`, `tests/unit/test_cert_scan_collect.cpp`) and a real MSVC build/link/run on Windows, but a `plugin-capture` run on all three OSes is a follow-up.

## Source and tests

<!-- BEGIN GENERATED: plugin-doc-gen source -->
- Plugin: `agents/plugins/cert_scan/src/cert_scan_collect.hpp` · `agents/plugins/cert_scan/src/cert_scan_plugin.cpp` · `agents/plugins/cert_scan/src/cert_scan_rules.hpp`
- Definitions: `content/definitions/cert_scan.yaml`
- Capability rows: `server/core/src/capability_decls/plugin_action_catalogue_cert_scan.hpp`
- Tests: `tests/unit/test_cert_scan_collect.cpp` · `tests/unit/test_cert_scan_rules.cpp`
- Privilege row: `docs/agent-privilege-model.md` (no row yet)
<!-- END GENERATED -->
