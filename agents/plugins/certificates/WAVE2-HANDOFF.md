# WP-B handoff — certificates plugin (Wave 2)

Owner of this handoff: WP-B engineer. Scope: `agents/plugins/certificates/**`
and `tests/unit/test_certificates_x509.cpp` only (this package's
`owned_files`). Everything below is delivered as listed content for the
Architect/integrator to apply to files this package does not own
(`tests/meson.build`, `docs/agent-spawn-sink-manifest.md`,
`server/core/src/capability_decls/**`), per this package's `boundaries`.

## 1. What changed

`agents/plugins/certificates/src/certificates_plugin.cpp` reaches **zero raw
spawn sites** (no `popen`/`_popen`/`system`/`fork`/`vfork`/`posix_spawn`/
`CreateProcess` anywhere in the file):

- **Linux** `list`/`details`/`delete`: promoted to rung 1. The `openssl x509`
  subprocess (`run_command`, `is_safe_path`, `parse_openssl_output`) is
  deleted outright; every field is parsed in-process by the new
  `certificates_x509.hpp` (`parse_pem_certs`, libcrypto only) fed by a plain
  `std::ifstream` read. `first_cert_of_file()` pins cardinality parity with
  the replaced `openssl x509 -in <file>` (first-PEM-block-only) for both the
  list/details read path and the delete match path — see its own comment and
  the two parity tests in `test_certificates_x509.cpp`.
- **macOS** `list`/`details`: `System.keychain` and
  `SystemRootCertificates.keychain` are promoted to rung 1 —
  `read_keychain_secitem()` reads them natively via `SecKeychainOpen` +
  `SecItemCopyMatching`, decoding each result's DER through
  `certificates_x509.hpp`'s new `parse_der_cert()`. The **login keychain is
  untouched**: `build_login_keychain_read_command()` and its `/bin/sh -c`
  runner call are byte-identical to the base revision (see §3). Because
  list/details still read the login keychain by default, both actions stay
  rung 3 overall — the rung reflects the deepest interpreter either call path
  intentionally invokes, not the shallowest one now available.
- **macOS** `delete`: unchanged (rung 2, `/usr/bin/security
  delete-certificate` via the bounded subprocess runner); still rejects
  `SystemRootCertificates.keychain` outright (sealed under SIP).
- **Windows**: unchanged (CryptoAPI, rung 1).
- `run_command()` and `is_safe_path()` are deleted; confirmed unreferenced
  (their only callers were the eight `openssl` sites now gone, and the one
  `parse_openssl_output` caller now gone).

## 2. New pure header: `certificates_x509.hpp`

`namespace yuzu::certificates_x509`, libcrypto only, no filesystem, no
subprocess. `parse_pem_certs(std::string_view)` returns every certificate a
PEM stream contains (in file order); `parse_der_cert(std::span<const
unsigned char>)` decodes one DER certificate (the macOS SecItem path).
Every OpenSSL object is RAII-owned (`BioPtr`/`X509Ptr`); garbage input
yields an empty vector / `std::nullopt`, never a throw.

Field-extraction recipes are pinned against the empirically-verified host
OpenSSL 3.6.2 (`/opt/homebrew/opt/openssl@3/bin/openssl`) exactly as the
spec directed — `X509_NAME_print_ex` with
`XN_FLAG_SEP_CPLUS_SPC|ASN1_STRFLGS_UTF8_CONVERT` for subject/issuer,
`i2a_ASN1_INTEGER` for serial, `X509_digest`+`EVP_sha1` for the thumbprint,
`ASN1_TIME_to_tm` for dates, `X509V3_EXT_print` plus the old
last-non-header-line selection for key usage. Every recipe's own doc comment
in the header cites the specific alternative API it deliberately rejects
(`XN_FLAG_ONELINE`/`XN_FLAG_RFC2253`/`X509_NAME_oneline`,
`ASN1_INTEGER_to_BN`+`BN_bn2hex`) and why.

## 3. Decision-7 login-keychain exception (unchanged, by design)

`build_login_keychain_read_command()` (in `certificates_macos_parsers.hpp`,
not owned by this package — untouched) and its two runner call sites in
`certificates_plugin.cpp` are byte-for-byte identical to the base revision
except for a one-line `// sink:` comment added directly above each call
(nothing else on those lines changed — confirm via `git diff` on the exact
call-construction lines). Rationale: the login-keychain read needs the outer
shell's `~username` expansion for the per-console-user `security
find-certificate` invocation, and `cert_store.cpp`'s macOS post-mortem
(`agents/core/src/cert_store.cpp`, the `__APPLE__` block) is the standing
reason this hop is not attempted as a clean argv call. See ADR-3002's
Decision-7 for the general exception shape.

## 4. Spawn-sink manifest rows (for `docs/agent-spawn-sink-manifest.md`)

This package does not own that file — these are the rows for the
Architect/integrator to add to its "Registered sites" table. All seven
surviving subprocess call sites in `certificates_plugin.cpp` are listed:
the two Decision-7 `/bin/sh -c` sites (already carrying `// sink:` comments
in the diff, §3 above) and the five plain-argv rung-2 sites that WP-B leaves
untouched (macOS-only; none of these were in this package's scope to
migrate — `boundaries` explicitly excludes the surviving macOS runner path's
result-status forwarding from this run).

| Site ID | Location | Mechanism | Platform | Provenance | Mutating | Shell features | Privilege | Ladder review | Rung + evidence | Registration |
|---|---|---|---|---|---|---|---|---|---|---|
| `certificates/list_certs_macos#1` | `certificates_plugin.cpp:list_certs_macos` | runner argv, single element = trusted shell script string | macOS | `cmd` built by `build_login_keychain_read_command()` from an already-allowlist-validated uid/username (local-system, not operator input) | read-only | `~user` home-directory expansion (the one feature `/bin/sh -c` is retained for) | none beyond the LaunchDaemon's existing root context (ships with no `UserName` key — runs as root today; no sudoers grant needed) | Reviewed — no rung-1/2 API reaches a per-console-user login keychain without a session hop; `security find-certificate` under `launchctl asuser`/`sudo -u` needs the shell for `~user` expansion | Rung 3 — Decision-7 governed-shell exception (ADR-3002); Decision-1 evidence: `cert_store.cpp`'s macOS post-mortem documents a prior clean-argv attempt failing to reach the per-user keychain session | Decision-7 shell exception |
| `certificates/details_cert_macos#1` | `certificates_plugin.cpp:details_cert_macos` | runner argv, single element = trusted shell script string | macOS | same as above | read-only | same as above | same as above | same as above | same as above | Decision-7 shell exception |
| `certificates/keychain_contains_thumbprint#1` | `certificates_plugin.cpp:keychain_contains_thumbprint` | runner argv (`/usr/bin/security find-certificate -a -p <path>`) | macOS | `keychain_path` is one of two fixed literal paths (`resolve_delete_keychain_path()`); no operator-controlled text reaches this argv | read-only (used for both the pre-delete presence check and the post-delete verify re-enumeration in `delete_cert_macos`) | none | none beyond the LaunchDaemon's existing root context | Reviewed — plain argv, no shell needed; already rung 2 | Rung 2 — clean multi-element argv through the bounded subprocess runner (Decision-5 registered mechanism) | Decision-5 interpreter registration (bounded runner) |
| `certificates/delete_cert_macos#1` | `certificates_plugin.cpp:delete_cert_macos` | runner argv (`/usr/bin/security delete-certificate -Z <thumbprint> <path>`) | macOS | `<thumbprint>` is hex-validated (`is_valid_thumbprint`) + canonicalized operator input; `<path>` is one of two fixed literal paths | **mutating** | none | `$ACCOUNT_NAME ALL=(root) NOPASSWD: /usr/bin/security delete-certificate -t /Library/Keychains/System.keychain *` (`scripts/install-agent-user.sh:467`) — scoped to System.keychain only; root-context LaunchDaemon needs no sudo hop today | Reviewed — plain argv, no shell needed; already rung 2 | Rung 2 — clean multi-element argv through the bounded subprocess runner | Decision-5 interpreter registration (bounded runner) |
| `certificates/parse_pem_block_macos#1` | `certificates_plugin.cpp:parse_pem_block_macos` | runner argv (`/usr/bin/openssl x509 -noout -in <tmpfile> -subject -issuer -startdate -enddate -serial -fingerprint -sha1 -text`) | macOS | `<tmpfile>` is a `yuzu::TempFile`-owned path (mkstemps/O_EXCL, mode 0600) holding one PEM block read from the login keychain — no operator text | read-only | none | none beyond the LaunchDaemon's existing root context | Reviewed — LibreSSL (the host `/usr/bin/openssl`) rejects `-ext keyUsage`, so this parses via `-text` + the shared line-selection helpers instead of certificates_x509.hpp; migrating this specific site to certificates_x509.hpp (feed it the PEM block directly, in-process) is a natural rung-1 follow-up but is OUT of this package's scope (the spec's part 6 froze the login-keychain path byte-identical) | Rung 2 — clean multi-element argv through the bounded subprocess runner | Decision-5 interpreter registration (bounded runner) |
| `certificates/resolve_console_user#1` | `certificates_plugin.cpp:resolve_console_user` | runner argv (`/usr/bin/stat -f%Su /dev/console`) | macOS | none — fixed literal argv | read-only | none | none beyond the LaunchDaemon's existing root context | Reviewed — the LaunchDaemon has no SystemConfiguration framework access (unlike `agents/plugins/users`'s `SCDynamicStoreCopyConsoleUser`), so this is the only console-user resolution mechanism available here | Rung 2 — clean multi-element argv through the bounded subprocess runner | Decision-5 interpreter registration (bounded runner) |
| `certificates/resolve_console_user#2` | `certificates_plugin.cpp:resolve_console_user` | runner argv (`/usr/bin/id -u <username>`) | macOS | `<username>` is the output of site `#1` above, allowlist-validated (`is_valid_username`) before use | read-only | none | none beyond the LaunchDaemon's existing root context | Reviewed — same constraint as `#1` | Rung 2 — clean multi-element argv through the bounded subprocess runner | Decision-5 interpreter registration (bounded runner) |

## 5. macOS SecItem validation note (interactive, not unit-tested)

`read_keychain_secitem()` cannot be exercised by
`test_certificates_x509.cpp` (a fixture-only unit suite — it needs a real
keychain). It was instead validated interactively against this development
host's real `System.keychain` during implementation: the SecItem read
returned the same certificates, by SHA-1 thumbprint, that `security
find-certificate -a -p /Library/Keychains/System.keychain` emits for the
same keychain. No `SystemRootCertificates.keychain` interactive check was
performed (sealed/read-only under SIP on this host, but readable — this is
the same `SecItemCopyMatching` code path, gated only by the keychain path
argument). Recommend a real-machine integration smoke test of both `list`
and `details` actions post-merge, on at least one Intel and one Apple
Silicon host, before this leg is trusted at parity with the pre-WP-B
subprocess path in production telemetry.

## 6. `tests/meson.build` — verbatim line to add

This package does not own `tests/meson.build`. Add the following line to
the `sources` list (alongside the existing `unit/test_certificates_macos.cpp`
entry) — no new `include_directories` entry is needed, since
`include_directories('../agents/plugins/certificates/src')` is already
present (added for `certificates_macos_parsers.hpp`, Gate-7 FIX A) and
covers `certificates_x509.hpp` too:

```
    'unit/test_certificates_x509.cpp',  # WP-B: certificates_x509.hpp libcrypto PEM/DER parse
                                         # fixtures; certificates/src already reachable via the
                                         # existing include_directories entry below (Gate-7 FIX A).
```

`test_certificates_x509.cpp` needs no new dependency either:
`agent_test_openssl_dep` (`tests/meson.build:161`) is already linked into
the `yuzu_agent_tests` target that this source list feeds.

## 7. Cross-check against acceptance criteria

- `grep -nE '\b(popen|_popen|system|fork|vfork|posix_spawn|CreateProcess)[A-Za-z]*[[:space:]]*\(' agents/plugins/certificates/src/certificates_plugin.cpp` — empty.
- `run_command`/`is_safe_path` deleted; grep confirms only comment-text references remain (§1).
- The only two `"/bin/sh"` occurrences left are the login-keychain hops (§3); each diffs as an unchanged call line with a comment added above it.
- Field-extraction recipes match §2 exactly, each pinned against a recorded CLI output in `test_certificates_x509.cpp`.
- Cardinality parity: `test_certificates_x509.cpp` has both the "3-cert bundle returns all 3, in order" and the "front()-only consumer never selects the 2nd cert" vectors.
- Every OpenSSL/CoreFoundation object is RAII-owned (`BioPtr`/`X509Ptr` in the new header; `yuzu::agent::ScopedCFRef<T>` in `read_keychain_secitem()`, constructed fresh from each owned +1 reference, never `reset()` with a borrowed one).
- macOS SecItem covers System/root only; login keychain reaches its shipped runner path unchanged.
- Linux legs are rung 1 with libcrypto mechanism strings; macOS list/details stay rung 3 with a hybrid mechanism string + fallback note; the descriptor block comment no longer claims `/bin/sh -c` for Linux.
- `meson.build` adds `openssl` on non-Windows and `Security`/`CoreFoundation` behind `required: false` + `-DYUZU_HAVE_SECURITY_FRAMEWORK` on darwin.
- No `agents/shared/` wave-0 header appears anywhere in this package's diff.
