# certificates

<!-- BEGIN GENERATED: plugin-doc-gen header -->
| | |
|---|---|
| **What it does** | Certificate inventory and management for system stores |
| **Version** | 1.0.0 |
| **Kind** | Action · read-only (`list`, `details`) / mutating (`delete`) · on-demand (no scheduled gather) |
| **Platforms** | Windows ✅ supported · macOS 🟡 constrained (`delete`) · Linux ✅ supported |
| **Actions** | `list` (definition `security.certificates.list`) · `details` (definition `security.certificates.details`) · `delete` (definition `security.certificates.delete`) |
| **Security** | `list`/`details`: securable `Security` · operation Read · risk Low · dispatch ReadOnly · approval gate none. `delete`: securable `Security` · operation Delete · risk High · dispatch Destructive · approval gate AdminOrApproval |
| **Roles** | execute: endpoint-admin, endpoint-operator, security-admin (`list`/`details`); endpoint-admin, security-admin (`delete`) · author: content-author |
<!-- END GENERATED -->

## How it works

`list` and `details` enumerate certificates in the OS's own stores and emit the same eight-field row per certificate; `list` returns every match (filtered by `store` and `expiring_within_days`), `details` returns the one row whose thumbprint matches (case-insensitive) or a `status|not_found`. `delete` is destructive: it hex-validates the thumbprint, then removes the certificate from the named store. On macOS `delete` additionally pre-checks presence before ever running the destructive command (so deleting an absent cert reports `status|not_found` instead of a command failure) and re-enumerates the keychain afterward to prove the certificate is actually gone before reporting `status|deleted` — a zero exit code alone is not trusted.

Windows reads/writes CryptoAPI stores (MY, ROOT, CA, Trust) natively, in-process, no subprocess. Linux parses PEM files under `/etc/ssl/certs` via in-process libcrypto (`certificates_x509.hpp`) — the `openssl x509` subprocess this used to shell out to is gone. macOS is a genuine hybrid: System.keychain and SystemRootCertificates.keychain are read in-process via `SecItemCopyMatching`, but the login keychain (the console user's own keychain, which the LaunchDaemon has none of itself) still reads through a `launchctl asuser`/`sudo -u`/`security find-certificate` subprocess hop, and `delete` always shells out to `/usr/bin/security delete-certificate`. Every macOS action runs under a shared 60-second wall-clock budget covering console-user resolution and every keychain read/parse it performs, so a wedged Directory Service or a pathological keychain degrades honestly (a `not_available|<reason>` row plus a `CONSTRAINED`/`PARTIAL` result status) instead of hanging or silently truncating.

This plugin deliberately does not validate a certificate's trust chain, check revocation (CRL/OCSP), import or renew certificates, or read anything beyond the fixed set of stores/keychains named above.

```mermaid
flowchart LR
  OP[Operator / workflow] --> SRV[Server<br/>authz: Security.Read / Security.Delete]
  SRV -- gRPC mTLS --> HOST[Agent plugin host] --> EX[certificates.execute]
  EX --> WIN[Windows leg<br/>CryptoAPI, in-process]
  EX --> MAC[macOS leg<br/>SecItem (System/root, in-process)<br/>+ security find-certificate/delete-certificate (login, subprocess)]
  EX --> LIN[Linux leg<br/>libcrypto PEM parse, in-process]
  WIN & MAC & LIN --> ROWS[rows + typed result status] --> RS[(ResponseStore)] --> API[REST /api/responses]
```

## OS capability

<!-- BEGIN GENERATED: plugin-doc-gen capability -->
| Action | Windows | macOS | Linux |
|---|---|---|---|
| `list` | ✅ supported · rung 1 · `CryptoAPI (CertEnumCertificatesInStore)` | ✅ supported · rung 2 · `SecItem (System/root, in-process) + security find-certificate argv via subprocess runner (login)` | ✅ supported · rung 1 · `libcrypto X509 (in-process PEM parse)` |
| `details` | ✅ supported · rung 1 · `CryptoAPI (CertEnumCertificatesInStore)` | ✅ supported · rung 2 · `SecItem (System/root, in-process) + security find-certificate argv via subprocess runner (login)` | ✅ supported · rung 1 · `libcrypto X509 (in-process PEM parse)` |
| `delete` | ✅ supported · rung 1 · `CryptoAPI (CertDeleteCertificateFromStore)` | 🟡 constrained · rung 2 · `security delete-certificate via subprocess runner` | ✅ supported · rung 1 · `libcrypto X509 lookup + filesystem remove` |

**Declared limits per leg** (the descriptor's fallback text, verbatim):

- **`list` / macOS** — System.keychain and SystemRootCertificates.keychain are read natively via SecItemCopyMatching (rung 1); the login keychain still requires the launchctl/sudo session hop, run as a pre-split argv through the bounded subprocess runner
- **`details` / macOS** — System.keychain and SystemRootCertificates.keychain are read natively via SecItemCopyMatching (rung 1); the login keychain still requires the launchctl/sudo session hop, run as a pre-split argv through the bounded subprocess runner
- **`delete` / macOS** — SystemRootCertificates.keychain is sealed under SIP and rejected outright; only System/MY store deletes are supported
<!-- END GENERATED -->

## Privileges and prerequisites

| OS | Runs as | Extra grant needed | Measured | If the read is refused |
|---|---|---|---|---|
| Windows | agent service account (LocalSystem today, #1442) | `list`/`details`: none — `CertEnumCertificatesInStore` needs no elevation. `delete`: `SeBackupPrivilege` + `SeRestorePrivilege` to write the certificate store; already granted to the service account under LocalSystem today, no new grant. | 2026-09-07, bare-metal Windows 10.0.26200.0 x64, as SYSTEM | `enumerate_store()` silently returns an empty vector when the store handle can't be opened (`certificates_plugin.cpp:325-341`) — `list`/`details` emit no row and no sentinel for that store; `delete` reports `status\|not_found` if the store can't be opened (`certificates_plugin.cpp:406-409`) |
| macOS | agent daemon; the shipped LaunchDaemon has no `UserName` key, so it runs as root — but this sample was captured unprivileged (see Measured) | System/root keychain reads: none (in-process `SecItemCopyMatching`, no subprocess). Login keychain read: root, via `launchctl asuser` + `sudo -u` — live today only because the daemon runs as root; needs a dormant sudoers grant once #1455 narrows the agent off root. `delete` (System/MY only): a sudoers grant for `/usr/bin/security delete-certificate -t /Library/Keychains/System.keychain *` under the future non-root account; moot today. | 2026-09-07, bare-metal macOS 26.6.2 arm64, euid 501 (alex) — unprivileged, captured via the test harness (`PluginHandle::load` + `LocalDispatcher::run`, no `init()`), not the production root LaunchDaemon | System/root keychain failure emits `not_available\|<keychain> read failed` + `CONSTRAINED`/`PARTIAL` (`certificates_plugin.cpp:1306,1333`); login-keychain failure emits `not_available\|login keychain read failed` + `CONSTRAINED`/`PARTIAL` (`certificates_plugin.cpp:1394-1396`) — the macOS sample shows exactly this (`macos.txt:164-165`) |
| Linux | dedicated unprivileged `yuzu` account in production; this sample was captured as euid 0 in a container, not representative of that account | `list`/`details`: none — native filesystem read + in-process libcrypto parse, no subprocess. `delete`: write access to `/etc/ssl/certs` to remove the matching file (`std::filesystem::remove`, `certificates_plugin.cpp:635`). | 2026-09-06, Debian GNU/Linux 13 (trixie) aarch64 container, euid 0 | An unreadable/unparseable PEM file reports `(unreadable)`/`(skipped)` and `CONSTRAINED`/`PARTIAL` rather than being silently dropped (`certificates_plugin.cpp:479-520`); `details`/`delete` report `not_available\|... scan incomplete` / `error\|...` rather than a false `not_found` when a candidate file couldn't be inspected (`certificates_plugin.cpp:592-596,643-649`) |

Binaries/subprocesses/network: Windows — none, in-process CryptoAPI/`crypt32` only. macOS — `/usr/bin/openssl` (per-block PEM parse, `certificates_plugin.cpp:989-992`), `/usr/bin/security` (`find-certificate`/`delete-certificate`, `certificates_plugin.cpp:1709,1850`), `/usr/bin/stat` (console-user resolution, `certificates_plugin.cpp:1117`) — all via the bounded subprocess runner, pre-split argv, no shell. Linux — none, in-process libcrypto only (`certificates_plugin.cpp:83-88`). No network access on any OS.

## Data contract

### Inputs

<!-- BEGIN GENERATED: plugin-doc-gen inputs -->
| Action | Parameter | Type | Required | Default | Description |
|---|---|---|---|---|---|
| `list` | `store` | string | no | `all` | Filters by store name. Windows: MY, ROOT, CA, Trust, or "all". macOS: "login", "System", "root", or "all". Ignored on Linux. |
| `list` | `expiring_within_days` | int32 | no | `0` | Only return certificates expiring within this many days; `0` returns all certificates. |
| `details` | `thumbprint` | string | **yes** | — | SHA-1 thumbprint (40 hex chars, no colons) of the certificate to retrieve; case-insensitive. |
| `details` | `store` | string | no | `all` | macOS only: restricts the search to one store ("login", "System", "root", "all"). Ignored on Windows and Linux, which always search every store. |
| `delete` | `thumbprint` | string | **yes** | — | SHA-1 thumbprint (40 hex chars, no colons) of the certificate to delete; case-insensitive. |
| `delete` | `store` | string | no | `MY` | The store to delete from. Windows: MY, ROOT, CA, Trust. macOS: "MY"/"System" (both target System.keychain); "root" is rejected (sealed by SIP); "login"/"all"/anything else is rejected. Ignored on Linux. |
<!-- END GENERATED -->

### Outputs

`list` and `details` write a header row followed by zero or more pipe-delimited certificate rows, or a `status|not_found` / `not_available|<reason>` line in place of a row when nothing matched or a store couldn't be read. `delete` writes one line only: `status|<value>`, `error|<message>`, or (macOS only) `not_available|<reason>`. `(unknown)` is the honest per-field sentinel for a value that failed to parse — it never means zero or empty; `subject`/`issuer`/`serial`/`key_usage` are escaped so a hostile value can never inject an extra pipe-delimited column or newline-delimited row.

<!-- BEGIN GENERATED: plugin-doc-gen outputs -->
**`list` / `details` — `subject|issuer|thumbprint|not_before|not_after|serial|store|key_usage`**

| Field | Type | Values | Available | Example |
|---|---|---|---|---|
| `subject` | string | free text (distinguished name) | W, M, L | `Logitech Inc` |
| `issuer` | string | free text (distinguished name) | W, M, L | `DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1` |
| `thumbprint` | string | 40 uppercase hex chars, or `(unknown)`/`(skipped)` | W, M, L | `FBD3B2C0991549EC5FB12FA1A994D2E0C32D8057` |
| `not_before` | string | `YYYY-MM-DD`, or `(unknown)` | W, M, L | `2025-01-09` |
| `not_after` | string | `YYYY-MM-DD`, or `(unknown)` | W, M, L | `2026-01-09` |
| `serial` | string | free text (hex) | W, M, L | `09CFB6DE3AB5124757FFEFDF3759BBF2` |
| `store` | string | Windows: MY/ROOT/CA/Trust. macOS: System.keychain/SystemRootCertificates.keychain/login.keychain-db. Linux: `/etc/ssl/certs` | W, M, L | `ROOT` |
| `key_usage` | string | comma-separated usage names, or `(none)` | W, M, L | `Digital Signature` |

**`delete` — single status line**

| Field | Type | Values | Available | Example |
|---|---|---|---|---|
| `status` | string | `status\|deleted`, `status\|not_found`, `status\|delete_failed` (Windows/Linux only), `error\|<message>` (any OS), `not_available\|<reason>` (macOS only, pre-validation) | W, M, L | `error\|thumbprint parameter required` |
<!-- END GENERATED -->

### Result status

| Status | Completeness | Provenance | When |
|---|---|---|---|
| `CONSTRAINED` | `PARTIAL` | `libcrypto:unreadable-file` | Linux: a PEM file under `/etc/ssl/certs` could not be read or parsed (`certificates_plugin.cpp:512,630`) |
| `CONSTRAINED` | `PARTIAL` | `login-keychain` | macOS: console-user resolution or the login-keychain read/scan failed, degraded, or was capped (`certificates_plugin.cpp:1268,1358-1396`) |
| `CONSTRAINED` | `PARTIAL` | `secitem:System.keychain` | macOS: System.keychain read or scan failed or was capped (`certificates_plugin.cpp:1291,1303,1307`) |
| `CONSTRAINED` | `PARTIAL` | `secitem:SystemRootCertificates.keychain` | macOS: SystemRootCertificates.keychain read or scan failed or was capped (`certificates_plugin.cpp:1317,1330,1334`) |

Windows never calls `set_result_status`; a clean Windows run, and any run that hits none of the degradations above, leaves the agent's default `UNDECLARED`/`UNKNOWN` status — the sample captures show this (`windows.txt:84,89,93`; `linux.txt:155,160,164`; `macos.txt:170,174`).

### Where the data goes

- **Instruction result only.** Rows travel over the agent's mTLS gRPC channel as the command response and land in the ResponseStore (90-day default retention, `server/core/src/response_store.hpp:8,152`), queryable at `/api/responses/{id}` and aggregatable (`list` groups by `store`/`issuer` per its YAML `aggregation` block).
- **Not consumed by** daily-sync inventory, the TAR warehouse, DEX, or metrics — no reference to the `certificates` plugin or its definition ids exists outside `server/core/src/capability_decls/plugin_action_catalogue_c.hpp`.
- **Siblings:** none in this plugin group; the `diagnostics.certificates` action (a different plugin, TLS cert/key diagnostics) is unrelated despite the similar name.
- **MCP / REST.** Discover: `discover_plugins` (summary) → `yuzu://plugin-docs` (this page as data) → `discover_instructions` / `get_definition("security.certificates.list")`. Run: `execute_instruction {definition_id, parameters}`. Read: `/api/responses/{id}`.

## Sample output

<!-- BEGIN GENERATED: plugin-doc-gen samples -->
**Windows** — captured: windows Microsoft Windows NT 10.0.26200.0 x64 · bare-metal · 2026-09-07 · SYSTEM · leg-hash pending

```
== action=list
subject|issuer|thumbprint|not_before|not_after|serial|store|key_usage
Logitech Inc|DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1|FBD3B2C0991549EC5FB12FA1A994D2E0C32D8057|2025-01-09|2026-01-09|09CFB6DE3AB5124757FFEFDF3759BBF2|ROOT|Digital Signature
Microsoft Identity Verification Root Certificate Authority 2020|Microsoft Identity Verification Root Certificate Authority 2020|F40042E2E5F7E8EF8189FED15519AECE42C3BFA2|2020-04-16|2045-04-16|5498D2D1D45B1995481379C811C08799|ROOT|Digital Signature, Certificate Signing, CRL Signing
Logitech Inc|DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1|D8D11D216CC42B72EA838CAD51F4F4932A1940A0|2026-01-08|2027-01-13|0CADE25B085DD33813FD746151BF6B5E|ROOT|Digital Signature
Baltimore CyberTrust Root|Baltimore CyberTrust Root|D4DE20D05E66FC53FE1A50882C78DB2852CAE474|2000-05-12|2025-05-12|020000B9|ROOT|Certificate Signing, CRL Signing
AAA Certificate Services|AAA Certificate Services|D1EB23A46D17D68FD92564C2F1F1601764D8E349|2004-01-01|2028-12-31|01|ROOT|Certificate Signing, CRL Signing
Microsoft Root Certificate Authority|Microsoft Root Certificate Authority|CDD4EEAE6000AC7F40C3802C171E30148030C072|2001-05-09|2021-05-09|79AD16A14AA0A5AD4C7358F407132E65|ROOT|Digital Signature, Certificate Signing, CRL Signing, Non-Repudiation
Logitech Inc|DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1|C27999A8CEE208F833289CB1A129666E952C7EC2|2022-04-11|2025-04-10|08FABFA8F305A513536B9F231CD3249C|ROOT|Digital Signature
Thawte Timestamping CA|Thawte Timestamping CA|BE36A4562FB2EE05DBB3D32323ADF445084ED656|1997-01-01|2020-12-31|00|ROOT|(none)
Starfield Root Certificate Authority - G2|Starfield Root Certificate Authority - G2|B51C067CEE2B0C3DF855AB2D92F4FE39D4E70F0E|2009-09-01|2037-12-31|00|ROOT|Certificate Signing, CRL Signing
Microsoft Root Authority|Microsoft Root Authority|A43489159A520F0D93D032CCAF37E7FE20A8B419|1997-01-10|2020-12-31|00C1008B3C3C8811D13EF663ECDF40|ROOT|(none)
Symantec Enterprise Mobile Root for Microsoft|Symantec Enterprise Mobile Root for Microsoft|92B46C76E13054E104F230517E6E504D43AB10B5|2012-03-15|2032-03-14|0F6B552F9EBF907B0F6629A9BDF4D8CE|ROOT|Certificate Signing, CRL Signing
Microsoft Root Certificate Authority 2011|Microsoft Root Certificate Authority 2011|8F43288AD272F3103B6FB1428485EA3014C0BCFE|2011-03-22|2036-03-22|3F8BC8B5FC9FB29643B569D66C42E144|ROOT|Digital Signature, Certificate Signing, CRL Signing
Microsoft Authenticode(tm) Root Authority|Microsoft Authenticode(tm) Root Authority|7F88CD7223F3C813818C994614A89C99FA3B5247|1995-01-01|1999-12-31|01|ROOT|(none)
Blizzard Battle.net Local Cert|Blizzard Battle.net Local Cert|7E7D281D1DCA51CCE3C81E42320BB9F898AB25B8|2023-03-23|2033-03-20|054082|ROOT|(none)
DigiCert High Assurance EV Root CA|DigiCert High Assurance EV Root CA|5FB7EE0633E259DBAD0C4C9AE6D38F1A61C7DC25|2006-11-10|2031-11-10|02AC5C266A0B409B8F0B79F2AE462577|ROOT|Digital Signature, Certificate Signing, CRL Signing
Microsoft Root Certificate Authority 2010|Microsoft Root Certificate Authority 2010|3B1EFD3A66EA28B16697394703A72CA340A05BD5|2010-06-23|2035-06-23|28CC3A25BFBA44AC449A9B586B4339AA|ROOT|Digital Signature, Certificate Signing, CRL Signing
Microsoft ECC TS Root Certificate Authority 2018|Microsoft ECC TS Root Certificate Authority 2018|31F9FC8BA3805986B721EA7295C65B3A44534274|2018-02-27|2043-02-27|153875E1647ED1B047B4EFAF41128245|ROOT|Digital Signature, Certificate Signing, CRL Signing
Copyright (c) 1997 Microsoft Corp.|Copyright (c) 1997 Microsoft Corp.|245C97DF7514E7CF2DF8BE72AE957B9E04741E85|1997-05-13|1999-12-30|01|ROOT|(none)
NO LIABILITY ACCEPTED, (c)97 VeriSign, Inc.|NO LIABILITY ACCEPTED, (c)97 VeriSign, Inc.|18F7C1FCC3090203FD5BAA2F861A754976C8DD25|1997-05-12|2004-01-07|4A19D2388C82591CA55D735F155DDCA3|ROOT|(none)
Microsoft ECC Product Root Certificate Authority 2018|Microsoft ECC Product Root Certificate Authority 2018|06F1AA330B927B753A40E68CDF22E34BCBEF3352|2018-02-27|2043-02-27|14982666DC7CCD8F4053677BB999EC85|ROOT|Digital Signature, Certificate Signing, CRL Signing
Microsoft Time Stamp Root Certificate Authority 2014|Microsoft Time Stamp Root Certificate Authority 2014|0119E81BE9A14CD8E22F40AC118C687ECBA3F4D8|2014-10-22|2039-10-22|2FD67A432293329045E953343EE27466|ROOT|Digital Signature, Certificate Signing, CRL Signing
AC RAIZ FNMT-RCM|AC RAIZ FNMT-RCM|EC503507B215C4956219E2A89A5B42992C4C2C20|2008-10-29|2030-01-01|5D938D306736C8061D1AC754846907|ROOT|Certificate Signing, CRL Signing
GTS Root R1|GTS Root R1|E58C1CC4913B38634BE9106EE3AD8E6B9DD9814A|2016-06-22|2036-06-22|0203E5936F31B01349886BA217|ROOT|Digital Signature, Certificate Signing, CRL Signing
IdenTrust Commercial Root CA 1|IdenTrust Commercial Root CA 1|DF717EAA4AD94EC9558499602D48DE5FBCF03A25|2014-01-16|2034-01-16|0A0142800000014523C844B500000002|ROOT|Certificate Signing, CRL Signing
DigiCert Global Root G2|DigiCert Global Root G2|DF3C24F9BFD666761B268073FE06D1CC8D4F82A4|2013-08-01|2038-01-15|033AF1E6A711A9A0BB2864B11D09FAE5|ROOT|Digital Signature, Certificate Signing, CRL Signing
… 25 of 80 rows
[result_status] UNDECLARED / UNKNOWN / 

== action=details thumbprint=FBD3B2C0991549EC5FB12FA1A994D2E0C32D8057
subject|issuer|thumbprint|not_before|not_after|serial|store|key_usage
Logitech Inc|DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1|FBD3B2C0991549EC5FB12FA1A994D2E0C32D8057|2025-01-09|2026-01-09|09CFB6DE3AB5124757FFEFDF3759BBF2|ROOT|Digital Signature
[result_status] UNDECLARED / UNKNOWN / 

== action=delete
error|thumbprint parameter required
[result_status] UNDECLARED / UNKNOWN / 
[rc] 1
```

**macOS** — captured: macos macOS 26.6.2 arm64 · bare-metal · 2026-09-07 · euid 501 (alex) · leg-hash pending

```
== action=list
subject|issuer|thumbprint|not_before|not_after|serial|store|key_usage
CN=com.apple.systemdefault, O=System Identity|CN=com.apple.systemdefault, O=System Identity|0C24DA5DE02640D8924F5C7BCB7D5F734815228D|2026-07-18|2046-07-13|076C11D1|System.keychain|Digital Signature, Key Encipherment, Data Encipherment
CN=com.apple.kerberos.kdc, O=System Identity|CN=com.apple.kerberos.kdc, O=System Identity|3CB6CE678431CB8DD8FDCF6601AA6A4F8CAD329A|2026-07-18|2046-07-13|38F8E0C5|System.keychain|Digital Signature, Key Encipherment
C=US, O=DigiCert, Inc., CN=DigiCert TLS ECC P384 Root G5|C=US, O=DigiCert, Inc., CN=DigiCert TLS ECC P384 Root G5|17F3DE5E9F0F19E98EF61F32266E20C407AE30EE|2021-01-15|2046-01-14|09E09365ACF7D9C8B93E1C0B042A2EF3|SystemRootCertificates.keychain|Digital Signature, Certificate Sign, CRL Sign
C=US, OU=www.xrampsecurity.com, O=XRamp Security Services Inc, CN=XRamp Global Certification Authority|C=US, OU=www.xrampsecurity.com, O=XRamp Security Services Inc, CN=XRamp Global Certification Authority|B80186D1EB9C86A54104CF3054F34C52B7E558C6|2004-11-01|2035-01-01|50946CEC18EAD59C4DD597EF758FA0AD|SystemRootCertificates.keychain|Digital Signature, Certificate Sign, CRL Sign
C=CH, O=WISeKey, OU=OISTE Foundation Endorsed, CN=OISTE WISeKey Global Root GB CA|C=CH, O=WISeKey, OU=OISTE Foundation Endorsed, CN=OISTE WISeKey Global Root GB CA|0FF9407618D3D76A4B98F0A8359E0CFD27ACCCED|2014-12-01|2039-12-01|76B1205274F0858746B3F8231AF6C2C0|SystemRootCertificates.keychain|Digital Signature, Certificate Sign, CRL Sign
C=US, O=Amazon, CN=Amazon Root CA 2|C=US, O=Amazon, CN=Amazon Root CA 2|5A8CEF45D7A69859767A8C8B4496B578CF474B1A|2015-05-26|2040-05-26|066C9FD29635869F0A0FE58678F85B26BB8A37|SystemRootCertificates.keychain|Digital Signature, Certificate Sign, CRL Sign
C=IT, L=Milan, O=Actalis S.p.A./03358520967, CN=Actalis Authentication Root CA|C=IT, L=Milan, O=Actalis S.p.A./03358520967, CN=Actalis Authentication Root CA|F373B387065A28848AF2F34ACE192BDDC78E9CAC|2011-09-22|2030-09-22|570A119742C4E3CC|SystemRootCertificates.keychain|Certificate Sign, CRL Sign
C=US, O=Internet Security Research Group, CN=ISRG Root X1|C=US, O=Internet Security Research Group, CN=ISRG Root X1|CABD2A79A1076A31F21D253635CB039D4329A5E8|2015-06-04|2035-06-04|8210CFB0D240E3594463E0BB63828B00|SystemRootCertificates.keychain|Certificate Sign, CRL Sign
C=US, O=Apple Inc., CN=Apple Platform Code Signing ECC Root CA - G1|C=US, O=Apple Inc., CN=Apple Platform Code Signing ECC Root CA - G1|E8DA8B1EFCFE2EB2FCEB9D41981E1869A71A9C13|2024-12-13|2049-12-08|521223A7BFF487D04BD387D29127D824|SystemRootCertificates.keychain|Certificate Sign, CRL Sign
CN=ACCVRAIZ1, OU=PKIACCV, O=ACCV, C=ES|CN=ACCVRAIZ1, OU=PKIACCV, O=ACCV, C=ES|93057A8815C64FCE882FFA9116522878BC536417|2011-05-05|2030-12-31|5EC3B7A6437FA4E0|SystemRootCertificates.keychain|Certificate Sign, CRL Sign
C=US, O=Certainly, CN=Certainly Root R1|C=US, O=Certainly, CN=Certainly Root R1|A050EE0F2871F427B2126D6F509625BACC8642AF|2021-04-01|2046-04-01|8E0FF94B907168653354F4D44439B7E0|SystemRootCertificates.keychain|Certificate Sign, CRL Sign
C=PL, O=Asseco Data Systems S.A., OU=Certum Certification Authority, CN=Certum Trusted Root CA|C=PL, O=Asseco Data Systems S.A., OU=Certum Certification Authority, CN=Certum Trusted Root CA|C88344C018AE9FCCF187B78F22D1C5D74584BAE5|2018-03-16|2043-03-16|1EBF5950B8C980374C06F7EB554FB5ED|SystemRootCertificates.keychain|Certificate Sign, CRL Sign
C=TR, L=Gebze - Kocaeli, O=Turkiye Bilimsel ve Teknolojik Arastirma Kurumu - TUBITAK, OU=Kamu Sertifikasyon Merkezi - Kamu SM, CN=TUBITAK Kamu SM SSL Kok Sertifikasi - Surum 1|C=TR, L=Gebze - Kocaeli, O=Turkiye Bilimsel ve Teknolojik Arastirma Kurumu - TUBITAK, OU=Kamu Sertifikasyon Merkezi - Kamu SM, CN=TUBITAK Kamu SM SSL Kok Sertifikasi - Surum 1|3143649BECCE27ECED3A3F0B8F0DE4E891DDEECA|2013-11-25|2043-10-25|01|SystemRootCertificates.keychain|Certificate Sign, CRL Sign
C=US, O=Google Trust Services LLC, CN=GTS Root R3|C=US, O=Google Trust Services LLC, CN=GTS Root R3|EDE571802BC892B95B833CD232683F09CDA01E46|2016-06-22|2036-06-22|0203E5B882EB20F825276D3D66|SystemRootCertificates.keychain|Digital Signature, Certificate Sign, CRL Sign
C=PL, O=Unizeto Technologies S.A., OU=Certum Certification Authority, CN=Certum Trusted Network CA|C=PL, O=Unizeto Technologies S.A., OU=Certum Certification Authority, CN=Certum Trusted Network CA|07E032E020B72C3F192F0628A2593A19A70F069E|2008-10-22|2029-12-31|0444C0|SystemRootCertificates.keychain|Certificate Sign, CRL Sign
C=US, O=Certainly, CN=Certainly Root E1|C=US, O=Certainly, CN=Certainly Root E1|F9E16DDC0189CFD58245633EC5377DC2EB936F2B|2021-04-01|2046-04-01|062533B1470333275CF98D9AB9BFCCF8|SystemRootCertificates.keychain|Certificate Sign, CRL Sign
C=RO, O=certSIGN, OU=certSIGN ROOT CA|C=RO, O=certSIGN, OU=certSIGN ROOT CA|FAB7EE36972662FB2DB02AF6BF03FDE87C4B2F9B|2006-07-04|2031-07-04|200605167002|SystemRootCertificates.keychain|Digital Signature, Non Repudiation, Certificate Sign, CRL Sign
C=CH, O=SwissSign AG, CN=SwissSign Gold CA - G2|C=CH, O=SwissSign AG, CN=SwissSign Gold CA - G2|D8C5388AB7301B1B6ED47AE645253A6F9F1A2761|2006-10-25|2036-10-25|BB401C43F55E4FB0|SystemRootCertificates.keychain|Certificate Sign, CRL Sign
C=DE, O=T-Systems Enterprise Services GmbH, OU=T-Systems Trust Center, CN=T-TeleSec GlobalRoot Class 2|C=DE, O=T-Systems Enterprise Services GmbH, OU=T-Systems Trust Center, CN=T-TeleSec GlobalRoot Class 2|590D2D7D884F402E617EA562321765CF17D894E9|2008-10-01|2033-10-01|01|SystemRootCertificates.keychain|Certificate Sign, CRL Sign
O=Entrust.net, OU=www.entrust.net/CPS_2048 incorp. by ref. (limits liab.), OU=(c) 1999 Entrust.net Limited, CN=Entrust.net Certification Authority (2048)|O=Entrust.net, OU=www.entrust.net/CPS_2048 incorp. by ref. (limits liab.), OU=(c) 1999 Entrust.net Limited, CN=Entrust.net Certification Authority (2048)|503006091D97D4F5AE39F7CBE7927D7D652D3431|1999-12-24|2029-07-24|3863DEF8|SystemRootCertificates.keychain|Certificate Sign, CRL Sign
C=DE, O=D-Trust GmbH, CN=D-TRUST Root Class 3 CA 2 2009|C=DE, O=D-Trust GmbH, CN=D-TRUST Root Class 3 CA 2 2009|58E8ABB0361533FB80F79B1B6D29D3FF8D5F00F0|2009-11-05|2029-11-05|0983F3|SystemRootCertificates.keychain|Certificate Sign, CRL Sign
C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Assured ID Root G2|C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Assured ID Root G2|A14B48D943EE0A0E40904F3CE0A4C09193515D3F|2013-08-01|2038-01-15|0B931C3AD63967EA6723BFC3AF9AF44B|SystemRootCertificates.keychain|Digital Signature, Certificate Sign, CRL Sign
C=TW, O=Chunghwa Telecom Co., Ltd., OU=ePKI Root Certification Authority|C=TW, O=Chunghwa Telecom Co., Ltd., OU=ePKI Root Certification Authority|67650DF17E8E7E5B8240A4F4564BCFE23D69C6F0|2004-12-20|2034-12-20|15C8BD65475CAFB897005EE406D2BC9D|SystemRootCertificates.keychain|(none)
C=US, O=GeoTrust Inc., OU=(c) 2007 GeoTrust Inc. - For authorized use only, CN=GeoTrust Primary Certification Authority - G2|C=US, O=GeoTrust Inc., OU=(c) 2007 GeoTrust Inc. - For authorized use only, CN=GeoTrust Primary Certification Authority - G2|8D1784D537F3037DEC70FE578B519A99E610D7B0|2007-11-05|2038-01-18|3CB2F4480A00E2FEEB243B5E603EC36B|SystemRootCertificates.keychain|Certificate Sign, CRL Sign
OU=GlobalSign Root CA - R3, O=GlobalSign, CN=GlobalSign|OU=GlobalSign Root CA - R3, O=GlobalSign, CN=GlobalSign|D69B561148F01C77C54578C10926DF5B856976AD|2009-03-18|2029-03-18|04000000000121585308A2|SystemRootCertificates.keychain|Certificate Sign, CRL Sign
… 25 of 160 rows
not_available|login keychain read failed
[result_status] CONSTRAINED / PARTIAL / login-keychain

== action=details thumbprint=0C24DA5DE02640D8924F5C7BCB7D5F734815228D
subject|issuer|thumbprint|not_before|not_after|serial|store|key_usage
CN=com.apple.systemdefault, O=System Identity|CN=com.apple.systemdefault, O=System Identity|0C24DA5DE02640D8924F5C7BCB7D5F734815228D|2026-07-18|2046-07-13|076C11D1|System.keychain|Digital Signature, Key Encipherment, Data Encipherment
[result_status] UNDECLARED / UNKNOWN / 

== action=delete
error|thumbprint parameter required
[result_status] UNDECLARED / UNKNOWN / 
[rc] 1
```

**Linux** — captured: linux Debian GNU/Linux 13 (trixie) aarch64 · container · 2026-09-06 · euid 0 · leg-hash pending

```
== action=list
subject|issuer|thumbprint|not_before|not_after|serial|store|key_usage
C=US, O=Google Trust Services LLC, CN=GTS Root R4|C=US, O=Google Trust Services LLC, CN=GTS Root R4|77D30367B5E00C15F60C3861DF7CE13B92464D47|2016-06-22|2036-06-22|0203E5C068EF631A9C72905052|/etc/ssl/certs|Digital Signature, Certificate Sign, CRL Sign
C=ES, O=IZENPE S.A., CN=Izenpe.com|C=ES, O=IZENPE S.A., CN=Izenpe.com|2F783D255218A74A653971B52CA29C45156FE919|2007-12-13|2037-12-13|B0B75A16485FBFE1CBF58BD719E67D|/etc/ssl/certs|Certificate Sign, CRL Sign
C=BM, O=QuoVadis Limited, CN=QuoVadis Root CA 2 G3|C=BM, O=QuoVadis Limited, CN=QuoVadis Root CA 2 G3|093C61F38B8BDC7D55DF7538020500E125F5C836|2012-01-12|2042-01-12|445734245B81899B35F2CEB82B3B5BA726F07528|/etc/ssl/certs|Certificate Sign, CRL Sign
C=US, OU=emSign PKI, O=eMudhra Inc, CN=emSign Root CA - C1|C=US, OU=emSign PKI, O=eMudhra Inc, CN=emSign Root CA - C1|E72EF1DFFCB20928CF5DD4D56737B151CB864F01|2018-02-18|2043-02-18|AECF00BAC4CF32F843B2|/etc/ssl/certs|Certificate Sign, CRL Sign
C=DE, O=D-Trust GmbH, CN=D-TRUST BR Root CA 1 2020|C=DE, O=D-Trust GmbH, CN=D-TRUST BR Root CA 1 2020|1F5B98F0E3B5F7743CEDE6B0367D32CDF4094167|2020-02-11|2035-02-11|7CC98F2B84D7DFEA0FC9659AD34B4D96|/etc/ssl/certs|Certificate Sign, CRL Sign
C=US, O=The Go Daddy Group, Inc., OU=Go Daddy Class 2 Certification Authority|C=US, O=The Go Daddy Group, Inc., OU=Go Daddy Class 2 Certification Authority|2796BAE63F1801E277261BA0D77770028F20EEE4|2004-06-29|2034-06-29|00|/etc/ssl/certs|(none)
C=FR, O=Dhimyotis, CN=Certigna|C=FR, O=Dhimyotis, CN=Certigna|B12E13634586A46F1AB2606837582DC4ACFD9497|2007-06-29|2027-06-29|FEDCE3010FC948FF|/etc/ssl/certs|Certificate Sign, CRL Sign
C=US, O=Microsoft Corporation, CN=Microsoft ECC Root Certificate Authority 2017|C=US, O=Microsoft Corporation, CN=Microsoft ECC Root Certificate Authority 2017|999A64C37FF47D9FAB95F14769891460EEC4C3C5|2019-12-18|2042-07-18|66F23DAF87DE8BB14AEA0C573101C2EC|/etc/ssl/certs|Digital Signature, Certificate Sign, CRL Sign
C=CN, O=TrustAsia Technologies, Inc., CN=TrustAsia Global Root CA G3|C=CN, O=TrustAsia Technologies, Inc., CN=TrustAsia Global Root CA G3|63CFB6C1272B56E4888E1C239AB62E814724C3C7|2021-05-20|2046-05-19|64F60E6577616AAB3BB4EA8584BBB189B871930F|/etc/ssl/certs|Certificate Sign, CRL Sign
C=US, O=Amazon, CN=Amazon Root CA 2|C=US, O=Amazon, CN=Amazon Root CA 2|5A8CEF45D7A69859767A8C8B4496B578CF474B1A|2015-05-26|2040-05-26|066C9FD29635869F0A0FE58678F85B26BB8A37|/etc/ssl/certs|Digital Signature, Certificate Sign, CRL Sign
C=BE, O=GlobalSign nv-sa, CN=GlobalSign Root R46|C=BE, O=GlobalSign nv-sa, CN=GlobalSign Root R46|53A2B04BCA6BD645E6398A8EC40DD2BF77C3A290|2019-03-20|2046-03-20|11D2BBB9D723189E405F0A9D2DD0DF2567D1|/etc/ssl/certs|Digital Signature, Certificate Sign, CRL Sign
CN=Atos TrustedRoot Root CA RSA TLS 2021, O=Atos, C=DE|CN=Atos TrustedRoot Root CA RSA TLS 2021, O=Atos, C=DE|18523B0D0637E4D63ADF23E498FB5B16FB867448|2021-04-22|2041-04-17|53D5CFE619930BFB2B0512D8C22AA2A4|/etc/ssl/certs|Digital Signature, Certificate Sign, CRL Sign
OU=GlobalSign ECC Root CA - R4, O=GlobalSign, CN=GlobalSign|OU=GlobalSign ECC Root CA - R4, O=GlobalSign, CN=GlobalSign|6BA0B098E171EF5AADFE4815807710F4BD6F0B28|2012-11-13|2038-01-19|0203E57EF53F93FDA50921B2A6|/etc/ssl/certs|Digital Signature, Certificate Sign, CRL Sign
C=NO, O=Buypass AS-983163327, CN=Buypass Class 3 Root CA|C=NO, O=Buypass AS-983163327, CN=Buypass Class 3 Root CA|DAFAF7FA6684EC068F1450BDC7C281A5BCA96457|2010-10-26|2040-10-26|02|/etc/ssl/certs|Certificate Sign, CRL Sign
C=GR, L=Athens, O=Hellenic Academic and Research Institutions Cert. Authority, CN=Hellenic Academic and Research Institutions RootCA 2015|C=GR, L=Athens, O=Hellenic Academic and Research Institutions Cert. Authority, CN=Hellenic Academic and Research Institutions RootCA 2015|010C0695A6981914FFBF5FC6B0B695EA29E912A6|2015-07-07|2040-06-30|00|/etc/ssl/certs|Certificate Sign, CRL Sign
C=IN, OU=emSign PKI, O=eMudhra Technologies Limited, CN=emSign Root CA - G1|C=IN, OU=emSign PKI, O=eMudhra Technologies Limited, CN=emSign Root CA - G1|8AC7AD8F73AC4EC1B5754DA540F4FCCF7CB58E8C|2018-02-18|2043-02-18|31F5E4620C6C58EDD6D8|/etc/ssl/certs|Certificate Sign, CRL Sign
C=US, O=CommScope, CN=CommScope Public Trust ECC Root-01|C=US, O=CommScope, CN=CommScope Public Trust ECC Root-01|0786C0D8DD8EC080980698D0587AEFDEA6CCA25D|2021-04-28|2046-04-28|43708277CF4D5D34F1CAAE322F37F7F47F75A09E|/etc/ssl/certs|Certificate Sign, CRL Sign
C=JP, O=SECOM Trust Systems CO.,LTD., OU=Security Communication RootCA2|C=JP, O=SECOM Trust Systems CO.,LTD., OU=Security Communication RootCA2|5F3B8CF2F810B37D78B4CEEC1919C37334B9C774|2009-05-29|2029-05-29|00|/etc/ssl/certs|Certificate Sign, CRL Sign
CN=ACCVRAIZ1, OU=PKIACCV, O=ACCV, C=ES|CN=ACCVRAIZ1, OU=PKIACCV, O=ACCV, C=ES|93057A8815C64FCE882FFA9116522878BC536417|2011-05-05|2030-12-31|5EC3B7A6437FA4E0|/etc/ssl/certs|Certificate Sign, CRL Sign
C=ES, O=Firmaprofesional SA, organizationIdentifier=VATES-A62634068, CN=FIRMAPROFESIONAL CA ROOT-A WEB|C=ES, O=Firmaprofesional SA, organizationIdentifier=VATES-A62634068, CN=FIRMAPROFESIONAL CA ROOT-A WEB|A8311174A614150DCA77DD0EE40C5D58FCA072A5|2022-04-06|2047-03-31|319721EDAF89427F354187A167564C6D|/etc/ssl/certs|Certificate Sign, CRL Sign
C=US, O=Internet Security Research Group, CN=ISRG Root X1|C=US, O=Internet Security Research Group, CN=ISRG Root X1|CABD2A79A1076A31F21D253635CB039D4329A5E8|2015-06-04|2035-06-04|8210CFB0D240E3594463E0BB63828B00|/etc/ssl/certs|Certificate Sign, CRL Sign
OU=GlobalSign Root CA - R6, O=GlobalSign, CN=GlobalSign|OU=GlobalSign Root CA - R6, O=GlobalSign, CN=GlobalSign|8094640EB5A7A1CA119C1FDDD59F810263A7FBD1|2014-12-10|2034-12-10|45E6BB038333C3856548E6FF4551|/etc/ssl/certs|Certificate Sign, CRL Sign
C=US, ST=Illinois, L=Chicago, O=Trustwave Holdings, Inc., CN=Trustwave Global ECC P384 Certification Authority|C=US, ST=Illinois, L=Chicago, O=Trustwave Holdings, Inc., CN=Trustwave Global ECC P384 Certification Authority|E7F3A3C8CF6FC3042E6D0E6732C59E68950D5ED2|2017-08-23|2042-08-23|08BD85976C9927A48068473B|/etc/ssl/certs|Certificate Sign, CRL Sign
C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert High Assurance EV Root CA|C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert High Assurance EV Root CA|5FB7EE0633E259DBAD0C4C9AE6D38F1A61C7DC25|2006-11-10|2031-11-10|02AC5C266A0B409B8F0B79F2AE462577|/etc/ssl/certs|Digital Signature, Certificate Sign, CRL Sign
C=BM, O=QuoVadis Limited, CN=QuoVadis Root CA 1 G3|C=BM, O=QuoVadis Limited, CN=QuoVadis Root CA 1 G3|1B8EEA5796291AC939EAB80A811A7373C0937967|2012-01-12|2042-01-12|78585F2EAD2C194BE3370735341328B596D46593|/etc/ssl/certs|Certificate Sign, CRL Sign
… 25 of 151 rows
[result_status] UNDECLARED / UNKNOWN / 

== action=details thumbprint=77D30367B5E00C15F60C3861DF7CE13B92464D47
subject|issuer|thumbprint|not_before|not_after|serial|store|key_usage
C=US, O=Google Trust Services LLC, CN=GTS Root R4|C=US, O=Google Trust Services LLC, CN=GTS Root R4|77D30367B5E00C15F60C3861DF7CE13B92464D47|2016-06-22|2036-06-22|0203E5C068EF631A9C72905052|/etc/ssl/certs|Digital Signature, Certificate Sign, CRL Sign
[result_status] UNDECLARED / UNKNOWN / 

== action=delete
error|thumbprint parameter required
[result_status] UNDECLARED / UNKNOWN / 
[rc] 1
```
<!-- END GENERATED -->

## Caveats and known gaps

1. **Windows store-open failures are silent.** `enumerate_store()` returns an empty vector when neither the LOCAL_MACHINE nor CURRENT_USER handle opens (`certificates_plugin.cpp:325-341`), and the Windows leg never calls `set_result_status` — a permission or missing-store failure looks identical to "this store is empty," unlike the explicit `not_available`/`CONSTRAINED` sentinels the macOS and Linux legs use.
2. **The login keychain read is a registered exception, not a rung-1 promotion.** System.keychain/SystemRootCertificates.keychain are read in-process via `SecItemCopyMatching`; the login keychain stays on the `launchctl asuser` + `sudo -u` + `security find-certificate` subprocess (rung 2, #3406) because the LaunchDaemon has no login keychain of its own (`certificates_plugin.cpp:16-23,750-762`) — do not "fix" this to a direct API call.
3. **SystemRootCertificates.keychain delete is permanently rejected.** It is sealed under System Integrity Protection; `delete_cert_macos` rejects `store=root` outright before ever shelling out (`certificates_plugin.cpp:1761-1771`) — a hard OS limitation, not a bug to fix.
4. **A macOS delete self-verifies before reporting success.** `delete_cert_macos` re-enumerates the target keychain after `security delete-certificate` exits 0 and only reports `status|deleted` on a positively-proven absence; a keychain that can't be re-read or still shows the certificate reports `error|...`, never a false `status|deleted` (`certificates_plugin.cpp:1863-1900`).
5. **The macOS sample was captured unprivileged and shows the login-keychain leg degrading live.** At euid 501 with no console session reachable via `launchctl asuser` without root, `list`'s login-keychain read failed and the result carries `CONSTRAINED`/`PARTIAL`/`login-keychain` (`macos.txt:164-165`) — expected under the capture harness, but it means this sample never exercises a successful login-keychain read.

## Source and tests

<!-- BEGIN GENERATED: plugin-doc-gen source -->
- Plugin: `agents/plugins/certificates/src/certificates_plugin.cpp` (descriptor legs, `execute()`) · `certificates_x509.hpp` (in-process libcrypto PEM/DER parse) · `certificates_macos_parsers.hpp` (shared pure parse/validate/classify/verdict helpers)
- Definitions: `content/definitions/certificates.yaml`
- Capability rows: `server/core/src/capability_decls/plugin_action_catalogue_c.hpp` (lines 317, 327, 337)
- Tests: `tests/unit/test_certificates_macos.cpp` (67 cases) · `tests/unit/test_certificates_x509.cpp` (19 cases)
- Privilege row: `docs/agent-privilege-model.md` (rows at lines 93 and 111)
- Changelog: `changelog.d/20260817-wave2-certificates-in-process-x509.changed.md` · `changelog.d/2204-declarations-group-c.added.md` · `changelog.d/3406-certificates-login-keychain-argv.changed.md`
<!-- END GENERATED -->
